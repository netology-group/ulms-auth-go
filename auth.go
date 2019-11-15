package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/cache/v7"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var metrics *prometheus.SummaryVec

type permissionCheckResult struct{}

func init() {
	metrics = promauto.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "authz_latency",
			Help:       "Authz request latency (in seconds)",
			Objectives: map[float64]float64{0.5: 0.05, 0.95: 0.005, 0.99: 0.001},
		},
		[]string{"audience", "code"},
	)
}

// Action used to authorize some user's action
type Action string

// actions to authorize
const (
	ActionCreate = Action("create")
	ActionRead   = Action("read")
	ActionUpdate = Action("update")
	ActionDelete = Action("delete")
)

type contextKey string

const tokenContextKey = contextKey("token")

// ErrorNotAuthorized indicates 403 Forbidden HTTP status code
var ErrorNotAuthorized = fmt.Errorf("not authorized")

// Auth is interface containing methods to authenticate and authorize users
type Auth interface {
	Issuer(*jwt.StandardClaims) Issuer
	Permission(space string) Permission
	TokenValidationMiddleware() func(next http.Handler) http.Handler
}

// Issuer interface represents issuer interface
type Issuer interface {
	Trusted() bool
}

// Permission interface contains methods to check authorization
type Permission interface {
	Check(claims *jwt.StandardClaims, action Action, objectValues ...string) error
	WithContext(ctx context.Context) Permission
}

// TenantAuth implements Auth interface using tenants
type TenantAuth struct {
	Tenants     map[string]*tenant     `toml:"authn"`
	Permissions map[string]*permission `toml:"authz"`
}

// LoadConfiguration loads current TenantAuth configuration
func LoadConfiguration(configFile string, cacheCodec *cache.Codec) (Auth, error) {
	auth := &TenantAuth{}
	if _, err := toml.DecodeFile(configFile, auth); err != nil {
		return nil, err
	}
	for audience, permission := range auth.Permissions {
		permission.metrics = metrics.MustCurryWith(prometheus.Labels{"audience": audience})
		permission.cacheCodec = cacheCodec
	}
	return auth, nil
}

// JWT returns request's JWT
func JWT(r *http.Request) *jwt.Token {
	if token, ok := r.Context().Value(tokenContextKey).(*jwt.Token); ok {
		return token
	}
	return nil
}

// Claims from request's JWT
func Claims(r *http.Request) *jwt.StandardClaims {
	token := JWT(r)
	if token != nil {
		if claims, ok := token.Claims.(*jwt.StandardClaims); ok {
			return claims
		}
	}
	return nil
}

// Issuer instance
func (auth *TenantAuth) Issuer(claims *jwt.StandardClaims) Issuer {
	if tenant, ok := auth.Tenants[claims.Issuer]; ok {
		return tenant
	}
	return nil
}

// Permission instance
func (auth *TenantAuth) Permission(space string) Permission {
	if permission, ok := auth.Permissions[space]; ok {
		return permission
	}
	return nil
}

// TokenValidationMiddleware returns middleware for validating JWT
func (auth *TenantAuth) TokenValidationMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				err         error
				token       *jwt.Token
				accessToken string
			)
			if accessToken = r.URL.Query().Get("access_token"); len(accessToken) == 0 {
				bearerAuthorization := r.Header.Get("Authorization")
				accessToken = strings.TrimPrefix(bearerAuthorization, "Bearer ")
			}
			token, err = jwt.ParseWithClaims(accessToken, new(jwt.StandardClaims), func(token *jwt.Token) (interface{}, error) {
				claims := token.Claims.(*jwt.StandardClaims)
				tenant, ok := auth.Tenants[claims.Issuer]
				if !ok {
					return nil, fmt.Errorf("JWT: unknown issuer (authn): %v", claims.Issuer)
				}
				for _, audience := range tenant.Audiences {
					if claims.VerifyAudience(audience, true) {
						goto audienceVerified
					}
				}
				return nil, fmt.Errorf("JWT: audience=%v for issuer=%v is not allowed", claims.Audience, claims.Issuer)
			audienceVerified:
				return tenant.keyBytes()
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
			} else {
				ctx := context.WithValue(r.Context(), tokenContextKey, token)
				next.ServeHTTP(w, r.WithContext(ctx))
			}
		})
	}
}

type tenant struct {
	Audiences []string `toml:"audience"`
	SecretKey string   `toml:"key"`
	IsTrusted bool     `toml:"trusted"`

	key []byte
}

func (tenant *tenant) Trusted() bool {
	return tenant.IsTrusted
}

func (tenant *tenant) keyBytes() ([]byte, error) {
	if tenant.key == nil {
		if key, err := ioutil.ReadFile(tenant.SecretKey); err == nil {
			tenant.key = bytes.TrimSpace(key)
		} else {
			return nil, err
		}
	}
	return tenant.key, nil
}

type permission struct {
	URL       string `toml:"uri"`
	Token     string `toml:"token"`
	ServiceID string `toml:"service_id"`

	MaxRetryAttempts int `toml:"max_retry_attempts"`

	CacheTTL int `toml:"cache_ttl"`

	metrics    prometheus.ObserverVec
	ctx        context.Context
	cacheCodec *cache.Codec
}

func (p *permission) Check(claims *jwt.StandardClaims, action Action, objectValues ...string) error {
	if p.cacheCodec == nil || p.CacheTTL == 0 {
		return p.check(claims, action, objectValues...)
	}
	return p.cacheCodec.Once(&cache.Item{
		Ctx:    p.ctx,
		Key:    fmt.Sprintf("ulms-go:authz:%v:%v:%v:%v:%v:%v", p.URL, p.ServiceID, claims.Audience, claims.Subject, action, strings.Join(objectValues, ":")),
		Object: new(permissionCheckResult),
		Func: func() (interface{}, error) {
			if err := p.check(claims, action, objectValues...); err != nil {
				return nil, err
			}
			return &permissionCheckResult{}, nil
		},
		Expiration: time.Duration(p.CacheTTL) * time.Second,
	})
}
func (p *permission) check(claims *jwt.StandardClaims, action Action, objectValues ...string) error {
	if p.URL == "" {
		// always allow any action if permission.URL is not defined
		return nil
	}
	var authorizedActions []Action
	authRequest := &authorizationRequest{
		Action:  action,
		Subject: &parameter{claims.Audience, []string{"accounts", claims.Subject}},
		Object:  &parameter{p.ServiceID, objectValues},
	}
	body, _ := json.Marshal(authRequest)
	request, err := http.NewRequest(http.MethodPost, p.URL, bytes.NewBuffer(body))
	attempt := 1
	if err == nil {
		if p.ctx != nil {
			request = request.WithContext(p.ctx)
		}
		var response *http.Response
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %v", p.Token))
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Content-Type", "application/json; charset=utf-8")
		for {
			if response, err = client.do(request, p.metrics); err == nil {
				if response.StatusCode != 200 {
					err = fmt.Errorf("non-200 response status code: %v", response.StatusCode)
				} else {
					err = json.NewDecoder(response.Body).Decode(&authorizedActions)
				}
				_ = response.Body.Close()
			}
			if err == nil || attempt >= p.MaxRetryAttempts+1 {
				break
			}
			attempt++
		}
	}
	if err != nil {
		return errors.Wrapf(err, "error performing authz request, attempts: %d, URL: %s", attempt, p.URL)
	}
	for _, authorizedAction := range authorizedActions {
		if action == authorizedAction {
			return nil
		}
	}
	return ErrorNotAuthorized
}

func (p *permission) WithContext(ctx context.Context) Permission {
	return &permission{
		URL:              p.URL,
		Token:            p.Token,
		ServiceID:        p.ServiceID,
		MaxRetryAttempts: p.MaxRetryAttempts,
		metrics:          p.metrics,
		ctx:              ctx,
	}
}

type authorizationRequest struct {
	Action  Action     `json:"action"`
	Subject *parameter `json:"subject"`
	Object  *parameter `json:"object"`
}

type parameter struct {
	Namespace string   `json:"namespace"`
	Values    []string `json:"value"`
}
