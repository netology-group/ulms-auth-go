package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"io/ioutil"
	"net/http"
	"strings"
)

var metrics *prometheus.SummaryVec

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
	CheckWithContext(ctx context.Context, cancel context.CancelFunc, claims *jwt.StandardClaims, action Action, objectValues ...string) error
}

// TenantAuth implements Auth interface using tenants
type TenantAuth struct {
	Tenants     map[string]*tenant     `toml:"authn"`
	Permissions map[string]*permission `toml:"authz"`
}

// LoadConfiguration loads current TenantAuth configuration
func LoadConfiguration(configFile string) (Auth, error) {
	auth := &TenantAuth{}
	if _, err := toml.DecodeFile(configFile, auth); err != nil {
		return nil, err
	}
	for audience, permission := range auth.Permissions {
		permission.metrics = metrics.MustCurryWith(prometheus.Labels{"audience": audience})
	}
	return auth, nil
}

// JWT returns request's JWT
func JWT(r *http.Request) *jwt.Token {
	return r.Context().Value(tokenContextKey).(*jwt.Token)
}

// Claims from request's JWT
func Claims(r *http.Request) *jwt.StandardClaims {
	return JWT(r).Claims.(*jwt.StandardClaims)
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

	metrics prometheus.ObserverVec
}

func (permission *permission) Check(claims *jwt.StandardClaims, action Action, objectValues ...string) error {
	return permission.CheckWithContext(nil, nil, claims, action, objectValues...)
}

func (permission *permission) CheckWithContext(ctx context.Context, cancel context.CancelFunc, claims *jwt.StandardClaims, action Action, objectValues ...string) error {
	if cancel != nil {
		defer cancel()
	}
	if permission.URL == "" {
		// always allow any action if permission.URL is not defined
		return nil
	}
	var authorizedActions []Action
	authRequest := &authorizationRequest{
		Action:  action,
		Subject: &parameter{claims.Audience, []string{"accounts", claims.Subject}},
		Object:  &parameter{permission.ServiceID, objectValues},
	}
	body, _ := json.Marshal(authRequest)
	request, err := http.NewRequest(http.MethodPost, permission.URL, bytes.NewBuffer(body))
	attempt := 1
	if err == nil {
		if ctx != nil {
			request = request.WithContext(ctx)
		}
		var response *http.Response
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %v", permission.Token))
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Content-Type", "application/json; charset=utf-8")
		for {
			if response, err = client.do(request, permission.metrics); err == nil {
				if response.StatusCode != 200 {
					err = fmt.Errorf("non-200 response status code: %v", response.StatusCode)
				} else {
					err = json.NewDecoder(response.Body).Decode(&authorizedActions)
				}
				_ = response.Body.Close()
			}
			if err == nil || attempt >= permission.MaxRetryAttempts+1 {
				break
			}
			attempt++
		}
	}
	if err != nil {
		return errors.Wrapf(err, "error performing authz request, attempts: %d, URL: %s", attempt, permission.URL)
	}
	for _, authorizedAction := range authorizedActions {
		if action == authorizedAction {
			return nil
		}
	}
	return ErrorNotAuthorized
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
