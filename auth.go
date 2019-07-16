package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/dgrijalva/jwt-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"
)

var metrics *prometheus.SummaryVec

func init() {
	metrics = promauto.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "authz_latency",
			Help:       "Authz request latency (in seconds)",
			Objectives: map[float64]float64{0.5: 0.05, 0.95: 0.005, 0.99: 0.001},
			MaxAge:     time.Hour,
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

// ErrAuthorization indicates 403 Forbidden HTTP status code
var ErrAuthorization = fmt.Errorf("not authorized")

// ErrTenant indicates tenant error
var ErrTenant = fmt.Errorf("error performing tenant request, see server logs for details")

// Auth is interface containing methods to authenticate and authorize users
type Auth interface {
	JWT(r *http.Request) *jwt.Token
	Claims(r *http.Request) *jwt.StandardClaims
	Tenant(issuer string) Tenant
	Permission(audience string) Permission
	TokenValidationMiddleware() func(next http.Handler) http.Handler
}

// Tenant interface contains methods to check authentication
type Tenant interface {
	Trusted() bool
}

// Permission interface contains methods to check authorization
type Permission interface {
	Check(claims *jwt.StandardClaims, action Action, objectValues ...string) error
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
func (auth *TenantAuth) JWT(r *http.Request) *jwt.Token {
	return r.Context().Value(tokenContextKey).(*jwt.Token)
}

// Claims from JWT
func (auth *TenantAuth) Claims(r *http.Request) *jwt.StandardClaims {
	return auth.JWT(r).Claims.(*jwt.StandardClaims)
}

// Tenant instance
func (auth *TenantAuth) Tenant(issuer string) Tenant {
	if tenant, ok := auth.Tenants[issuer]; ok {
		return tenant
	}
	return nil
}

// Permission instance
func (auth *TenantAuth) Permission(audience string) Permission {
	if permission, ok := auth.Permissions[audience]; ok {
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
				for _, audience := range tenant.Audience {
					if claims.VerifyAudience(audience, true) {
						goto audienceVerified
					}
				}
				return nil, fmt.Errorf("JWT: audience=%v for issuer=%v is not allowed", claims.Audience, claims.Issuer)
			audienceVerified:
				return tenant.keyBytes(), nil
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
	Audience  []string
	Key       string
	IsTrusted bool `toml:"trusted"`

	key  []byte
	once sync.Once
}

func (tenant *tenant) Trusted() bool {
	return tenant.IsTrusted
}

func (tenant *tenant) keyBytes() []byte {
	tenant.once.Do(func() {
		if key, err := ioutil.ReadFile(tenant.Key); err == nil {
			tenant.key = bytes.TrimSpace(key)
		} else {
			logrus.WithError(err).Panic("can't read tenant key file")
		}
	})
	return tenant.key
}

type permission struct {
	URL       string `toml:"uri"`
	Token     string `toml:"token"`
	ServiceID string `toml:"service_id"`

	metrics prometheus.ObserverVec
}

func (permission *permission) Check(claims *jwt.StandardClaims, action Action, objectValues ...string) error {
	authorizedActions := make([]Action, 0)
	authRequest := &authorizationRequest{
		Action:  action,
		Subject: &parameter{claims.Audience, []string{"accounts", claims.Subject}},
		Object:  &parameter{permission.ServiceID, objectValues},
	}
	body, err := json.Marshal(authRequest)
	if err == nil {
		var request *http.Request
		if request, err = http.NewRequest(http.MethodPost, permission.URL, bytes.NewBuffer(body)); err == nil {
			var response *http.Response
			request.Header.Set("Authorization", fmt.Sprintf("Bearer %v", permission.Token))
			request.Header.Set("Accept", "application/json")
			request.Header.Set("Content-Type", "application/json; charset=utf-8")
			if response, err = httpClient().Do(request, permission.metrics); err == nil {
				defer response.Body.Close()
				if response.StatusCode >= 300 {
					err = fmt.Errorf("bad response status code: %v", response.StatusCode)
				} else {
					err = json.NewDecoder(response.Body).Decode(&authorizedActions)
				}
			}
		}
	}
	if err != nil {
		logrus.WithError(err).WithField("url", permission.URL).Error("error performing tenant request")
		return ErrTenant
	}
	for _, authorizedAction := range authorizedActions {
		if action == authorizedAction {
			return nil
		}
	}
	return ErrAuthorization
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
