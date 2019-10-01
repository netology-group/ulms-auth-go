package auth

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/cache/v7"
	"github.com/go-redis/redis/v7"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

var cases = map[string]struct {
	expectedStatusCode int
	expectedBody       string
	claims             *jwt.StandardClaims
	key                string
}{
	"noErrors": {
		expectedStatusCode: http.StatusOK,
		claims: &jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			Issuer:    "iam.example.com",
			Audience:  "example.com",
		},
		key: "secret",
	},
	"unknownTenant": {
		expectedStatusCode: http.StatusUnauthorized,
		claims: &jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			Issuer:    "unknownTenant",
			Audience:  "example.com",
		},
		expectedBody: "JWT: unknown issuer (authn): unknownTenant\n",
		key:          "secret",
	},
	"audienceMismatch": {
		expectedStatusCode: http.StatusUnauthorized,
		claims: &jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			Issuer:    "iam.example.com",
			Audience:  "audienceMismatch",
		},
		expectedBody: "JWT: audience=audienceMismatch for issuer=iam.example.com is not allowed\n",
		key:          "secret",
	},
	"invalidSign": {
		expectedStatusCode: http.StatusUnauthorized,
		claims: &jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			Issuer:    "iam.example.com",
			Audience:  "example.com",
		},
		expectedBody: "signature is invalid\n",
		key:          "invalidSign",
	},
	"tokenNotProvided": {
		expectedStatusCode: http.StatusUnauthorized,
		expectedBody:       "token contains an invalid number of segments\n",
	},
}

func TestJWTValidationErrorsOverQuery(t *testing.T) {
	auth, err := LoadConfiguration("fixtures/auth.toml", nil)
	assert.NoError(t, err)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	for testName, testCase := range cases {
		t.Run(testName, func(t *testing.T) {
			var accessToken string
			if testCase.claims != nil {
				accessToken, err = jwt.NewWithClaims(
					jwt.GetSigningMethod("HS256"),
					testCase.claims,
				).SignedString([]byte(testCase.key))
				assert.NoError(t, err)
			}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.URL.RawQuery = url.Values{"access_token": []string{accessToken}}.Encode()
			auth.TokenValidationMiddleware()(handler).ServeHTTP(response, request)
			assert.Equal(t, testCase.expectedStatusCode, response.Code)
			assert.Equal(t, testCase.expectedBody, response.Body.String())
		})
	}
}

func TestJWTValidationErrorsOverHeader(t *testing.T) {
	auth, err := LoadConfiguration("fixtures/auth.toml", nil)
	assert.NoError(t, err)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	for testName, testCase := range cases {
		t.Run(testName, func(t *testing.T) {
			var accessToken string
			if testCase.claims != nil {
				accessToken, err = jwt.NewWithClaims(
					jwt.GetSigningMethod("HS256"),
					testCase.claims,
				).SignedString([]byte(testCase.key))
				assert.NoError(t, err)
			}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set("Authorization", fmt.Sprintf("Bearer %v", accessToken))
			auth.TokenValidationMiddleware()(handler).ServeHTTP(response, request)
			assert.Equal(t, testCase.expectedStatusCode, response.Code)
			assert.Equal(t, testCase.expectedBody, response.Body.String())
		})
	}
}

func TestPermissionCheckFromCache(t *testing.T) {
	ring := redis.NewRing(&redis.RingOptions{
		Addrs: map[string]string{
			"redis": ":6379",
		},
	})
	codec := &cache.Codec{
		Redis: ring,
		Marshal: func(v interface{}) ([]byte, error) {
			return json.Marshal(v)
		},
		Unmarshal: func(b []byte, v interface{}) error {
			return json.Unmarshal(b, v)
		},
	}
	URL := "url"
	serviceID := "service-id"
	action := "action"
	claims := &jwt.StandardClaims{}
	key := fmt.Sprintf("authz:%v:%v:%v:%v:%v:", URL, serviceID, claims.Audience, claims.Subject, action)
	_ = codec.Delete(key)
	perm := &permission{
		URL:              URL,
		Token:            "token",
		ServiceID:        serviceID,
		MaxRetryAttempts: 0,
		metrics:          metrics,
		ctx:              nil,
		cacheCodec:       codec,
	}
	assert.Error(t, perm.Check(claims, Action(action)))
	assert.Error(t, codec.Get(key, new(struct{}))) // should not cache errors
	assert.NoError(t, codec.Set(&cache.Item{       // store result in cache
		Key:        key,
		Expiration: time.Minute,
	}))
	assert.NoError(t, perm.Check(claims, Action(action))) // result without error from cache
}
