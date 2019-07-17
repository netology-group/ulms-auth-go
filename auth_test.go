package auth

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
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
	auth, err := LoadConfiguration("fixtures/auth.toml")
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
	auth, err := LoadConfiguration("fixtures/auth.toml")
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
