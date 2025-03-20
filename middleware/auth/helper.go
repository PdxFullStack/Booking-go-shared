package auth

import (
	"net/http"
)

// VerifyJWT creates a middleware with default configuration
func VerifyJWT() func(http.Handler) http.Handler {
	return Middleware(DefaultConfig())
}

// VerifyJWTWithScopes creates a middleware that requires specific scopes
func VerifyJWTWithScopes(scopes ...string) func(http.Handler) http.Handler {
	config := DefaultConfig()
	config.RequiredScopes = scopes
	return Middleware(config)
}

// VerifyJWTWithConfig creates a middleware with a custom configuration
func VerifyJWTWithConfig(config Config) func(http.Handler) http.Handler {
	return Middleware(config)
}

// ExtractUserID is a helper function to get the user ID from context
func ExtractUserID(r *http.Request) (string, error) {
	claims, err := GetClaims(r.Context())
	if err != nil {
		return "", err
	}
	return claims.UserID, nil
}

// ExtractEmail is a helper function to get the email from context
func ExtractEmail(r *http.Request) (string, error) {
	claims, err := GetClaims(r.Context())
	if err != nil {
		return "", err
	}
	return claims.Email, nil
}

// HasScope checks if the request has a particular scope
func HasScope(r *http.Request, scope string) bool {
	claims, err := GetClaims(r.Context())
	if err != nil {
		return false
	}

	for _, s := range claims.Scopes {
		if s == scope {
			return true
		}
	}

	return false
}
