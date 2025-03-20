package auth

import (
	"net/http"
)

// VerifyJWT creates a middleware with default configuration.
// This is the simplest way to add JWT authentication to a route.
//
// Example:
//
//	http.Handle("/api/protected", auth.VerifyJWT()(http.HandlerFunc(protectedHandler)))
func VerifyJWT() func(http.Handler) http.Handler {
	return Middleware(DefaultConfig())
}

// VerifyJWTWithScopes creates a middleware that requires specific authorization scopes.
// The handler will return a 403 Forbidden response if the token doesn't contain all required scopes.
//
// Example:
//
//	http.Handle("/api/admin", auth.VerifyJWTWithScopes("admin")(http.HandlerFunc(adminHandler)))
func VerifyJWTWithScopes(scopes ...string) func(http.Handler) http.Handler {
	config := DefaultConfig()
	config.RequiredScopes = scopes
	return Middleware(config)
}

// VerifyJWTWithConfig creates a middleware with a custom configuration.
// Use this when you need to customize token extraction, environment variables,
// or other advanced settings.
//
// Example:
//
//	config := auth.DefaultConfig()
//	config.PublicKeyEnv = "CUSTOM_PUBLIC_KEY_ENV"
//	http.Handle("/api/custom", auth.VerifyJWTWithConfig(config)(http.HandlerFunc(customHandler)))
func VerifyJWTWithConfig(config Config) func(http.Handler) http.Handler {
	return Middleware(config)
}

// ExtractUserID is a helper function to get the user ID from a request context.
// The request must have gone through the JWT middleware first.
//
// Returns an error if the claims are not in the context or if the user ID is empty.
func ExtractUserID(r *http.Request) (string, error) {
	claims, err := GetClaims(r.Context())
	if err != nil {
		return "", err
	}
	return claims.UserID, nil
}

// ExtractEmail is a helper function to get the email from a request context.
// The request must have gone through the JWT middleware first.
//
// Returns an error if the claims are not in the context or if the email is empty.
func ExtractEmail(r *http.Request) (string, error) {
	claims, err := GetClaims(r.Context())
	if err != nil {
		return "", err
	}
	return claims.Email, nil
}

// HasScope checks if the request contains a JWT with a particular scope.
// Returns false if the request doesn't have valid claims or if the scope is not present.
//
// Example:
//
//	if auth.HasScope(r, "admin") {
//	    // Perform admin actions
//	}
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
