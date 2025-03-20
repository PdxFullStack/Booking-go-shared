package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Key type for storing claims in context
type contextKey string

const (
	// ClaimsContextKey is the key used to store JWT claims in the request context
	ClaimsContextKey contextKey = "jwt_claims"

	// DefaultPublicKeyEnv is the default environment variable name for the JWT public key
	DefaultPublicKeyEnv = "JWT_PUBLIC_KEY"
)

// Config holds the middleware configuration
type Config struct {
	// PublicKeyEnv is the environment variable name containing the JWT public key in PEM format
	PublicKeyEnv string

	// Required scopes (if any)
	RequiredScopes []string

	// Optional function to extract the token from the request
	TokenExtractor func(r *http.Request) (string, error)
}

// DefaultConfig returns a default middleware configuration
func DefaultConfig() Config {
	return Config{
		PublicKeyEnv:   DefaultPublicKeyEnv,
		RequiredScopes: []string{},
		TokenExtractor: ExtractTokenFromHeader,
	}
}

// JWTClaims holds the JWT claims with additional custom fields
type JWTClaims struct {
	UserID string   `json:"user_id"`
	Email  string   `json:"email"`
	Scopes []string `json:"scopes,omitempty"`
	jwt.RegisteredClaims
}

// Middleware returns an HTTP middleware that verifies JWT tokens
func Middleware(config Config) func(http.Handler) http.Handler {
	// If no config is provided, use the default
	if config.PublicKeyEnv == "" {
		config.PublicKeyEnv = DefaultPublicKeyEnv
	}

	// If no token extractor is provided, use the default
	if config.TokenExtractor == nil {
		config.TokenExtractor = ExtractTokenFromHeader
	}

	// Load the public key once at startup
	publicKey, err := loadPublicKeyFromEnv(config.PublicKeyEnv)
	if err != nil {
		// Log the error but still create the middleware (it will reject all requests)
		fmt.Printf("JWT Middleware Error: %v\n", err)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from request
			tokenString, err := config.TokenExtractor(r)
			if err != nil {
				http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
				return
			}

			// Parse and validate token
			claims := &JWTClaims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				// Validate signing method
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return publicKey, nil
			})

			if err != nil || !token.Valid {
				http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
				return
			}

			// Check required scopes
			if len(config.RequiredScopes) > 0 {
				if !hasRequiredScopes(claims.Scopes, config.RequiredScopes) {
					http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
					return
				}
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ExtractTokenFromHeader extracts a JWT token from the Authorization header
func ExtractTokenFromHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header is required")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", errors.New("authorization header format must be 'Bearer {token}'")
	}

	return parts[1], nil
}

// GetClaims retrieves JWT claims from context
func GetClaims(ctx context.Context) (*JWTClaims, error) {
	claims, ok := ctx.Value(ClaimsContextKey).(*JWTClaims)
	if !ok {
		return nil, errors.New("jwt claims not found in context")
	}
	return claims, nil
}

// loadPublicKeyFromEnv loads and parses the RSA public key from the specified environment variable
func loadPublicKeyFromEnv(envName string) (*rsa.PublicKey, error) {
	publicKeyPEM := os.Getenv(envName)
	if publicKeyPEM == "" {
		return nil, fmt.Errorf("environment variable %s is not set", envName)
	}

	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

// hasRequiredScopes checks if the token has all required scopes
func hasRequiredScopes(tokenScopes, requiredScopes []string) bool {
	if len(requiredScopes) == 0 {
		return true
	}

	scopeMap := make(map[string]bool)
	for _, scope := range tokenScopes {
		scopeMap[scope] = true
	}

	for _, requiredScope := range requiredScopes {
		if !scopeMap[requiredScope] {
			return false
		}
	}

	return true
}
