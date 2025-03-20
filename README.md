# Booking Eco Shared Go Packages

This repository contains shared Go packages for the Booking Eco microservices ecosystem.

## Installation

```bash
go get github.com/PdxFullStack/Booking-go-shared
```

## Packages

### Auth Middleware

The auth middleware provides JWT token verification using asymmetric encryption (RS256). It verifies tokens issued by the authentication service using the public key provided in the consuming application's environment variables.

```go
import "github.com/PdxFullStack/Booking-go-shared/middleware/auth"
```

## Usage

### JWT Middleware

The JWT middleware verifies tokens and adds user claims to the request context.

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/PdxFullStack/Booking-go-shared/middleware/auth"
)

func main() {
	// Create a protected route with default configuration
	http.Handle("/api/protected", auth.VerifyJWT()(http.HandlerFunc(protectedHandler)))

	// Create a route that requires specific scopes
	http.Handle("/api/admin", auth.VerifyJWTWithScopes("admin")(http.HandlerFunc(adminHandler)))

	// Start the server
	http.ListenAndServe(":8080", nil)
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from the token
	userID, err := auth.ExtractUserID(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "Hello, User %s!", userID)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, Admin!")
}
```

### Configuration

The middleware requires the public key to be set in the environment variable:

```bash
export JWT_PUBLIC_KEY="$(cat public.pem)"
```

You can customize the environment variable name:

```go
config := auth.DefaultConfig()
config.PublicKeyEnv = "MY_CUSTOM_PUBLIC_KEY_ENV"
http.Handle("/api/custom", auth.VerifyJWTWithConfig(config)(http.HandlerFunc(customHandler)))
```

### Custom Token Extraction

By default, tokens are extracted from the Authorization header. You can provide a custom extractor:

```go
config := auth.DefaultConfig()
config.TokenExtractor = func(r *http.Request) (string, error) {
    return r.URL.Query().Get("token"), nil
}
http.Handle("/api/query-token", auth.VerifyJWTWithConfig(config)(http.HandlerFunc(queryTokenHandler)))
```

### Accessing Claims

You can access the full claims object:

```go
func userHandler(w http.ResponseWriter, r *http.Request) {
    claims, err := auth.GetClaims(r.Context())
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    
    fmt.Fprintf(w, "User: %s, Email: %s", claims.UserID, claims.Email)
}
```

## Import Paths

Here are the import paths for all available packages:

```go

// Authentication middleware
import "github.com/PdxFullStack/Booking-go-shared/middleware/auth"
```

## Security Considerations

1. Always store your public key securely in environment variables
2. Never log or expose the token content in production
3. Use HTTPS in production environments
4. Consider setting appropriate token expiration times

## License

MIT License 