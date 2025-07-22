package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client provides methods for other services to interact with the identity service
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient creates a new identity service client
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// UserClaims represents the user information from a validated JWT
type UserClaims struct {
	UserID      uint     `json:"user_id"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	Scopes      []string `json:"scopes"`
}

// ValidateTokenRequest represents the token validation request
type ValidateTokenRequest struct {
	Token string `json:"token"`
}

// ValidateTokenResponse represents the token validation response
type ValidateTokenResponse struct {
	Valid  bool        `json:"valid"`
	Claims *UserClaims `json:"claims,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// ValidateToken validates a JWT token with the identity service
func (c *Client) ValidateToken(token string) (*UserClaims, error) {
	req := ValidateTokenRequest{Token: token}
	
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.HTTPClient.Post(
		c.BaseURL+"/api/v1/auth/validate",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	var validateResp ValidateTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&validateResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !validateResp.Valid {
		return nil, fmt.Errorf("invalid token: %s", validateResp.Error)
	}

	return validateResp.Claims, nil
}

// HasPermission checks if the user has a specific permission
func (u *UserClaims) HasPermission(permission string) bool {
	for _, p := range u.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasRole checks if the user has a specific role
func (u *UserClaims) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasScope checks if the user has a specific scope
func (u *UserClaims) HasScope(scope string) bool {
	for _, s := range u.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope checks if the user has any of the provided scopes
func (u *UserClaims) HasAnyScope(scopes ...string) bool {
	for _, scope := range scopes {
		if u.HasScope(scope) {
			return true
		}
	}
	return false
}

// Middleware creates HTTP middleware for protecting routes
func (c *Client) Middleware(requiredScopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			// Extract Bearer token
			if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
				http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
				return
			}

			token := authHeader[7:]

			// Validate token
			claims, err := c.ValidateToken(token)
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Check required scopes
			if len(requiredScopes) > 0 && !claims.HasAnyScope(requiredScopes...) {
				http.Error(w, "Insufficient permissions", http.StatusForbidden)
				return
			}

			// Add claims to request context
			ctx := r.Context()
			ctx = WithUserClaims(ctx, claims)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// Example usage in other services:
//
// func main() {
//     authClient := auth.NewClient("http://identity-service:8080")
//     
//     // Protect route with required scopes
//     protectedHandler := authClient.Middleware("users:read")(yourHandler)
//     
//     http.Handle("/api/users", protectedHandler)
//     http.ListenAndServe(":8081", nil)
// }