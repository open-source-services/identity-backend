package services

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sharan-industries/identity-service/internal/config"
	"github.com/sharan-industries/identity-service/internal/models"
)

// JWTService handles JWT token operations
type JWTService struct {
	cfg *config.Config
}

// NewJWTService creates a new JWT service
func NewJWTService(cfg *config.Config) *JWTService {
	return &JWTService{
		cfg: cfg,
	}
}

// Claims represents the JWT claims with scopes
type Claims struct {
	UserID      uint     `json:"user_id"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	jwt.RegisteredClaims
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scopes       []string  `json:"scopes,omitempty"`
}

// GenerateTokenPair generates both access and refresh tokens
func (j *JWTService) GenerateTokenPair(user *models.User, userPermissions *models.UserPermissions) (*TokenPair, error) {
	// Generate access token
	accessToken, expiresAt, err := j.GenerateAccessToken(user, userPermissions)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := j.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	expiresIn := int(j.cfg.JWTExpiry.Seconds())

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		ExpiresAt:    expiresAt,
		Scopes:       userPermissions.GetScopes(),
	}, nil
}

// GenerateAccessToken generates a JWT access token with user permissions
func (j *JWTService) GenerateAccessToken(user *models.User, userPermissions *models.UserPermissions) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(j.cfg.JWTExpiry)

	claims := &Claims{
		UserID:      user.ID,
		Email:       user.Email,
		Roles:       userPermissions.Roles,
		Permissions: userPermissions.Permissions,
		Scopes:      userPermissions.Scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "identity-service",
			Subject:   fmt.Sprintf("user:%d", user.ID),
			ID:        fmt.Sprintf("%d_%d", user.ID, now.Unix()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(j.cfg.JWTSecret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, expiresAt, nil
}

// GenerateRefreshToken generates a refresh token
func (j *JWTService) GenerateRefreshToken(userID uint) (string, error) {
	now := time.Now()
	expiresAt := now.Add(j.cfg.RefreshTokenExpiry)

	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Issuer:    "identity-service",
		Subject:   fmt.Sprintf("refresh:%d", userID),
		ID:        fmt.Sprintf("refresh_%d_%d", userID, now.Unix()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(j.cfg.JWTSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return tokenString, nil
}

// ValidateAccessToken validates and parses an access token
func (j *JWTService) ValidateAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.cfg.JWTSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// ValidateRefreshToken validates a refresh token
func (j *JWTService) ValidateRefreshToken(tokenString string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.cfg.JWTSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh token: %w", err)
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid refresh token claims")
}

// ExtractUserIDFromToken extracts user ID from token without full validation (for logout, etc.)
func (j *JWTService) ExtractUserIDFromToken(tokenString string) (uint, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(j.cfg.JWTSecret), nil
	})

	if err != nil {
		return 0, err
	}

	if claims, ok := token.Claims.(*Claims); ok {
		return claims.UserID, nil
	}

	return 0, fmt.Errorf("invalid token claims")
}

// HasPermission checks if the token claims contain a specific permission
func (c *Claims) HasPermission(permission string) bool {
	for _, p := range c.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasRole checks if the token claims contain a specific role
func (c *Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasScope checks if the token claims contain a specific scope
func (c *Claims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope checks if the token claims contain any of the provided scopes
func (c *Claims) HasAnyScope(scopes ...string) bool {
	for _, scope := range scopes {
		if c.HasScope(scope) {
			return true
		}
	}
	return false
}

// HasAllScopes checks if the token claims contain all of the provided scopes
func (c *Claims) HasAllScopes(scopes ...string) bool {
	for _, scope := range scopes {
		if !c.HasScope(scope) {
			return false
		}
	}
	return true
}