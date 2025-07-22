package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sharan-industries/identity-service/internal/services"
)

// AuthRequired is a middleware that validates JWT tokens
func AuthRequired(jwtService *services.JWTService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"message": "Authorization header is required",
			})
			c.Abort()
			return
		}

		// Check if token has Bearer prefix
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"message": "Authorization header must be Bearer token",
			})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// Validate token using JWT service
		claims, err := jwtService.ValidateAccessToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"message": "Invalid token",
			})
			c.Abort()
			return
		}

		// Set user info and permissions in context
		c.Set("user_id", claims.UserID)
		c.Set("user_email", claims.Email)
		c.Set("user_roles", claims.Roles)
		c.Set("user_permissions", claims.Permissions)
		c.Set("user_scopes", claims.Scopes)
		c.Set("claims", claims)
		c.Next()
	}
}

// OptionalAuth is a middleware that validates JWT tokens but doesn't require them
func OptionalAuth(jwtService *services.JWTService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		// Check if token has Bearer prefix
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.Next()
			return
		}

		tokenString := parts[1]

		// Validate token using JWT service
		claims, err := jwtService.ValidateAccessToken(tokenString)
		if err != nil {
			c.Next()
			return
		}

		// Set user info and permissions in context if valid
		c.Set("user_id", claims.UserID)
		c.Set("user_email", claims.Email)
		c.Set("user_roles", claims.Roles)
		c.Set("user_permissions", claims.Permissions)
		c.Set("user_scopes", claims.Scopes)
		c.Set("claims", claims)
		c.Next()
	}
}