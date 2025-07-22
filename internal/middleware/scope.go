package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sharan-industries/identity-service/internal/services"
)

// RequireScope is a middleware that checks if the user has required scopes
func RequireScope(requiredScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get claims from context (set by AuthRequired middleware)
		claimsInterface, exists := c.Get("claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"message": "Authentication required",
			})
			c.Abort()
			return
		}

		claims, ok := claimsInterface.(*services.Claims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"message": "Invalid token claims",
			})
			c.Abort()
			return
		}

		// Check if user has any of the required scopes
		if !claims.HasAnyScope(requiredScopes...) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "forbidden",
				"message": "Insufficient permissions",
				"required_scopes": requiredScopes,
				"user_scopes": claims.Scopes,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAllScopes is a middleware that checks if the user has all required scopes
func RequireAllScopes(requiredScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claimsInterface, exists := c.Get("claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"message": "Authentication required",
			})
			c.Abort()
			return
		}

		claims, ok := claimsInterface.(*services.Claims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"message": "Invalid token claims",
			})
			c.Abort()
			return
		}

		// Check if user has all required scopes
		if !claims.HasAllScopes(requiredScopes...) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "forbidden",
				"message": "Insufficient permissions",
				"required_scopes": requiredScopes,
				"user_scopes": claims.Scopes,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireRole is a middleware that checks if the user has a required role
func RequireRole(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claimsInterface, exists := c.Get("claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"message": "Authentication required",
			})
			c.Abort()
			return
		}

		claims, ok := claimsInterface.(*services.Claims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"message": "Invalid token claims",
			})
			c.Abort()
			return
		}

		// Check if user has any of the required roles
		hasRole := false
		for _, role := range requiredRoles {
			if claims.HasRole(role) {
				hasRole = true
				break
			}
		}

		if !hasRole {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "forbidden",
				"message": "Insufficient permissions",
				"required_roles": requiredRoles,
				"user_roles": claims.Roles,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequirePermission is a middleware that checks if the user has a required permission
func RequirePermission(requiredPermissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claimsInterface, exists := c.Get("claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"message": "Authentication required",
			})
			c.Abort()
			return
		}

		claims, ok := claimsInterface.(*services.Claims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"message": "Invalid token claims",
			})
			c.Abort()
			return
		}

		// Check if user has any of the required permissions
		hasPermission := false
		for _, permission := range requiredPermissions {
			if claims.HasPermission(permission) {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "forbidden",
				"message": "Insufficient permissions",
				"required_permissions": requiredPermissions,
				"user_permissions": claims.Permissions,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}