package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sharan-industries/identity-service/internal/services"
)

type AuthHandler struct {
	authService *services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// RegisterRequest represents the registration request payload
type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name" binding:"required"`
}

// LoginRequest represents the login request payload
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// TokenResponse represents the response containing JWT tokens
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// Register handles user registration
func (h *AuthHandler) Register(c *gin.Context) {
	var req services.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "validation_error",
			"message": err.Error(),
		})
		return
	}

	response, err := h.authService.Register(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "registration_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Registration successful",
		"data":    response,
	})
}

// Login handles user authentication
func (h *AuthHandler) Login(c *gin.Context) {
	var req services.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "validation_error",
			"message": err.Error(),
		})
		return
	}

	response, err := h.authService.Login(&req)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"data":    response,
	})
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "validation_error",
			"message": err.Error(),
		})
		return
	}

	tokens, err := h.authService.RefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "token_refresh_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Token refreshed successfully",
		"data": tokens,
	})
}

// Logout handles user logout
func (h *AuthHandler) Logout(c *gin.Context) {
	// Get user ID from middleware context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "unauthorized",
			"message": "User ID not found in token",
		})
		return
	}

	// Optional: Get refresh token from request body
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	c.ShouldBindJSON(&req)

	if err := h.authService.Logout(userID.(uint), req.RefreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "logout_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logout successful",
	})
}

// OAuth handlers (placeholder implementations)

func (h *AuthHandler) GoogleOAuth(c *gin.Context) {
	// TODO: Implement Google OAuth initiation
	c.JSON(http.StatusOK, gin.H{
		"message": "Google OAuth endpoint - to be implemented",
	})
}

func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	// TODO: Implement Google OAuth callback
	c.JSON(http.StatusOK, gin.H{
		"message": "Google OAuth callback - to be implemented",
	})
}

func (h *AuthHandler) GitHubOAuth(c *gin.Context) {
	// TODO: Implement GitHub OAuth initiation
	c.JSON(http.StatusOK, gin.H{
		"message": "GitHub OAuth endpoint - to be implemented",
	})
}

func (h *AuthHandler) GitHubCallback(c *gin.Context) {
	// TODO: Implement GitHub OAuth callback
	c.JSON(http.StatusOK, gin.H{
		"message": "GitHub OAuth callback - to be implemented",
	})
}