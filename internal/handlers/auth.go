package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sharan-industries/identity-service/internal/models"
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

	// Check for redirect_url in query parameter if not in body
	if req.RedirectURL == "" {
		req.RedirectURL = c.Query("redirect_url")
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

	// Check for redirect_url in query parameter if not in body
	if req.RedirectURL == "" {
		req.RedirectURL = c.Query("redirect_url")
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

// handleOAuthCallback handles the common OAuth callback logic for redirecting to frontend
func (h *AuthHandler) handleOAuthCallback(c *gin.Context, tokens *models.AuthTokens, user *models.User, redirectURL string) {
	// Construct frontend redirect URL with tokens
	frontendURL := "http://localhost:3000" // TODO: Make this configurable
	if redirectURL != "" {
		frontendURL = redirectURL
	} else {
		frontendURL += "/auth/callback"
	}
	
	// Add tokens as query parameters (for frontend to handle)
	// In production, consider using secure HTTP-only cookies instead
	redirectURLWithTokens := fmt.Sprintf("%s?access_token=%s&refresh_token=%s&user_id=%d&email=%s&first_name=%s&last_name=%s",
		frontendURL,
		tokens.AccessToken,
		tokens.RefreshToken,
		user.ID,
		user.Email,
		user.FirstName,
		user.LastName,
	)
	
	// Redirect to frontend
	c.Redirect(http.StatusTemporaryRedirect, redirectURLWithTokens)
}

func (h *AuthHandler) GoogleOAuth(c *gin.Context) {
	state := generateOAuthState()
	
	// Check for redirect_url parameter and include it in state
	redirectURL := c.Query("redirect_url")
	if redirectURL != "" {
		// Validate redirect URL
		if err := h.authService.ValidateRedirectURL(redirectURL); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("invalid redirect URL: %v", err),
			})
			return
		}
		// Store redirect URL in a separate cookie
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "oauth_redirect_url",
			Value:    redirectURL,
			MaxAge:   300, // 5 minutes
			Path:     "/",
			Domain:   "",
			Secure:   false,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
	
	// Set cookie with explicit SameSite=Lax for OAuth redirects
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		MaxAge:   300, // 5 minutes
		Path:     "/",
		Domain:   "",
		Secure:   false,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	
	authURL := h.authService.OAuthService.GetGoogleAuthURL(state)
	if authURL == "" {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Google OAuth not configured",
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"auth_url": authURL,
	})
}

func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	// Verify state parameter
	state := c.Query("state")
	cookieState, err := c.Cookie("oauth_state")
	
	if err != nil || state != cookieState {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid state parameter",
		})
		return
	}
	
	// Get stored redirect URL
	redirectURL, _ := c.Cookie("oauth_redirect_url")
	
	// Clear cookies
	c.SetCookie("oauth_state", "", -1, "/", "", false, true)
	c.SetCookie("oauth_redirect_url", "", -1, "/", "", false, true)
	
	// Get authorization code
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Authorization code not provided",
		})
		return
	}
	
	// Handle OAuth callback
	tokens, user, err := h.authService.OAuthService.HandleGoogleCallback(c.Request.Context(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("OAuth authentication failed: %v", err),
		})
		return
	}
	
	// Handle OAuth callback redirect
	h.handleOAuthCallback(c, tokens, user, redirectURL)
}

func (h *AuthHandler) MicrosoftOAuth(c *gin.Context) {
	state := generateOAuthState()
	
	// Check for redirect_url parameter and include it in state
	redirectURL := c.Query("redirect_url")
	if redirectURL != "" {
		// Validate redirect URL
		if err := h.authService.ValidateRedirectURL(redirectURL); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("invalid redirect URL: %v", err),
			})
			return
		}
		// Store redirect URL in a separate cookie
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "oauth_redirect_url",
			Value:    redirectURL,
			MaxAge:   300, // 5 minutes
			Path:     "/",
			Domain:   "",
			Secure:   false,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
	
	// Set cookie with explicit SameSite=Lax for OAuth redirects
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		MaxAge:   300, // 5 minutes
		Path:     "/",
		Domain:   "",
		Secure:   false,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	
	authURL := h.authService.OAuthService.GetMicrosoftAuthURL(state)
	if authURL == "" {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Microsoft OAuth not configured",
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"auth_url": authURL,
	})
}

func (h *AuthHandler) MicrosoftCallback(c *gin.Context) {
	// Verify state parameter
	state := c.Query("state")
	cookieState, err := c.Cookie("oauth_state")
	if err != nil || state != cookieState {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid state parameter",
		})
		return
	}
	
	// Clear state cookie
	c.SetCookie("oauth_state", "", -1, "/", "", false, true)
	
	// Get authorization code
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Authorization code not provided",
		})
		return
	}
	
	// Handle OAuth callback
	tokens, user, err := h.authService.OAuthService.HandleMicrosoftCallback(c.Request.Context(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("OAuth authentication failed: %v", err),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"user": gin.H{
			"id":         user.ID,
			"email":      user.Email,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
		},
		"tokens": tokens,
	})
}

// generateOAuthState generates a random state string for OAuth security
func generateOAuthState() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (h *AuthHandler) GitHubOAuth(c *gin.Context) {
	state := generateOAuthState()
	
	// Set cookie with explicit SameSite=Lax for OAuth redirects
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		MaxAge:   300, // 5 minutes
		Path:     "/",
		Domain:   "",
		Secure:   false,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	
	authURL := h.authService.OAuthService.GetGitHubAuthURL(state)
	if authURL == "" {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "GitHub OAuth not configured",
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"auth_url": authURL,
	})
}

func (h *AuthHandler) GitHubCallback(c *gin.Context) {
	// Verify state parameter
	state := c.Query("state")
	cookieState, err := c.Cookie("oauth_state")
	if err != nil || state != cookieState {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid state parameter",
		})
		return
	}
	
	// Clear state cookie
	c.SetCookie("oauth_state", "", -1, "/", "", false, true)
	
	// Get authorization code
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Authorization code not provided",
		})
		return
	}
	
	// Handle OAuth callback
	tokens, user, err := h.authService.OAuthService.HandleGitHubCallback(c.Request.Context(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("OAuth authentication failed: %v", err),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"user": gin.H{
			"id":         user.ID,
			"email":      user.Email,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
		},
		"tokens": tokens,
	})
}
