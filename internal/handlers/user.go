package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"github.com/sharan-industries/identity-service/internal/config"
)

type UserHandler struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewUserHandler(db *gorm.DB, cfg *config.Config) *UserHandler {
	return &UserHandler{
		db:  db,
		cfg: cfg,
	}
}

// UpdateProfileRequest represents the profile update request payload
type UpdateProfileRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	AvatarURL string `json:"avatar_url"`
}

// GetProfile handles getting user profile
func (h *UserHandler) GetProfile(c *gin.Context) {
	// Get user ID from middleware context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "unauthorized",
			"message": "User ID not found in token",
		})
		return
	}

	// TODO: Implement get profile logic
	// - Fetch user from database
	// - Return user profile (without sensitive data)

	c.JSON(http.StatusOK, gin.H{
		"message": "Get profile endpoint - to be implemented",
		"user_id": userID,
	})
}

// UpdateProfile handles updating user profile
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	// Get user ID from middleware context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "unauthorized",
			"message": "User ID not found in token",
		})
		return
	}

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "validation_error",
			"message": err.Error(),
		})
		return
	}

	// TODO: Implement update profile logic
	// - Find user in database
	// - Update allowed fields
	// - Return updated profile

	c.JSON(http.StatusOK, gin.H{
		"message": "Update profile endpoint - to be implemented",
		"user_id": userID,
		"data": req,
	})
}

// DeleteAccount handles account deletion
func (h *UserHandler) DeleteAccount(c *gin.Context) {
	// Get user ID from middleware context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "unauthorized",
			"message": "User ID not found in token",
		})
		return
	}

	// TODO: Implement account deletion logic
	// - Soft delete or hard delete user
	// - Revoke all tokens
	// - Clean up associated data

	c.JSON(http.StatusOK, gin.H{
		"message": "Delete account endpoint - to be implemented",
		"user_id": userID,
	})
}