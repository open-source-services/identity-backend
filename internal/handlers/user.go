package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"github.com/sharan-industries/identity-service/internal/config"
	"github.com/sharan-industries/identity-service/internal/models"
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

	// Fetch user from database with roles
	var user models.User
	if err := h.db.Preload("Roles").First(&user, userID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "not_found",
				"message": "User not found",
			})
			return
		}
		
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "database_error",
			"message": "Failed to fetch user profile",
		})
		return
	}

	// Return user profile without sensitive data
	c.JSON(http.StatusOK, gin.H{
		"data": user.ToResponse(),
		"message": "Profile retrieved successfully",
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

	// Find user in database
	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "not_found",
				"message": "User not found",
			})
			return
		}
		
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "database_error",
			"message": "Failed to fetch user",
		})
		return
	}

	// Update allowed fields
	user.FirstName = req.FirstName
	user.LastName = req.LastName
	if req.AvatarURL != "" {
		user.AvatarURL = req.AvatarURL
	}

	// Save updates to database
	if err := h.db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "database_error",
			"message": "Failed to update profile",
		})
		return
	}

	// Return updated profile
	c.JSON(http.StatusOK, gin.H{
		"message": "Profile updated successfully",
		"data": user.ToResponse(),
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

	// Start a transaction for atomic operations
	tx := h.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Find user in database
	var user models.User
	if err := tx.First(&user, userID).Error; err != nil {
		tx.Rollback()
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "not_found",
				"message": "User not found",
			})
			return
		}
		
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "database_error",
			"message": "Failed to fetch user",
		})
		return
	}

	// Revoke all refresh tokens for this user
	if err := tx.Model(&models.RefreshToken{}).Where("user_id = ?", userID).Update("is_revoked", true).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "database_error",
			"message": "Failed to revoke tokens",
		})
		return
	}

	// Soft delete the user (preserves data with deleted_at timestamp)
	if err := tx.Delete(&user).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "database_error",
			"message": "Failed to delete account",
		})
		return
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "database_error",
			"message": "Failed to complete account deletion",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Account deleted successfully",
	})
}