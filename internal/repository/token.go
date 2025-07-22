package repository

import (
	"crypto/sha256"
	"fmt"
	"time"

	"gorm.io/gorm"
	"github.com/sharan-industries/identity-service/internal/models"
)

// TokenRepository handles refresh token database operations
type TokenRepository struct {
	db *gorm.DB
}

// NewTokenRepository creates a new token repository
func NewTokenRepository(db *gorm.DB) *TokenRepository {
	return &TokenRepository{
		db: db,
	}
}

// CreateRefreshToken creates a new refresh token
func (r *TokenRepository) CreateRefreshToken(userID uint, token string, expiresAt time.Time) error {
	tokenHash := r.hashToken(token)
	
	refreshToken := &models.RefreshToken{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
		IsRevoked: false,
	}

	if err := r.db.Create(refreshToken).Error; err != nil {
		return fmt.Errorf("failed to create refresh token: %w", err)
	}
	return nil
}

// ValidateRefreshToken validates a refresh token
func (r *TokenRepository) ValidateRefreshToken(token string) (*models.RefreshToken, error) {
	tokenHash := r.hashToken(token)
	
	var refreshToken models.RefreshToken
	if err := r.db.Where("token_hash = ? AND is_revoked = ? AND expires_at > ?", 
		tokenHash, false, time.Now()).First(&refreshToken).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("refresh token not found or expired")
		}
		return nil, fmt.Errorf("failed to validate refresh token: %w", err)
	}

	return &refreshToken, nil
}

// RevokeRefreshToken revokes a refresh token
func (r *TokenRepository) RevokeRefreshToken(token string) error {
	tokenHash := r.hashToken(token)
	
	if err := r.db.Model(&models.RefreshToken{}).
		Where("token_hash = ?", tokenHash).
		Update("is_revoked", true).Error; err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}
	return nil
}

// RevokeAllUserTokens revokes all refresh tokens for a user
func (r *TokenRepository) RevokeAllUserTokens(userID uint) error {
	if err := r.db.Model(&models.RefreshToken{}).
		Where("user_id = ? AND is_revoked = ?", userID, false).
		Update("is_revoked", true).Error; err != nil {
		return fmt.Errorf("failed to revoke all user tokens: %w", err)
	}
	return nil
}

// CleanupExpiredTokens removes expired refresh tokens
func (r *TokenRepository) CleanupExpiredTokens() error {
	if err := r.db.Where("expires_at < ?", time.Now()).Delete(&models.RefreshToken{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}
	return nil
}

// GetUserActiveTokens returns active refresh tokens for a user
func (r *TokenRepository) GetUserActiveTokens(userID uint) ([]models.RefreshToken, error) {
	var tokens []models.RefreshToken
	if err := r.db.Where("user_id = ? AND is_revoked = ? AND expires_at > ?", 
		userID, false, time.Now()).Find(&tokens).Error; err != nil {
		return nil, fmt.Errorf("failed to get user active tokens: %w", err)
	}
	return tokens, nil
}

// RotateRefreshToken revokes old token and creates new one
func (r *TokenRepository) RotateRefreshToken(oldToken, newToken string, userID uint, expiresAt time.Time) error {
	// Start transaction
	tx := r.db.Begin()
	if tx.Error != nil {
		return fmt.Errorf("failed to start transaction: %w", tx.Error)
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Revoke old token
	oldTokenHash := r.hashToken(oldToken)
	if err := tx.Model(&models.RefreshToken{}).
		Where("token_hash = ?", oldTokenHash).
		Update("is_revoked", true).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to revoke old token: %w", err)
	}

	// Create new token
	newTokenHash := r.hashToken(newToken)
	refreshToken := &models.RefreshToken{
		UserID:    userID,
		TokenHash: newTokenHash,
		ExpiresAt: expiresAt,
		IsRevoked: false,
	}

	if err := tx.Create(refreshToken).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to create new refresh token: %w", err)
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// hashToken creates a SHA256 hash of the token for secure storage
func (r *TokenRepository) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", hash)
}