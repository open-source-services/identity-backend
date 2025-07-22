package services

import (
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
	"github.com/sharan-industries/identity-service/internal/config"
	"github.com/sharan-industries/identity-service/internal/models"
	"github.com/sharan-industries/identity-service/internal/repository"
)

// AuthService handles authentication business logic
type AuthService struct {
	cfg            *config.Config
	userRepo       *repository.UserRepository
	tokenRepo      *repository.TokenRepository
	jwtService     *JWTService
	OAuthService   *OAuthService
}

// NewAuthService creates a new authentication service
func NewAuthService(cfg *config.Config, userRepo *repository.UserRepository, tokenRepo *repository.TokenRepository, jwtService *JWTService) *AuthService {
	return &AuthService{
		cfg:        cfg,
		userRepo:   userRepo,
		tokenRepo:  tokenRepo,
		jwtService: jwtService,
	}
}

// RegisterRequest represents user registration data
type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name" binding:"required"`
}

// LoginRequest represents user login data
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	User   *models.UserResponse `json:"user"`
	Tokens *TokenPair           `json:"tokens"`
}

// Register creates a new user account
func (s *AuthService) Register(req *RegisterRequest) (*AuthResponse, error) {
	// Check if email already exists
	exists, err := s.userRepo.EmailExists(req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to check email existence: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("email already registered")
	}

	// Hash password
	hashedPassword, err := s.hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &models.User{
		Email:     req.Email,
		Password:  hashedPassword,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		IsActive:  true,
		IsEmailVerified: false, // Email verification can be added later
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Assign default user role
	if err := s.userRepo.AssignRole(user.ID, 1, user.ID); err != nil { // Assuming role ID 1 is "user" role
		log.Printf("Warning: Failed to assign default role to user %d: %v", user.ID, err)
	}
	
	// Get user permissions
	userPermissions, err := s.userRepo.GetUserPermissions(user.ID)
	if err != nil {
		// If no roles/permissions found, create empty permissions
		userPermissions = &models.UserPermissions{
			UserID:      user.ID,
			Roles:       []string{},
			Permissions: []string{},
			Scopes:      []string{},
		}
	}

	// Generate tokens
	tokens, err := s.jwtService.GenerateTokenPair(user, userPermissions)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Store refresh token
	expiresAt := time.Now().Add(s.cfg.RefreshTokenExpiry)
	if err := s.tokenRepo.CreateRefreshToken(user.ID, tokens.RefreshToken, expiresAt); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &AuthResponse{
		User:   user.ToResponse(),
		Tokens: tokens,
	}, nil
}

// Login authenticates a user and returns tokens
func (s *AuthService) Login(req *LoginRequest) (*AuthResponse, error) {
	// Find user by email
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, fmt.Errorf("account is inactive")
	}

	// Verify password
	if err := s.verifyPassword(req.Password, user.Password); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	if err := s.userRepo.Update(user); err != nil {
		// Log error but don't fail the login
		fmt.Printf("Warning: failed to update last login time: %v\n", err)
	}

	// Get user permissions
	userPermissions, err := s.userRepo.GetUserPermissions(user.ID)
	if err != nil {
		userPermissions = &models.UserPermissions{
			UserID:      user.ID,
			Roles:       []string{},
			Permissions: []string{},
			Scopes:      []string{},
		}
	}

	// Generate tokens
	tokens, err := s.jwtService.GenerateTokenPair(user, userPermissions)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Store refresh token
	expiresAt := time.Now().Add(s.cfg.RefreshTokenExpiry)
	if err := s.tokenRepo.CreateRefreshToken(user.ID, tokens.RefreshToken, expiresAt); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &AuthResponse{
		User:   user.ToResponse(),
		Tokens: tokens,
	}, nil
}

// RefreshToken generates new tokens using refresh token
func (s *AuthService) RefreshToken(refreshToken string) (*TokenPair, error) {
	// Validate refresh token in database
	tokenRecord, err := s.tokenRepo.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Get user
	user, err := s.userRepo.GetByID(tokenRecord.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	if !user.IsActive {
		return nil, fmt.Errorf("account is inactive")
	}

	// Get user permissions
	userPermissions, err := s.userRepo.GetUserPermissions(user.ID)
	if err != nil {
		userPermissions = &models.UserPermissions{
			UserID:      user.ID,
			Roles:       []string{},
			Permissions: []string{},
			Scopes:      []string{},
		}
	}

	// Generate new tokens
	newTokens, err := s.jwtService.GenerateTokenPair(user, userPermissions)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new tokens: %w", err)
	}

	// Rotate refresh token (revoke old, create new)
	expiresAt := time.Now().Add(s.cfg.RefreshTokenExpiry)
	if err := s.tokenRepo.RotateRefreshToken(refreshToken, newTokens.RefreshToken, user.ID, expiresAt); err != nil {
		return nil, fmt.Errorf("failed to rotate refresh token: %w", err)
	}

	return newTokens, nil
}

// Logout revokes the user's refresh tokens
func (s *AuthService) Logout(userID uint, refreshToken string) error {
	// Revoke specific refresh token if provided
	if refreshToken != "" {
		if err := s.tokenRepo.RevokeRefreshToken(refreshToken); err != nil {
			return fmt.Errorf("failed to revoke refresh token: %w", err)
		}
	} else {
		// Revoke all user tokens if no specific token provided
		if err := s.tokenRepo.RevokeAllUserTokens(userID); err != nil {
			return fmt.Errorf("failed to revoke user tokens: %w", err)
		}
	}

	return nil
}

// ValidateAccessToken validates an access token
func (s *AuthService) ValidateAccessToken(token string) (*Claims, error) {
	return s.jwtService.ValidateAccessToken(token)
}

// hashPassword creates a bcrypt hash of the password
func (s *AuthService) hashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

// verifyPassword compares a password with its hash
func (s *AuthService) verifyPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// SetOAuthService sets the OAuth service (used to avoid circular dependency)
func (s *AuthService) SetOAuthService(oauthService *OAuthService) {
	s.OAuthService = oauthService
}

// generateTokensForUser generates JWT tokens for a user (used by OAuth service)
func (s *AuthService) generateTokensForUser(user *models.User) (*models.AuthTokens, error) {
	// Get user permissions
	permissions, err := s.userRepo.GetUserPermissions(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	// Generate access token
	accessToken, _, err := s.jwtService.GenerateAccessToken(user, permissions)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := s.jwtService.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token in database
	expiresAt := time.Now().Add(s.cfg.RefreshTokenExpiry)
	if err := s.tokenRepo.CreateRefreshToken(user.ID, refreshToken, expiresAt); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &models.AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.cfg.JWTExpiry.Seconds()),
	}, nil
}