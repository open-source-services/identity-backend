package repository

import (
	"fmt"
	"strings"

	"gorm.io/gorm"
	"github.com/sharan-industries/identity-service/internal/models"
)

// UserRepository handles user database operations
type UserRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{
		db: db,
	}
}

// Create creates a new user
func (r *UserRepository) Create(user *models.User) error {
	if err := r.db.Create(user).Error; err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// GetByID retrieves a user by ID
func (r *UserRepository) GetByID(id uint) (*models.User, error) {
	var user models.User
	if err := r.db.Preload("Roles.Permissions").First(&user, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

// GetByEmail retrieves a user by email
func (r *UserRepository) GetByEmail(email string) (*models.User, error) {
	var user models.User
	if err := r.db.Preload("Roles.Permissions").Where("email = ? AND is_active = ?", email, true).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

// GetByOAuthAccount retrieves a user by OAuth provider and provider user ID
func (r *UserRepository) GetByOAuthAccount(provider, providerUserID string) (*models.User, error) {
	var user models.User
	if err := r.db.Preload("Roles.Permissions").
		Joins("JOIN oauth_accounts ON users.id = oauth_accounts.user_id").
		Where("oauth_accounts.provider = ? AND oauth_accounts.provider_id = ? AND users.is_active = ?", 
			provider, providerUserID, true).
		First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

// Update updates a user
func (r *UserRepository) Update(user *models.User) error {
	if err := r.db.Save(user).Error; err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}

// UpdateProfile updates user profile fields only
func (r *UserRepository) UpdateProfile(userID uint, updates map[string]interface{}) error {
	if err := r.db.Model(&models.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to update user profile: %w", err)
	}
	return nil
}

// Delete soft deletes a user
func (r *UserRepository) Delete(id uint) error {
	if err := r.db.Delete(&models.User{}, id).Error; err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

// EmailExists checks if an email already exists
func (r *UserRepository) EmailExists(email string) (bool, error) {
	var count int64
	if err := r.db.Model(&models.User{}).Where("email = ?", email).Count(&count).Error; err != nil {
		return false, fmt.Errorf("failed to check email existence: %w", err)
	}
	return count > 0, nil
}

// GetUserPermissions retrieves all permissions for a user
func (r *UserRepository) GetUserPermissions(userID uint) (*models.UserPermissions, error) {
	var user models.User
	if err := r.db.Preload("Roles.Permissions").First(&user, userID).Error; err != nil {
		return nil, fmt.Errorf("failed to get user with roles: %w", err)
	}

	permissions := &models.UserPermissions{
		UserID:      userID,
		Roles:       make([]string, 0),
		Permissions: make([]string, 0),
		Scopes:      make([]string, 0),
	}

	// Collect unique roles and permissions
	roleMap := make(map[string]bool)
	permissionMap := make(map[string]bool)

	for _, role := range user.Roles {
		if !roleMap[role.Name] {
			permissions.Roles = append(permissions.Roles, role.Name)
			roleMap[role.Name] = true
		}

		for _, permission := range role.Permissions {
			if !permissionMap[permission.Name] {
				permissions.Permissions = append(permissions.Permissions, permission.Name)
				permissionMap[permission.Name] = true

				// Convert permission to OAuth scope format
				scope := r.permissionToScope(permission)
				permissions.Scopes = append(permissions.Scopes, scope)
			}
		}
	}

	return permissions, nil
}

// AssignRole assigns a role to a user
func (r *UserRepository) AssignRole(userID, roleID uint, grantedBy uint) error {
	userRole := &models.UserRole{
		UserID:    userID,
		RoleID:    roleID,
		GrantedBy: grantedBy,
		IsActive:  true,
	}

	if err := r.db.Create(userRole).Error; err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}
	return nil
}

// RemoveRole removes a role from a user
func (r *UserRepository) RemoveRole(userID, roleID uint) error {
	if err := r.db.Where("user_id = ? AND role_id = ?", userID, roleID).Delete(&models.UserRole{}).Error; err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}
	return nil
}

// CreateOAuthAccount creates an OAuth account linked to a user
func (r *UserRepository) CreateOAuthAccount(oauthAccount *models.OAuthAccount) error {
	if err := r.db.Create(oauthAccount).Error; err != nil {
		return fmt.Errorf("failed to create OAuth account: %w", err)
	}
	return nil
}

// UpdateOAuthAccount updates an OAuth account
func (r *UserRepository) UpdateOAuthAccount(oauthAccount *models.OAuthAccount) error {
	if err := r.db.Save(oauthAccount).Error; err != nil {
		return fmt.Errorf("failed to update OAuth account: %w", err)
	}
	return nil
}

// GetOAuthAccount retrieves an OAuth account
func (r *UserRepository) GetOAuthAccount(provider, providerID string) (*models.OAuthAccount, error) {
	var account models.OAuthAccount
	if err := r.db.Where("provider = ? AND provider_id = ?", provider, providerID).First(&account).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("OAuth account not found")
		}
		return nil, fmt.Errorf("failed to get OAuth account: %w", err)
	}
	return &account, nil
}

// AssignRoleByName assigns a role to a user by role name
func (r *UserRepository) AssignRoleByName(userID uint, roleName string) error {
	// Find the role by name
	var role models.Role
	if err := r.db.Where("name = ?", roleName).First(&role).Error; err != nil {
		return fmt.Errorf("failed to find role '%s': %w", roleName, err)
	}
	
	// Assign the role
	return r.AssignRole(userID, role.ID, userID) // Self-assigned for OAuth registration
}

// permissionToScope converts a permission to OAuth scope format
func (r *UserRepository) permissionToScope(permission models.Permission) string {
	// Convert "users:read" to "users:read" or "products:write" to "products:write"
	if strings.Contains(permission.Name, ":") {
		return permission.Name
	}
	// Convert resource.action to resource:action format
	return fmt.Sprintf("%s:%s", permission.Resource, permission.Action)
}