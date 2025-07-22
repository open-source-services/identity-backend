package models

import (
	"time"
	"gorm.io/gorm"
)

// Role represents a user role with permissions
type Role struct {
	ID          uint   `json:"id" gorm:"primaryKey"`
	Name        string `json:"name" gorm:"uniqueIndex;not null"` // admin, user, moderator, etc.
	Description string `json:"description"`
	IsActive    bool   `json:"is_active" gorm:"default:true"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	Permissions []Permission `json:"permissions,omitempty" gorm:"many2many:role_permissions;"`
	Users       []User       `json:"-" gorm:"many2many:user_roles;"`
}

// Permission represents a specific permission/scope
type Permission struct {
	ID          uint   `json:"id" gorm:"primaryKey"`
	Name        string `json:"name" gorm:"uniqueIndex;not null"` // users:read, products:write, etc.
	Resource    string `json:"resource" gorm:"not null"`         // users, products, orders
	Action      string `json:"action" gorm:"not null"`           // read, write, delete, admin
	Description string `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// Relationships
	Roles []Role `json:"-" gorm:"many2many:role_permissions;"`
}

// UserRole represents the many-to-many relationship between users and roles
type UserRole struct {
	UserID    uint      `json:"user_id" gorm:"primaryKey"`
	RoleID    uint      `json:"role_id" gorm:"primaryKey"`
	GrantedAt time.Time `json:"granted_at" gorm:"default:CURRENT_TIMESTAMP"`
	GrantedBy uint      `json:"granted_by"` // User ID who granted this role
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // Optional expiration
	IsActive  bool      `json:"is_active" gorm:"default:true"`

	// Foreign keys
	User Role `json:"-" gorm:"foreignKey:UserID"`
	Role Role `json:"-" gorm:"foreignKey:RoleID"`
}

// TableName specifies the table name for UserRole
func (UserRole) TableName() string {
	return "user_roles"
}

// RolePermission represents the many-to-many relationship between roles and permissions
type RolePermission struct {
	RoleID       uint `json:"role_id" gorm:"primaryKey"`
	PermissionID uint `json:"permission_id" gorm:"primaryKey"`

	// Foreign keys
	Role       Role       `json:"-" gorm:"foreignKey:RoleID"`
	Permission Permission `json:"-" gorm:"foreignKey:PermissionID"`
}

// TableName specifies the table name for RolePermission
func (RolePermission) TableName() string {
	return "role_permissions"
}

// UserPermissions represents the computed permissions for a user
type UserPermissions struct {
	UserID      uint     `json:"user_id"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	Scopes      []string `json:"scopes"` // JWT scopes format
}

// HasPermission checks if user has a specific permission
func (up *UserPermissions) HasPermission(permission string) bool {
	for _, p := range up.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasRole checks if user has a specific role
func (up *UserPermissions) HasRole(role string) bool {
	for _, r := range up.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasScope checks if user has a specific scope
func (up *UserPermissions) HasScope(scope string) bool {
	for _, s := range up.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// GetScopes returns permission names in OAuth scope format
func (up *UserPermissions) GetScopes() []string {
	return up.Scopes
}