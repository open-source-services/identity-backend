package database

import (
	"log"

	"gorm.io/gorm"
	"github.com/sharan-industries/identity-service/internal/models"
)

// SeedDatabase creates default roles and permissions
func SeedDatabase(db *gorm.DB) error {
	log.Println("Seeding database with default roles and permissions...")

	// Create default permissions
	permissions := []models.Permission{
		{Name: "users:read", Resource: "users", Action: "read", Description: "Read user profiles"},
		{Name: "users:write", Resource: "users", Action: "write", Description: "Update user profiles"},
		{Name: "users:delete", Resource: "users", Action: "delete", Description: "Delete user accounts"},
		{Name: "users:admin", Resource: "users", Action: "admin", Description: "Admin user management"},
		
		{Name: "products:read", Resource: "products", Action: "read", Description: "Read product information"},
		{Name: "products:write", Resource: "products", Action: "write", Description: "Create and update products"},
		{Name: "products:delete", Resource: "products", Action: "delete", Description: "Delete products"},
		{Name: "products:admin", Resource: "products", Action: "admin", Description: "Admin product management"},
		
		{Name: "orders:read", Resource: "orders", Action: "read", Description: "Read order information"},
		{Name: "orders:write", Resource: "orders", Action: "write", Description: "Create and update orders"},
		{Name: "orders:admin", Resource: "orders", Action: "admin", Description: "Admin order management"},
	}

	for _, permission := range permissions {
		var existingPermission models.Permission
		if err := db.Where("name = ?", permission.Name).First(&existingPermission).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				if err := db.Create(&permission).Error; err != nil {
					log.Printf("Warning: Failed to create permission %s: %v", permission.Name, err)
				} else {
					log.Printf("Created permission: %s", permission.Name)
				}
			}
		}
	}

	// Create default roles
	roles := []struct {
		Name        string
		Description string
		Permissions []string
	}{
		{
			Name:        "user",
			Description: "Standard user with basic permissions",
			Permissions: []string{"users:read", "products:read", "orders:read"},
		},
		{
			Name:        "moderator", 
			Description: "Moderator with extended permissions",
			Permissions: []string{"users:read", "users:write", "products:read", "products:write", "orders:read", "orders:write"},
		},
		{
			Name:        "admin",
			Description: "Administrator with full permissions",
			Permissions: []string{"users:read", "users:write", "users:delete", "users:admin", "products:read", "products:write", "products:delete", "products:admin", "orders:read", "orders:write", "orders:admin"},
		},
	}

	for _, roleData := range roles {
		var existingRole models.Role
		if err := db.Where("name = ?", roleData.Name).First(&existingRole).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				// Create the role
				role := models.Role{
					Name:        roleData.Name,
					Description: roleData.Description,
					IsActive:    true,
				}

				if err := db.Create(&role).Error; err != nil {
					log.Printf("Warning: Failed to create role %s: %v", roleData.Name, err)
					continue
				}

				log.Printf("Created role: %s", roleData.Name)

				// Assign permissions to role
				for _, permissionName := range roleData.Permissions {
					var permission models.Permission
					if err := db.Where("name = ?", permissionName).First(&permission).Error; err == nil {
						rolePermission := models.RolePermission{
							RoleID:       role.ID,
							PermissionID: permission.ID,
						}
						if err := db.Create(&rolePermission).Error; err != nil {
							log.Printf("Warning: Failed to assign permission %s to role %s: %v", permissionName, roleData.Name, err)
						}
					}
				}
			}
		}
	}

	log.Println("Database seeding completed successfully")
	return nil
}

// AssignDefaultRole assigns the default "user" role to a user
func AssignDefaultRole(db *gorm.DB, userID uint) error {
	// Find the default "user" role
	var userRole models.Role
	if err := db.Where("name = ?", "user").First(&userRole).Error; err != nil {
		return err
	}

	// Check if user already has this role
	var existingUserRole models.UserRole
	if err := db.Where("user_id = ? AND role_id = ?", userID, userRole.ID).First(&existingUserRole).Error; err == nil {
		// Role already assigned
		return nil
	}

	// Assign the role
	newUserRole := models.UserRole{
		UserID:   userID,
		RoleID:   userRole.ID,
		IsActive: true,
	}

	return db.Create(&newUserRole).Error
}