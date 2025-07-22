package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/sharan-industries/identity-service/internal/config"
	"github.com/sharan-industries/identity-service/internal/handlers"
	"github.com/sharan-industries/identity-service/internal/middleware"
	"github.com/sharan-industries/identity-service/internal/repository"
	"github.com/sharan-industries/identity-service/internal/services"
	"github.com/sharan-industries/identity-service/pkg/database"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Load configuration
	cfg := config.Load()

	// Initialize database
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Auto-migrate database tables
	if err := database.Migrate(db); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// Seed database with default roles and permissions
	if err := database.SeedDatabase(db); err != nil {
		log.Printf("Warning: Failed to seed database: %v", err)
	}

	// Set Gin mode
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize Gin router
	r := gin.Default()

	// Configure trusted proxies for production security
	if cfg.Environment == "production" {
		// In production, specify trusted proxy IPs (load balancers, reverse proxies)
		// Example: r.SetTrustedProxies([]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"})
		// For now, disable proxy trust for maximum security
		r.SetTrustedProxies(nil)
	} else {
		// In development, trust localhost
		r.SetTrustedProxies([]string{"127.0.0.1", "::1"})
	}

	// Setup middleware
	r.Use(middleware.CORS(cfg))
	r.Use(middleware.RateLimit())

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(db)

	// Initialize services
	jwtService := services.NewJWTService(cfg)
	authService := services.NewAuthService(cfg, userRepo, tokenRepo, jwtService)
	oauthService := services.NewOAuthService(cfg, userRepo, authService)
	authService.SetOAuthService(oauthService)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService)
	userHandler := handlers.NewUserHandler(db, cfg)
	validateHandler := handlers.NewValidateHandler(jwtService)

	// Setup routes
	setupRoutes(r, authHandler, userHandler, validateHandler, jwtService)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func setupRoutes(r *gin.Engine, authHandler *handlers.AuthHandler, userHandler *handlers.UserHandler, validateHandler *handlers.ValidateHandler, jwtService *services.JWTService) {
	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy"})
	})

	// API v1 routes
	v1 := r.Group("/api/v1")
	{
		// Public auth routes
		auth := v1.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/refresh", authHandler.RefreshToken)
			auth.POST("/validate", validateHandler.ValidateToken) // For other services
			
			// OAuth routes
			oauth := auth.Group("/oauth")
			{
				oauth.GET("/google", authHandler.GoogleOAuth)
				oauth.GET("/google/callback", authHandler.GoogleCallback)
				oauth.GET("/github", authHandler.GitHubOAuth)
				oauth.GET("/github/callback", authHandler.GitHubCallback)
				oauth.GET("/microsoft", authHandler.MicrosoftOAuth)
				oauth.GET("/microsoft/callback", authHandler.MicrosoftCallback)
			}
		}

		// Protected user routes
		users := v1.Group("/users")
		users.Use(middleware.AuthRequired(jwtService))
		{
			users.GET("/profile", userHandler.GetProfile)
			users.PUT("/profile", userHandler.UpdateProfile)
			users.DELETE("/account", userHandler.DeleteAccount)
		}

		// Protected auth routes (require authentication)
		protectedAuth := v1.Group("/auth")
		protectedAuth.Use(middleware.AuthRequired(jwtService))
		{
			protectedAuth.POST("/logout", authHandler.Logout)
		}
	}
}