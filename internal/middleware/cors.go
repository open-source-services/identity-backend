package middleware

import (
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/sharan-industries/identity-service/internal/config"
)

// CORS returns a CORS middleware with appropriate configuration
func CORS(cfg *config.Config) gin.HandlerFunc {
	corsConfig := cors.Config{
		AllowOrigins: getAllowedOrigins(cfg),
		AllowMethods: []string{
			"GET",
			"POST",
			"PUT",
			"PATCH",
			"DELETE",
			"HEAD",
			"OPTIONS",
		},
		AllowHeaders: []string{
			"Origin",
			"Content-Length",
			"Content-Type",
			"Authorization",
			"X-Requested-With",
			"Accept",
			"Accept-Encoding",
			"Accept-Language",
			"Connection",
			"Host",
			"Referer",
			"User-Agent",
		},
		ExposeHeaders: []string{
			"Content-Length",
			"Content-Type",
			"Authorization",
		},
		AllowCredentials: true,
		MaxAge:          12 * time.Hour,
	}

	return cors.New(corsConfig)
}

// getAllowedOrigins gets CORS allowed origins from configuration
func getAllowedOrigins(cfg *config.Config) []string {
	// Start with development origins
	origins := []string{
		"http://localhost:3000",
		"http://localhost:3001", 
		"http://localhost:3002",
		"http://localhost:8080",
		"http://127.0.0.1:3000",
		"http://127.0.0.1:3001",
		"http://127.0.0.1:8080",
	}

	// Add configured origins (for production subdomains)
	if len(cfg.AllowedOrigins) > 0 {
		origins = append(origins, cfg.AllowedOrigins...)
	}

	// Add legacy environment variable support
	customOrigins := getEnvSlice("CORS_ALLOWED_ORIGINS")
	if len(customOrigins) > 0 {
		for _, origin := range customOrigins {
			if strings.TrimSpace(origin) != "" {
				origins = append(origins, strings.TrimSpace(origin))
			}
		}
	}

	return origins
}

// getEnvSlice parses comma-separated environment variable into slice
func getEnvSlice(key string) []string {
	// This is a simplified version - in real implementation,
	// you'd use your config package
	envValue := os.Getenv(key)
	if envValue == "" {
		return []string{}
	}
	return strings.Split(envValue, ",")
}