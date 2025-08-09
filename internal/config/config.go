package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Server config
	Port        string
	Environment string

	// JWT config
	JWTSecret          string
	JWTExpiry          time.Duration
	RefreshTokenExpiry time.Duration

	// Database config
	DatabaseURL string

	// OAuth config
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string

	GitHubClientID     string
	GitHubClientSecret string
	GitHubRedirectURL  string

	MicrosoftClientID     string
	MicrosoftClientSecret string
	MicrosoftRedirectURL  string

	// CORS config
	CORSAllowedOrigins []string

	// Rate limiting config
	RateLimitRequestsPerMinute int

	// Cross-domain config
	CookieDomain   string
	AllowedOrigins []string
}

func Load() *Config {
	return &Config{
		Port:        getEnv("PORT", "8080"),
		Environment: getEnv("ENVIRONMENT", "development"),

		JWTSecret:          getEnv("JWT_SECRET", "default-secret-change-me"),
		JWTExpiry:          parseDuration(getEnv("JWT_EXPIRY", "1h")),
		RefreshTokenExpiry: parseDuration(getEnv("REFRESH_TOKEN_EXPIRY", "168h")), // 7 days

		DatabaseURL: getEnv("DATABASE_URL", "postgres://username:password@localhost:5432/identity_service?sslmode=disable"),

		GoogleClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirectURL:  getEnv("GOOGLE_REDIRECT_URL", ""),

		GitHubClientID:     getEnv("GITHUB_CLIENT_ID", ""),
		GitHubClientSecret: getEnv("GITHUB_CLIENT_SECRET", ""),
		GitHubRedirectURL:  getEnv("GITHUB_REDIRECT_URL", ""),

		MicrosoftClientID:     getEnv("MICROSOFT_CLIENT_ID", ""),
		MicrosoftClientSecret: getEnv("MICROSOFT_CLIENT_SECRET", ""),
		MicrosoftRedirectURL:  getEnv("MICROSOFT_REDIRECT_URL", ""),

		RateLimitRequestsPerMinute: parseIntWithDefault(getEnv("RATE_LIMIT_REQUESTS_PER_MINUTE", "60"), 60),

		CookieDomain:   getEnv("COOKIE_DOMAIN", ""),
		AllowedOrigins: parseOrigins(getEnv("ALLOWED_ORIGINS", "")),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseDuration(s string) time.Duration {
	duration, err := time.ParseDuration(s)
	if err != nil {
		return time.Hour // default to 1 hour
	}
	return duration
}

func parseIntWithDefault(s string, defaultValue int) int {
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}
	return defaultValue
}

func parseOrigins(s string) []string {
	if s == "" {
		return []string{}
	}
	origins := strings.Split(s, ",")
	result := make([]string, 0, len(origins))
	for _, origin := range origins {
		if trimmed := strings.TrimSpace(origin); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
