package config

import (
	"net/http"
)

// CookieConfig holds cookie configuration for cross-subdomain support
type CookieConfig struct {
	Domain     string        // .mycompany.com for subdomain sharing
	Path       string        // Usually "/"
	MaxAge     int           // Cookie expiration in seconds
	HTTPOnly   bool          // Prevent XSS access
	Secure     bool          // HTTPS only
	SameSite   http.SameSite // CSRF protection
}

// GetCookieConfig returns cookie configuration based on environment
func (c *Config) GetCookieConfig() CookieConfig {
	domain := getEnv("COOKIE_DOMAIN", "")
	secure := c.Environment == "production"
	
	// For cross-subdomain sharing, domain should be ".mycompany.com"
	// This allows cookies to be shared across all subdomains
	
	return CookieConfig{
		Domain:   domain, // Set to ".mycompany.com" in production
		Path:     "/",
		MaxAge:   int(c.RefreshTokenExpiry.Seconds()),
		HTTPOnly: true, // Prevent JavaScript access
		Secure:   secure, // HTTPS only in production
		SameSite: http.SameSiteStrictMode, // CSRF protection
	}
}

// SetAuthCookie sets authentication cookie with proper cross-subdomain configuration
func SetAuthCookie(w http.ResponseWriter, name, value string, config CookieConfig) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   config.Domain,
		Path:     config.Path,
		MaxAge:   config.MaxAge,
		HttpOnly: config.HTTPOnly,
		Secure:   config.Secure,
		SameSite: config.SameSite,
	}
	
	http.SetCookie(w, cookie)
}

// ClearAuthCookie removes authentication cookie
func ClearAuthCookie(w http.ResponseWriter, name string, config CookieConfig) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		Domain:   config.Domain,
		Path:     config.Path,
		MaxAge:   -1, // Expire immediately
		HttpOnly: config.HTTPOnly,
		Secure:   config.Secure,
		SameSite: config.SameSite,
	}
	
	http.SetCookie(w, cookie)
}