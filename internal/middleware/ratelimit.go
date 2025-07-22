package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimiter holds the rate limiters for different IPs
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mutex    sync.RWMutex
	rate     rate.Limit
	burst    int
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(requestsPerMinute int) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     rate.Limit(float64(requestsPerMinute) / 60), // Convert to requests per second
		burst:    requestsPerMinute,
	}
}

// getLimiter returns the rate limiter for the given IP
func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	limiter, exists := rl.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.limiters[ip] = limiter
	}

	return limiter
}

// cleanupLimiters removes old limiters to prevent memory leaks
func (rl *RateLimiter) cleanupLimiters() {
	for {
		time.Sleep(time.Minute * 10)
		rl.mutex.Lock()
		for ip, limiter := range rl.limiters {
			// Remove limiter if it hasn't been used recently
			if limiter.Tokens() == float64(rl.burst) {
				delete(rl.limiters, ip)
			}
		}
		rl.mutex.Unlock()
	}
}

// Global rate limiter instance
var globalRateLimiter = NewRateLimiter(60) // 60 requests per minute default

func init() {
	// Start cleanup goroutine
	go globalRateLimiter.cleanupLimiters()
}

// RateLimit returns a rate limiting middleware
func RateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get client IP
		ip := c.ClientIP()
		
		// Get rate limiter for this IP
		limiter := globalRateLimiter.getLimiter(ip)
		
		// Check if request is allowed
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "too_many_requests",
				"message": "Rate limit exceeded. Please try again later.",
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}