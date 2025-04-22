package middlewares

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// FailedLoginTracker stores failed login attempts
var FailedLoginTracker sync.Map

// LoginAttempt tracks failed login attempts
type LoginAttempt struct {
	Count     int
	BlockedAt time.Time
}

// RateLimitLogin prevents brute force login attempts
func RateLimitLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP() // Get user IP address

		// Check if this IP has previous failed attempts
		if val, exists := FailedLoginTracker.Load(ip); exists {
			attempt := val.(LoginAttempt)

			// If the user is blocked, deny access
			if time.Since(attempt.BlockedAt) < 1*time.Minute {
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many failed attempts. Please try again in 1 minute."})
				c.Abort()
				return
			}
		}

		// Proceed to login handler
		c.Next()
	}
}

// TrackFailedLogin increases the failed login count
func TrackFailedLogin(ip string) {
	val, exists := FailedLoginTracker.Load(ip)
	if exists {
		attempt := val.(LoginAttempt)
		attempt.Count++

		// Block if too many attempts
		if attempt.Count >= 5 {
			attempt.BlockedAt = time.Now() // Block for 1 minute
		}
		FailedLoginTracker.Store(ip, attempt)
	} else {
		// First failed attempt
		FailedLoginTracker.Store(ip, LoginAttempt{Count: 1, BlockedAt: time.Time{}})
	}
}

// ResetFailedLogin resets the failed attempts on successful login
func ResetFailedLogin(ip string) {
	FailedLoginTracker.Delete(ip)
}
