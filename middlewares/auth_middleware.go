package middlewares

import (
	"net/http"
	"strings"

	"github.com/g4l1l10/bandroom/authentication/utils"
	"github.com/gin-gonic/gin"
)

// AuthMiddleware ensures that only authenticated users can access certain routes.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Extract the token (expecting "Bearer <token>")
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate the token
		claims, err := utils.ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		// Store user ID in context for later use
		c.Set("userID", claims.UserID)
		c.Next() // Proceed to the next handler
	}
}
