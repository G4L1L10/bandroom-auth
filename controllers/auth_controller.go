package controllers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/g4l1l10/bandroom/authentication/middlewares"
	"github.com/g4l1l10/bandroom/authentication/models"
	"github.com/g4l1l10/bandroom/authentication/repository"
	"github.com/g4l1l10/bandroom/authentication/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AuthValidate verifies the JWT token
func AuthValidate(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := utils.ValidateToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Token is valid", "user_id": claims.UserID})
}

// Register creates a new user account
func Register(c *gin.Context) {
	var input struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	input.Email = strings.ToLower(input.Email)

	if err := utils.ValidatePassword(input.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user := &models.User{
		ID:                 uuid.New(),
		Email:              input.Email,
		PasswordHash:       hashedPassword,
		Role:               "user",
		RefreshToken:       nil,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		LastPasswordChange: time.Now(),
	}

	if err := repository.CreateUser(user); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User already exists or database error"})
		return
	}

	// ✅ Generate access token
	accessToken, err := utils.GenerateAccessToken(user.ID, user.Email, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	// ✅ Generate refresh token
	refreshToken, err := utils.GenerateRefreshToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	err = repository.UpdateRefreshToken(user.ID, refreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store refresh token"})
		return
	}

	// ✅ Set refresh_token cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,            // set true in prod
		MaxAge:   60 * 60 * 24 * 7, // 7 days
	})

	// ✅ Return access token like in Login
	c.JSON(http.StatusCreated, gin.H{
		"message":      "User registered successfully",
		"access_token": accessToken,
	})
}

// Login authenticates a user and issues access + refresh tokens
func Login(c *gin.Context) {
	var input struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	input.Email = strings.ToLower(input.Email)
	ip := c.ClientIP()

	user, err := repository.VerifyCredentials(input.Email, input.Password)
	if err != nil {
		middlewares.TrackFailedLogin(ip)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	accessToken, err := utils.GenerateAccessToken(user.ID, user.Email, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	refreshToken, err := utils.GenerateRefreshToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	err = repository.UpdateRefreshToken(user.ID, refreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store refresh token"})
		return
	}

	middlewares.ResetFailedLogin(ip)

	// ✅ Set refresh_token as HttpOnly cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,            // Set true in production with HTTPS
		MaxAge:   60 * 60 * 24 * 7, // 7 days
	})

	c.JSON(http.StatusOK, gin.H{
		"message":      "Login successful",
		"access_token": accessToken,
	})
}

// RefreshToken issues a new access token using the refresh token cookie
func RefreshToken(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token missing or invalid"})
		return
	}

	claims, err := utils.ValidateToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		return
	}

	user, err := repository.GetUserByID(claims.UserID)
	if err != nil || user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	if user.RefreshToken == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No refresh token stored"})
		return
	}

	decryptedToken, err := utils.DecryptRefreshToken(*user.RefreshToken)
	if err != nil || decryptedToken != refreshToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token does not match"})
		return
	}

	newAccessToken, err := utils.GenerateAccessToken(user.ID, user.Email, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate access token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access_token": newAccessToken})
}

// Logout clears refresh token from DB and cookie
func Logout(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		// 🔍 DEBUG: dump all received cookies
		allCookies := []string{}
		for _, cookie := range c.Request.Cookies() {
			allCookies = append(allCookies, fmt.Sprintf("%s=%s", cookie.Name, cookie.Value))
		}
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":            "Refresh token missing",
			"availableCookies": allCookies,
		})
		return
	}

	claims, err := utils.ValidateToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}

	storedToken, err := repository.GetRefreshToken(claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch refresh token"})
		return
	}

	if storedToken == "" || storedToken != refreshToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired session"})
		return
	}

	err = repository.UpdateRefreshToken(claims.UserID, "")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		return
	}

	// ✅ Clear refresh_token cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
		MaxAge:   -1, // Expire immediately
	})

	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

// GetUser returns current authenticated user
func GetUser(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse user ID"})
		return
	}

	user, err := repository.GetUserByID(userUUID)
	if err != nil || user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"id": user.ID, "email": user.Email})
}
