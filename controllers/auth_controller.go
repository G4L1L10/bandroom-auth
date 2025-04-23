package controllers

import (
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

	// ✅ Hash Password
	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// ✅ Create User Model
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

	// ✅ Insert User into DB
	if err := repository.CreateUser(user); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User already exists or database error"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully", "user_id": user.ID})
}

// Login authenticates a user and issues an access + refresh token
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

	// ✅ Verify credentials and retrieve user
	user, err := repository.VerifyCredentials(input.Email, input.Password)
	if err != nil {
		middlewares.TrackFailedLogin(ip)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// ✅ Generate access and refresh tokens
	accessToken, err := utils.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	refreshToken, err := utils.GenerateRefreshToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	middlewares.ResetFailedLogin(ip)

	// ✅ Store Refresh Token in DB
	err = repository.UpdateRefreshToken(user.ID, refreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store refresh token"})
		return
	}

	// ✅ Store Refresh Token in HttpOnly Cookie
	isSecure := c.Request.TLS != nil // ✅ Detects if HTTPS is used
	//	c.SetCookie("refresh_token", refreshToken, 7*24*60*60, "/", c.Request.Host, isSecure, true)
	c.SetCookie("refresh_token", refreshToken, 7*24*60*60, "/", "localhost", isSecure, true)

	// ✅ Return only the access token (refresh token is in cookies)
	c.JSON(http.StatusOK, gin.H{
		"message":      "Login successful",
		"access_token": accessToken,
	})
}

// RefreshToken generates a new access token using the refresh token
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

	// ✅ Check if refresh token in DB matches
	if user.RefreshToken == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No refresh token stored"})
		return
	}

	decryptedToken, err := utils.DecryptRefreshToken(*user.RefreshToken)
	if err != nil || decryptedToken != refreshToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token does not match"})
		return
	}

	newAccessToken, err := utils.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate access token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access_token": newAccessToken})
}

// Logout invalidates the refresh token properly
func Logout(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token missing or invalid"})
		return
	}

	claims, err := utils.ValidateToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}

	// ✅ Get stored refresh token from database
	storedToken, err := repository.GetRefreshToken(claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch refresh token"})
		return
	}

	// ✅ If there's no stored token, user is already logged out
	if storedToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User already logged out"})
		return
	}

	// ✅ If stored token doesn't match the one in the cookie, reject logout
	if storedToken != refreshToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token does not match"})
		return
	}

	// ✅ Explicitly clear refresh token from DB
	err = repository.UpdateRefreshToken(claims.UserID, "")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		return
	}

	// ✅ Remove refresh token from cookies
	//	c.SetCookie("refresh_token", "", -1, "/", c.Request.Host, false, true)
	c.SetCookie("refresh_token", "", -1, "/", "localhost", false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

// GetUser retrieves the authenticated user's profile
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
