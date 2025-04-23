package services

import (
	"errors"
	"strings"
	"time"

	"github.com/g4l1l10/bandroom/authentication/models"
	"github.com/g4l1l10/bandroom/authentication/repository"
	"github.com/g4l1l10/bandroom/authentication/utils"

	"github.com/google/uuid"
)

// RegisterUser registers a new user.
func RegisterUser(email, password string) (*models.User, error) {
	email = strings.ToLower(email) // Normalize email

	// Check if the user already exists
	existingUser, _ := repository.GetUserByEmail(email)
	if existingUser != nil {
		return nil, errors.New("user already exists")
	}

	// Validate and hash the password
	if err := utils.ValidatePassword(password); err != nil {
		return nil, err
	}
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return nil, err
	}

	// Create new user model
	user := &models.User{
		ID:                 uuid.New(),
		Email:              email,
		PasswordHash:       hashedPassword,
		Role:               "user", // Default role
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		LastPasswordChange: time.Now(),
	}

	// Save user to DB
	if err = repository.CreateUser(user); err != nil {
		return nil, err
	}

	return user, nil
}

// LoginUser authenticates a user and returns an access and refresh token.
func LoginUser(email, password string) (string, string, error) {
	email = strings.ToLower(email) // Normalize email

	user, err := repository.GetUserByEmail(email)
	if err != nil || user == nil {
		return "", "", errors.New("invalid credentials")
	}

	// Compare hashed passwords
	if !utils.ComparePassword(user.PasswordHash, password) {
		return "", "", errors.New("invalid credentials")
	}

	// Generate new access token
	accessToken, err := utils.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		return "", "", err
	}

	// Ensure a refresh token exists
	refreshToken, err := repository.GetRefreshToken(user.ID)
	if err != nil {
		return "", "", err
	}

	if refreshToken == "" {
		// Generate and store new refresh token
		refreshToken, err = utils.GenerateRefreshToken(user.ID)
		if err != nil {
			return "", "", err
		}

		if err = repository.UpdateRefreshToken(user.ID, refreshToken); err != nil {
			return "", "", err
		}
	}

	return accessToken, refreshToken, nil
}

// LogoutUser removes the refresh token from the database, logging the user out.
func LogoutUser(userID uuid.UUID) error {
	return repository.UpdateRefreshToken(userID, "")
}

// RefreshToken generates a new access token using a valid refresh token.
func RefreshToken(userID uuid.UUID, providedRefreshToken string) (string, error) {
	// Retrieve stored refresh token from DB
	storedRefreshToken, err := repository.GetRefreshToken(userID)
	if err != nil {
		return "", errors.New("failed to retrieve stored refresh token")
	}

	// Compare stored and provided refresh tokens
	if storedRefreshToken == "" || storedRefreshToken != providedRefreshToken {
		return "", errors.New("invalid or expired refresh token")
	}

	// Fetch user to get email
	user, err := repository.GetUserByID(userID)
	if err != nil || user == nil {
		return "", errors.New("user not found")
	}

	// Generate new access token WITH email
	newAccessToken, err := utils.GenerateAccessToken(userID, user.Email)
	if err != nil {
		return "", errors.New("failed to generate new access token")
	}

	return newAccessToken, nil
}

// ChangePassword allows a user to update their password securely.
func ChangePassword(userID uuid.UUID, oldPassword, newPassword string) error {
	user, err := repository.GetUserByID(userID)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	// Ensure old password is correct
	if !utils.ComparePassword(user.PasswordHash, oldPassword) {
		return errors.New("incorrect current password")
	}

	// Validate and hash new password
	if err = utils.ValidatePassword(newPassword); err != nil {
		return err
	}
	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Update the password
	if err = repository.UpdatePassword(userID, hashedPassword); err != nil {
		return errors.New("failed to update password")
	}

	return nil
}

// GetUser retrieves user details.
func GetUser(userID uuid.UUID) (*models.User, error) {
	user, err := repository.GetUserByID(userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}
	return user, nil
}
