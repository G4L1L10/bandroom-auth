package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the authentication system
type User struct {
	ID                 uuid.UUID `json:"id"`                      // Unique User ID (UUID)
	Email              string    `json:"email"`                   // User Email (Unique)
	PasswordHash       string    `json:"password_hash"`           // Hashed Password
	Role               string    `json:"role"`                    // User role ('user' or 'admin')
	RefreshToken       *string   `json:"refresh_token,omitempty"` // Stores latest refresh token (nullable)
	LastPasswordChange time.Time `json:"last_password_change"`    // Track last password update
	CreatedAt          time.Time `json:"created_at"`              // Timestamp when the user was created
	UpdatedAt          time.Time `json:"updated_at"`              // Timestamp when the user was last updated
}

// NewUser creates a new user instance with a generated UUID and timestamps
func NewUser(email, hashedPassword, role string) *User {
	currentTime := time.Now()
	return &User{
		ID:                 uuid.New(),
		Email:              email,
		PasswordHash:       hashedPassword,
		Role:               role,
		RefreshToken:       nil, // Nullable field
		LastPasswordChange: currentTime,
		CreatedAt:          currentTime,
		UpdatedAt:          currentTime,
	}
}

// UpdateUser updates user details and refreshes the updatedAt timestamp
func (u *User) UpdateUser(email, hashedPassword, role string) {
	u.Email = email
	u.PasswordHash = hashedPassword
	u.Role = role
	u.UpdatedAt = time.Now() // Update timestamp
}

// UpdateRefreshToken updates the refresh token for the user
func (u *User) UpdateRefreshToken(refreshToken *string) {
	u.RefreshToken = refreshToken
	u.UpdatedAt = time.Now() // Track token change
}
