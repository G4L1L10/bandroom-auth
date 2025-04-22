package repository

import (
	"github.com/g4l1l10/bandroom/authentication/db"
	"github.com/g4l1l10/bandroom/authentication/models"
)

// CreateUser inserts a new user into the database.
func CreateUser(user *models.User) error {
	query := `INSERT INTO users (id, email, password_hash, role, refresh_token, created_at, updated_at, last_password_change) 
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := db.DB.Exec(query, user.ID, user.Email, user.PasswordHash, user.Role, user.RefreshToken, user.CreatedAt, user.UpdatedAt, user.LastPasswordChange)
	return err
}
