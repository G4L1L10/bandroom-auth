package utils

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes a plaintext password using bcrypt.
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// ComparePassword compares a hashed password with a plaintext password.
func ComparePassword(hashedPassword, password string) bool {
	fmt.Println("🔍 Debug: Comparing", password, "with", hashedPassword)
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		fmt.Println("❌ Debug: bcrypt comparison failed:", err)
		return false
	}
	fmt.Println("✅ Debug: bcrypt comparison successful!")
	return true
}
