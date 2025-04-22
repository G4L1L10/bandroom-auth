package utils

import (
	"errors"
	"unicode"
)

// List of weak passwords to block
var weakPasswords = map[string]bool{
	"password": true, "password123": true, "123456": true, "123456789": true, "qwerty": true,
	"qwerty123": true, "abc123": true, "letmein": true, "welcome": true, "admin": true,
	"monkey": true, "football": true, "iloveyou": true, "sunshine": true, "123123": true,
	"superman": true, "batman": true, "trustno1": true, "shadow": true, "1234": true,
	"passw0rd": true, "hello123": true, "princess": true, "dragon": true, "ninja": true,
	"1q2w3e4r": true, "zaq1xsw2": true, "qazwsx": true, "qwertyuiop": true, "asdfghjkl": true,
}

// ValidatePassword ensures the password meets security requirements.
func ValidatePassword(password string) error {
	// Convert password to lowercase and check if it's in the weak password list
	if weakPasswords[password] {
		return errors.New("this password is too common. Please choose a stronger password")
	}

	var (
		hasMinLength = len(password) >= 8
		hasUpper     = false
		hasLower     = false
		hasNumber    = false
		hasSpecial   = false
		specialChars = "!@#$%^&*()_+|~-=\\{}[]:;\"'<>,.?/"
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasNumber = true
		case contains(specialChars, char):
			hasSpecial = true
		}
	}

	if !hasMinLength || !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return errors.New("password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character")
	}

	return nil
}

// contains checks if a rune is in a string
func contains(str string, char rune) bool {
	for _, c := range str {
		if c == char {
			return true
		}
	}
	return false
}
