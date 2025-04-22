package services

import (
	"fmt"
)

// SendResetEmail prints the reset token instead of sending an actual email
func SendResetEmail(email, resetToken string) error {
	resetLink := fmt.Sprintf("http://localhost:3000/reset-password?token=%s", resetToken)

	// Print the reset link in the terminal
	fmt.Println("📧 Password Reset Requested:")
	fmt.Printf("User: %s\nReset Link: %s\n", email, resetLink)

	return nil
}
