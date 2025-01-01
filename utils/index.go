package utils

import (
	"log"
	"net/mail"
	_ "time/tzdata"

	"golang.org/x/crypto/bcrypt"
)

func IsEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	check := true

	if err != nil {
		check = false
	}
	return check
}

func HashPassword(password string) (string, error) {
	// Set the bcrypt cost factor (10 is a reasonable default)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error hashing password:", err)
		return "", err
	}

	return string(hashedPassword), nil
}

// CheckPassword compares the entered password with the hashed password
func CheckPassword(plainPassword, hashedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
}
