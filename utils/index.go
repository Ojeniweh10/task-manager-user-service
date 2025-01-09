package utils

import (
	"errors"
	"log"
	"net/mail"
	"strconv"
	_ "time/tzdata"

	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/ojeniweh10/task-manager-user-service/config"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte(config.SecretKey)

type TokenClaims struct {
	Email  string `json:"email"`
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

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

func ValidateToken(tokenStr string) (string, int64, error) {
	// Parse the token
	token, err := jwt.ParseWithClaims(tokenStr, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is correct
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil {
		return "", 0, err
	}

	// Extract the claims
	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		// Check expiration
		if claims.ExpiresAt.Before(time.Now()) {
			return "", 0, errors.New("token has expired")
		}

		// Convert user ID from string to int64, if it's not already in the correct format
		userID, err := strconv.ParseInt(claims.UserID, 10, 64)
		if err != nil {
			return "", 0, errors.New("invalid user id in token")
		}

		// Return the email and user ID from the token claims
		return claims.Email, userID, nil
	}

	return "", 0, errors.New("invalid token")
}
