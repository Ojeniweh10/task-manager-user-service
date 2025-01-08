package utils

import (
	"errors"
	"log"
	"net/mail"
	_ "time/tzdata"

	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/ojeniweh10/task-manager-user-service/config"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte(config.SecretKey)

type TokenClaims struct {
	Email  string `json:"email"`
	UserID int64  `json:"user_id"`
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

// validateToken function validates the token and returns the user's email
func ValidateToken(tokenStr string) (string, error) {
	// Parse the token
	token, err := jwt.ParseWithClaims(tokenStr, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil {
		return "", err
	}
	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		// Check the expiration time
		if claims.ExpiresAt.Before(time.Now()) {
			return "", errors.New("token has expired")
		}

		// Token is valid, return the user's email from the claims
		return claims.Email, nil
	} else {
		return "", errors.New("invalid token")
	}
}
