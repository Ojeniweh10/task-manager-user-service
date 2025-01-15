package utils

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/mail"
	_ "time/tzdata"

	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/gomail.v2"

	"github.com/golang-jwt/jwt/v4"
	"github.com/ojeniweh10/task-manager-user-service/config"
	"github.com/ojeniweh10/task-manager-user-service/database"
	"github.com/ojeniweh10/task-manager-user-service/models"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
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

func CapitilizeName(name string) string {
	return cases.Title(language.Und).String(strings.TrimSpace(name))
}

func IsName(name string) bool {
	pattern := "^[a-zA-Z]+([-']?[a-zA-Z]+)*( [a-zA-Z]+([-']?[a-zA-Z]+)*){0,1}$"
	return regexp.MustCompile(pattern).MatchString(strings.TrimSpace(name)) && len(name) >= 3
}

func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func HashPassword(password string) string {
	// Set the bcrypt cost factor (14 is a reasonable default)
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Println("Error hashing password:", err)
		panic(err)
	}
	return string(bytes)

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
		userID := claims.UserID

		// Return the email and user ID from the token claims
		return claims.Email, userID, nil
	}

	return "", 0, errors.New("invalid token")
}

func GenerateUsertag(firstname string) string {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomNumber := rng.Intn(999999-100000+1) + 100000
	Usertag := firstname[:3]
	Usertag = strings.ToUpper(Usertag)
	return Usertag + strconv.Itoa(randomNumber)
}

func FindUserByUsertag(usertag string) (*models.User, error) {
	db := database.NewConnection()
	defer db.Close()
	query := `
		SELECT usertag, email, password, first_name, last_name, created_at, updated_at 
		FROM users 
		WHERE usertag = ?
	`
	var user models.User
	err := db.QueryRow(query, usertag).Scan(
		&user.Usertag,
		&user.Email,
		&user.Password,
		&user.FirstName,
		&user.LastName,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			// Return nil if no user is found
			return nil, nil
		}
		return nil, fmt.Errorf("error querying user by usertag: %w", err)
	}
	return &user, nil
}

func FindUserByEmail(email string) (*models.User, error) {
	db := database.NewConnection()
	query := "SELECT usertag, email, password FROM users WHERE LOWER(email) = LOWER(?)"
	var user models.User
	err := db.QueryRow(query, email).Scan(&user.Usertag, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// find a user by their ID
func FindUserByTag(usertag string) (*models.User, error) {
	db := database.NewConnection()
	query := "SELECT usertag, email, password FROM users WHERE LOWER(usertag) = LOWER(?)"
	var user models.User
	err := db.QueryRow(query, usertag).Scan(&user.Usertag, &user.Email, &user.Password)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

func GenerateResetToken(email string) (string, error) {
	expiration := time.Now().Add(1 * time.Hour).Unix()
	claims := jwt.MapClaims{
		"email": email,
		"exp":   expiration,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// Validates a reset token
func ValidateResetToken(token string) (string, error) {
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !parsedToken.Valid {
		return "", errors.New("invalid or expired reset token")
	}
	claims := parsedToken.Claims.(jwt.MapClaims)
	email := claims["email"].(string)
	return email, nil
}

func SendResetEmail(email string, token string) error {
	resetURL := fmt.Sprintf("http://localhost:8081/reset-password?token=%s", token)

	// Email content
	subject := "Password Reset Request"
	body := fmt.Sprintf("To reset your password, click the link below:\n\n%s\n\nIf you did not request this, please ignore this email.", resetURL)

	// SMTP configuration
	mailer := gomail.NewMessage()
	mailer.SetHeader("From", config.AppEmail)
	mailer.SetHeader("To", email)
	mailer.SetHeader("Subject", subject)
	mailer.SetBody("text/plain", body)

	// SMTP server configuration
	dialer := gomail.NewDialer("smtp.gmail.com", 587, config.AppEmail, config.AppPassword)

	// Send the email
	if err := dialer.DialAndSend(mailer); err != nil {
		fmt.Printf("Failed to send email to %s: %v\n", email, err)
		return err
	}
	fmt.Printf("Password reset email sent to %s\n", email)
	return nil
}

func UpdateUserPassword(email string, hashedPassword string) error {
	db := database.NewConnection()
	query := "UPDATE users SET password = LOWER(?), updated_at = LOWER(?) WHERE email = LOWER(?)"
	_, err := db.Exec(query, hashedPassword, time.Now(), email)
	return err
}

func HashPwd(password string) (string, error) {
	// bcrypt.DefaultCost is typically 10, which balances security and performance
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
