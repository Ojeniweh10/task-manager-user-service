package servers

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/ojeniweh10/task-manager-user-service/config"
	"github.com/ojeniweh10/task-manager-user-service/database"
	"github.com/ojeniweh10/task-manager-user-service/models"
	"github.com/ojeniweh10/task-manager-user-service/responses"
	"github.com/ojeniweh10/task-manager-user-service/utils"
)

var jwtSecret = []byte(config.SecretKey)
var db = database.NewConnection()

type UserServer struct{}

// SetUser handles the business logic of registering a new user
func (UserServer) SetUser(data models.RegisterUser) (*models.User, error) {
	var emailExist bool
	query := "SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)"
	err := db.QueryRow(query, data.Email).Scan(&emailExist)

	if err != nil {
		return nil, fmt.Errorf("error checking email existence: %v", err)
	}

	if emailExist {
		return nil, errors.New(responses.EMAIL_EXIST)
	}

	hashedPassword := utils.HashPassword(data.Password)
	var usertag string
	for {
		usertag = utils.GenerateUsertag(data.FirstName)
		// Check if the generated usertag already exists in the database
		existingUsertag, _ := utils.FindUserByUsertag(usertag)
		if existingUsertag == nil {
			break
		}
	}

	// Create the user object
	user := models.User{
		Usertag:   usertag,
		Email:     data.Email,
		FirstName: data.FirstName,
		LastName:  data.LastName,
		Password:  hashedPassword,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	insertQuery := `
		INSERT INTO users (usertag, email, password, first_name, last_name, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	db := database.NewConnection()
	defer db.Close()
	_, err = db.Exec(insertQuery, user.Usertag, user.Email, user.Password, user.FirstName, user.LastName, user.CreatedAt, user.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("error inserting user into database: %v", err)
	}
	return &user, nil
}

func (UserServer) AuthenticateUser(data models.LoginUser) (string, *models.User, error) {
	// Find the user by email
	existingUser, err := utils.FindUserByEmail(data.Email)
	if err != nil {
		return "", nil, fmt.Errorf("error checking existing user: %v", err)
	}

	if existingUser == nil {
		return "", nil, errors.New("user does not exist")
	}

	// Verify the provided password with the stored hash
	if err := utils.CheckPassword(data.Password, existingUser.Password); err != nil {
		return "", nil, errors.New("invalid credentials")
	}

	// Generate a JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"usertag": existingUser.Usertag,
		"email":   existingUser.Email,
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(1 * time.Hour).Unix(), // Token expires in 1 hour
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", nil, fmt.Errorf("error generating token: %v", err)
	}

	return tokenString, &models.User{
		Usertag: existingUser.Usertag,
		Email:   existingUser.Email,
	}, nil
}

func (UserServer) UpdatePassword(data models.ChangePasswordReq) error {
	var password string
	data.Usertag = strings.TrimSpace(data.Usertag)
	err := db.QueryRow("SELECT password FROM users WHERE LOWER(usertag) = LOWER(?)", data.Usertag).Scan(&password)
	if err == sql.ErrNoRows {
		fmt.Printf("No user found for usertag: %s\n", data.Usertag)
		return errors.New(responses.SOMETHING_WRONG)
	}
	passwordCheck := utils.VerifyPassword(data.Old_password, password)
	if !passwordCheck {
		return errors.New(responses.WRONG_PASSWORD)
	} else {
		fmt.Println("password matches")
	}

	if checkPassword(data.Usertag, data.New_password) {
		return errors.New(responses.PASSWORD_REUSE)
	}
	new_password := utils.HashPassword(data.New_password)
	_, err = db.Exec("UPDATE users SET password = ? WHERE usertag = ?", new_password, data.Usertag)
	if err != nil {

		return errors.New(responses.SOMETHING_WRONG)
	} else {
		fmt.Println("password updated")
	}

	return nil
}

func (UserServer) UpdateEmail(data models.ChangeEmail, usertag string) error {
	existingUser, err := utils.FindUserByTag(usertag)
	if err != nil {
		return fmt.Errorf("error checking existing user: %v", err)
	}
	if existingUser == nil {
		return errors.New("user not found")
	}

	if err := utils.CheckPassword(data.Current_password, existingUser.Password); err != nil {
		return errors.New("invalid credentials")
	}

	//Check if the new email is already in use
	newEmailUser, err := utils.FindUserByEmail(data.Email)
	if err != nil {
		return fmt.Errorf("error checking new email: %v", err)
	}
	if newEmailUser != nil {
		return errors.New("email is already in use")
	}

	err = updateEmailInDatabase(usertag, data.Email)
	if err != nil {
		return fmt.Errorf("error updating email in the database: %v", err)
	}

	return nil
}

func updateEmailInDatabase(usertag string, newEmail string) error {
	db := database.NewConnection()
	query := "UPDATE users SET email = ?, updated_at = ? WHERE usertag = ?"
	_, err := db.Exec(query, newEmail, time.Now(), usertag)
	if err != nil {
		return err
	}

	return nil
}

func checkPassword(usertag, password string) bool {
	var old_password string
	rows, err := db.Query("SELECT password FROM users WHERE wisetag = $1", usertag)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&old_password)
		if err != nil {
			return false
		}

		passwordCheck := utils.VerifyPassword(password, old_password)
		if passwordCheck {
			return true
		}
	}
	return false
}
