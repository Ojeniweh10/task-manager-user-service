package servers

import (
	"errors"
	"fmt"
	"time"

	"github.com/ojeniweh10/task-manager-user-service/database"
	"github.com/ojeniweh10/task-manager-user-service/models"
	"github.com/ojeniweh10/task-manager-user-service/utils"
)

type UserServer struct{}

// SetUser handles the business logic of registering a new user
func (UserServer) SetUser(data models.RegisterUser) (*models.User, error) {
	existingUser, err := findUserByEmail(data.Email)
	if err != nil {
		return nil, fmt.Errorf("error checking existing user: %v", err)
	}

	if existingUser != nil {
		return nil, errors.New("user already exists with the given email")
	}
	hashedPassword, err := utils.HashPassword(data.Password)
	if err != nil {
		return nil, fmt.Errorf("error hashing password: %v", err)
	}

	user := models.User{
		Email:     data.Email,
		Password:  hashedPassword,
		Timezone:  data.Timezone,
		CreatedAt: time.Now(),
	}

	// Save the user to the database
	userId, err := saveUserToDatabase(user)
	if err != nil {
		return nil, fmt.Errorf("error saving user to the database: %v", err)
	}

	// Assign the ID to the user and return the user data
	user.ID = userId
	return &user, nil
}

// findUserByEmail checks if a user exists in the database by their email
func findUserByEmail(email string) (*models.User, error) {
	// Query the database for an existing user
	db := database.NewConnection()
	query := "SELECT id, email, password, created_at FROM users WHERE email = ?"
	var user models.User
	err := db.QueryRow(query, email).Scan(&user.ID, &user.Email, &user.Password, &user.CreatedAt)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, err
	}

	// Return the user data if found
	return &user, nil
}

// saveUserToDatabase inserts a new user into the database
func saveUserToDatabase(user models.User) (int64, error) {
	// Prepare the query to insert a new user
	db := database.NewConnection()
	query := "INSERT INTO users (email, password, created_at) VALUES (?, ?, ?)"

	// Execute the insert statement
	result, err := db.Exec(query, user.Email, user.Password, user.Deviceid, user.Timezone, user.CreatedAt)
	if err != nil {
		return 0, err
	}
	// Retrieve the last inserted ID
	userID, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	return userID, nil
}
