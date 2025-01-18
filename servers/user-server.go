package servers

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
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

	// Log the registration action
	err = LogAction(db, user.Usertag, "Registered User", "user", 0, fmt.Sprintf("Email: %s, Name: %s %s", user.Email, user.FirstName, user.LastName))
	if err != nil {
		fmt.Printf("Failed to log registration action: %v\n", err)
	}

	return &user, nil
}

func (UserServer) AuthenticateUser(data models.LoginUser) (string, *models.User, error) {
	// Find the user by email
	existingUser, err := utils.FindUserByEmail(data.Email)
	if err != nil {
		// Log failed login attempt
		err = LogAction(db, "", "Failed Login Attempt", "auth", 0, fmt.Sprintf("Email: %s - Reason: %v", data.Email, err))
		if err != nil {
			fmt.Printf("Failed to log login attempt: %v\n", err)
		}
		return "", nil, fmt.Errorf("error checking existing user: %v", err)
	}

	if existingUser == nil {
		// Log user not found
		err = LogAction(db, "", "Failed Login Attempt", "auth", 0, fmt.Sprintf("Email: %s - Reason: User does not exist", data.Email))
		if err != nil {
			fmt.Printf("Failed to log login attempt: %v\n", err)
		}
		return "", nil, errors.New("user does not exist")
	}

	// Verify the provided password with the stored hash
	if err := utils.CheckPassword(data.Password, existingUser.Password); err != nil {
		// Log failed password verification
		err = LogAction(db, existingUser.Usertag, "Failed Login Attempt", "auth", 0, fmt.Sprintf("Email: %s - Reason: Invalid password", data.Email))
		if err != nil {
			fmt.Printf("Failed to log login attempt: %v\n", err)
		}
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

	// Log successful login
	err = LogAction(db, existingUser.Usertag, "Successful Login", "auth", 0, fmt.Sprintf("Email: %s", existingUser.Email))
	if err != nil {
		fmt.Printf("Failed to log login attempt: %v\n", err)
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
		// Log failed password update attempt: User not found
		logErr := LogAction(db, data.Usertag, "Failed Password Update", "user", 0, "User not found")
		if logErr != nil {
			fmt.Printf("Failed to log action: %v\n", logErr)
		}

		return errors.New(responses.SOMETHING_WRONG)
	}

	// Verify the old password
	passwordCheck := utils.VerifyPassword(data.Old_password, password)
	if !passwordCheck {
		// Log failed password update attempt: Incorrect old password
		logErr := LogAction(db, data.Usertag, "Failed Password Update", "user", 0, "Incorrect old password")
		if logErr != nil {
			fmt.Printf("Failed to log action: %v\n", logErr)
		}

		return errors.New(responses.WRONG_PASSWORD)
	}
	if checkPassword(data.Usertag, data.New_password) {
		// Log failed password update attempt: Password reuse
		logErr := LogAction(db, data.Usertag, "Failed Password Update", "user", 0, "Password reuse attempt")
		if logErr != nil {
			fmt.Printf("Failed to log action: %v\n", logErr)
		}

		return errors.New(responses.PASSWORD_REUSE)
	}

	new_password := utils.HashPassword(data.New_password)
	_, err = db.Exec("UPDATE users SET password = ? WHERE usertag = ?", new_password, data.Usertag)
	if err != nil {
		// Log failed password update attempt: Database error
		logErr := LogAction(db, data.Usertag, "Failed Password Update", "user", 0, "Database error")
		if logErr != nil {
			fmt.Printf("Failed to log action: %v\n", logErr)
		}

		return errors.New(responses.SOMETHING_WRONG)
	}

	// Log successful password update
	logErr := LogAction(db, data.Usertag, "Successful Password Update", "user", 0, "Password updated successfully")
	if logErr != nil {
		fmt.Printf("Failed to log action: %v\n", logErr)
	}

	fmt.Println("password updated")
	return nil
}

func (UserServer) UpdateEmail(data models.ChangeEmail, usertag string) error {
	existingUser, err := utils.FindUserByTag(usertag)
	if err != nil {
		// Log failed email update: Database error while fetching user
		logErr := LogAction(db, usertag, "Failed Email Update", "user", 0, "Error checking existing user")
		if logErr != nil {
			fmt.Printf("Failed to log action: %v\n", logErr)
		}

		return fmt.Errorf("error checking existing user: %v", err)
	}
	if existingUser == nil {
		// Log failed email update: User not found
		logErr := LogAction(db, usertag, "Failed Email Update", "user", 0, "User not found")
		if logErr != nil {
			fmt.Printf("Failed to log action: %v\n", logErr)
		}

		return errors.New("user not found")
	}

	// Verify the current password
	if err := utils.CheckPassword(data.Current_password, existingUser.Password); err != nil {
		// Log failed email update: Invalid credentials
		logErr := LogAction(db, usertag, "Failed Email Update", "user", 0, "Invalid credentials")
		if logErr != nil {
			fmt.Printf("Failed to log action: %v\n", logErr)
		}

		return errors.New("invalid credentials")
	}

	// Check if the new email is already in use
	newEmailUser, err := utils.FindUserByEmail(data.Email)
	if err != nil {
		// Log failed email update: Error checking new email
		logErr := LogAction(db, usertag, "Failed Email Update", "user", 0, "Error checking new email")
		if logErr != nil {
			fmt.Printf("Failed to log action: %v\n", logErr)
		}

		return fmt.Errorf("error checking new email: %v", err)
	}
	if newEmailUser != nil {
		// Log failed email update: Email already in use
		logErr := LogAction(db, usertag, "Failed Email Update", "user", 0, "Email already in use")
		if logErr != nil {
			fmt.Printf("Failed to log action: %v\n", logErr)
		}

		return errors.New("email is already in use")
	}
	err = updateEmailInDatabase(usertag, data.Email)
	if err != nil {
		// Log failed email update: Database error during email update
		logErr := LogAction(db, usertag, "Failed Email Update", "user", 0, "Database error during email update")
		if logErr != nil {
			fmt.Printf("Failed to log action: %v\n", logErr)
		}

		return fmt.Errorf("error updating email in the database: %v", err)
	}

	// Log successful email update
	logErr := LogAction(db, usertag, "Successful Email Update", "user", 0, "Email updated successfully")
	if logErr != nil {
		fmt.Printf("Failed to log action: %v\n", logErr)
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

func (UserServer) HandleForgotPassword(email string) error {
	// Check if the email exists in the database
	user, err := utils.FindUserByEmail(email)
	if err != nil || user == nil {
		return fmt.Errorf("email not found")
	}

	// Generate reset token
	token, err := utils.GenerateResetToken(email)
	if err != nil {
		return fmt.Errorf("could not generate reset token")
	}

	// Send email with the reset token
	if err := utils.SendResetEmail(email, token); err != nil {
		return fmt.Errorf("could not send reset email")
	}

	return nil
}

func (UserServer) HandleResetPassword(data models.ResetPasswordRequest) error {
	email, err := utils.ValidateResetToken(data.Token)
	if err != nil {
		return fmt.Errorf("invalid or expired reset token")
	}
	hashedPassword, err := utils.HashPwd(data.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password")
	}
	if err := utils.UpdateUserPassword(email, hashedPassword); err != nil {
		return fmt.Errorf("failed to update password")
	}

	return nil
}

func (UserServer) DeleteAccount(data models.DeleteAccountReq) error {
	existingUser, err := utils.FindUserByTag(data.Usertag)
	if err != nil {
		return fmt.Errorf("error checking existing user: %v", err)
	}
	if existingUser == nil {
		return errors.New("user not found")
	}
	if err := utils.CheckPassword(data.CurrentPassword, existingUser.Password); err != nil {
		return errors.New("invalid password")
	}
	err = utils.DeleteUserFromDatabase(data.Usertag)
	if err != nil {
		return fmt.Errorf("error deleting user account from the database: %v", err)
	}

	return nil
}

// service layer for tasks
func (UserServer) CreateTask(data models.CreateTaskReq) error {
	query := `
		INSERT INTO tasks (title, description, deadline, category_id, usertag, status)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	result, err := db.Exec(query, data.Title, data.Description, data.Deadline, data.CategoryID, data.Usertag, data.Status)
	if err != nil {
		return fmt.Errorf("could not insert task: %v", err)
	}
	taskID, _ := result.LastInsertId()
	err = LogAction(db, data.Usertag, "Created Task", "task", int(taskID), fmt.Sprintf("Title: %s", data.Title))
	if err != nil {
		fmt.Printf("Failed to log action: %v\n", err)
	}
	return nil
}

func (UserServer) GetTasksByUsertag(usertag string) ([]models.Task, error) {
	query := `SELECT id, title, description, deadline, category_id, usertag, status, created_at, updated_at FROM tasks WHERE usertag = ?`
	rows, err := database.NewConnection().Query(query, usertag)
	if err != nil {
		return nil, fmt.Errorf("could not fetch tasks: %v", err)
	}
	defer rows.Close()

	var tasks []models.Task
	for rows.Next() {
		var task models.Task
		if err := rows.Scan(&task.ID, &task.Title, &task.Description, &task.Deadline, &task.CategoryID, &task.Usertag, &task.Status, &task.CreatedAt, &task.UpdatedAt); err != nil {
			return nil, fmt.Errorf("error scanning task: %v", err)
		}
		tasks = append(tasks, task)
	}
	return tasks, nil
}

func (UserServer) GetTaskByID(id string) (*models.Task, error) {
	query := `SELECT * FROM tasks WHERE id = ?`
	row := db.QueryRow(query, id)
	var task models.Task
	if err := row.Scan(&task.ID, &task.Title, &task.Description, &task.Deadline, &task.CategoryID, &task.Usertag, &task.Status, &task.CreatedAt, &task.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("task not found")
		}
		return nil, fmt.Errorf("could not fetch task: %v", err)
	}
	return &task, nil
}

func (UserServer) UpdateTask(id string, data models.UpdateTaskReq) error {
	query := `
		UPDATE tasks
		SET title = ?, description = ?, deadline = ?, status = ?
		WHERE id = ?
	`
	_, err := db.Exec(query, data.Title, data.Description, data.Deadline, data.Status, id)
	if err != nil {
		return fmt.Errorf("could not update task: %v", err)
	}
	// Convert id from string to int
	taskID, err := strconv.Atoi(id)
	if err != nil {
		return fmt.Errorf("invalid task ID: %v", err)
	}
	err = LogAction(db, data.Usertag, "Updated Task", "task", taskID, fmt.Sprintf("Title: %s", data.Title))
	if err != nil {
		fmt.Printf("Failed to log action: %v\n", err)
	}

	return nil
}

func (UserServer) DeleteTask(id string, usertag string) error {
	// Fetch the task details before deletion
	querySelect := `SELECT title FROM tasks WHERE id = ?`
	var taskTitle string
	err := db.QueryRow(querySelect, id).Scan(&taskTitle)
	if err != nil {
		return fmt.Errorf("could not fetch task details for logging: %v", err)
	}
	queryDelete := `DELETE FROM tasks WHERE id = ?`
	_, err = db.Exec(queryDelete, id)
	if err != nil {
		return fmt.Errorf("could not delete task: %v", err)
	}
	taskID, err := strconv.Atoi(id)
	if err != nil {
		return fmt.Errorf("invalid task ID: %v", err)
	}
	err = LogAction(db, usertag, "Deleted Task", "task", taskID, fmt.Sprintf("Title: %s", taskTitle))
	if err != nil {
		fmt.Printf("Failed to log action: %v\n", err)
	}

	return nil
}

func LogAction(db *sql.DB, usertag, action, resource string, resourceID int, details string) error {
	query := `INSERT INTO audit_logs (usertag, action, resource, resource_id, details) VALUES (?, ?, ?, ?, ?)`
	_, err := db.Exec(query, usertag, action, resource, resourceID, details)
	if err != nil {
		return fmt.Errorf("failed to log action: %v", err)
	}
	return nil
}
