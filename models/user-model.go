package models

import (
	"time"
)

type RegisterUser struct {
	Email     string `json:"email" validate:"required"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Password  string `json:"password" validate:"required"`
}

type User struct {
	Usertag   string    `json:"usertag"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type LoginUser struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserLoginRequest struct {
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type ChangePasswordReq struct {
	Usertag      string `json:"usertag"`
	Old_password string `json:"old_password" validate:"required"`
	New_password string `json:"new_password" validate:"required"`
}

type ChangeEmail struct {
	Usertag          string `json:"usertag"`
	Email            string `json:"email"`
	Current_password string `json:"current_password"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type DeleteAccountReq struct {
	Usertag         string `json:"usertag"`
	CurrentPassword string `json:"current_password"`
}
