package models

import (
	"time"
)

type RegisterUser struct {
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type User struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	CreatedAt time.Time `json:"created_at"`
}

type LoginUser struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserLoginRequest struct {
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type Changepassword struct {
	Email        string `json:"email"`
	Old_password string `json:"old_password"`
	New_password string `json:"new_password"`
}

type ChangeEmail struct {
	Email            string `json:"email"`
	Current_password string `json:"current_password"`
}
