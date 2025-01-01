package models

import (
	"time"
)

type RegisterUser struct {
	Email        string `json:"email" validate:"required"`
	Password     string `json:"password" validate:"required"`
	Deviceid     string `json:"deviceid"`
	Device_token string `json:"device_token"`
	Timezone     string
}

type User struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	Deviceid  string    `json:"deviceid"`
	Timezone  string    `json:"timezone"`
	CreatedAt time.Time `json:"created_at"`
}
