package config

import (
	"os"

	"github.com/joho/godotenv"
)

var _ = godotenv.Load("dev.env")

type dbConfig struct {
	Host     string
	User     string
	Password string
	Name     string
}

func Db() dbConfig {
	return dbConfig{
		Host:     os.Getenv("DB_HOST"),
		User:     os.Getenv("DB_USER"),
		Password: os.Getenv("DB_PASSWORD"),
		Name:     os.Getenv("DB_NAME"),
	}
}

var SecretKey = os.Getenv("SECRET_KEY")
