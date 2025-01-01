package middleware

import (
	"errors"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/ojeniweh10/task-manager-user-service/config"
)

// JWTAuthMiddleware protects routes with JWT verification.

func JWTAuthMiddleware(c *fiber.Ctx) error {
	// Get the JWT from the Authorization header
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "Missing or Invalid Authorization Header")
	}

	// Split the "Bearer <token>" and get the token string
	bearerToken := strings.Split(authHeader, " ")
	if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid Authorization Format")
	}

	// Validate the token with the secret key
	tokenStr := bearerToken[1]

	// Parse the JWT
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(config.SecretKey), nil
	})

	if err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid Token")
	}

	// If the token is valid, extract the claims (user data in this case)
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Store the user data in the context (we can access it later)
		c.Locals("user", claims)
		return c.Next()
	}

	// Token invalid or expired
	return fiber.NewError(fiber.StatusUnauthorized, "Token Invalid or Expired")
}
