package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch"
	"github.com/elastic/go-elasticsearch/esapi"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/golang-jwt/jwt/v4"
	"github.com/ojeniweh10/task-manager-user-service/config"
	"github.com/ojeniweh10/task-manager-user-service/routes"
)

var jwtSecret = []byte(config.SecretKey)

func sendToElasticsearch() {
	cfg := elasticsearch.Config{
		Addresses: []string{
			"http://localhost:9200",
		},
	}

	es, err := elasticsearch.NewClient(cfg)
	if err != nil {
		log.Fatalf("Error creating the client: %s", err)
	}

	file, err := os.Open("audit.log")
	if err != nil {
		log.Fatalf("Error opening audit.log: %s", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry AuditLogEntry
		if err := json.Unmarshal([]byte(scanner.Text()), &entry); err != nil {
			log.Fatalf("Error parsing JSON: %s", err)
		}

		body, err := json.Marshal(entry)
		if err != nil {
			log.Fatalf("Error marshaling entry to JSON: %s", err)
		}

		req := esapi.IndexRequest{
			Index:        "audit_logs",
			DocumentType: "_doc",
			DocumentID:   "",
			Body:         strings.NewReader(string(body)),
			Refresh:      "true",
		}

		_, err = req.Do(context.Background(), es)
		if err != nil {
			log.Fatalf("Error sending entry to Elasticsearch: %s", err)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading audit.log: %s", err)
	}
}

// JWTMiddleware checks the validity of the token
func JWTMiddleware(c *fiber.Ctx) error {
	// Get the Authorization header
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Authorization header missing"})
	}

	// Extract the token from the "Bearer <token>" format
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid Authorization format"})
	}

	tokenString := parts[1]

	// Parse and verify the JWT token
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		// Ensure the signing method is as expected
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or expired token"})
	}

	// Extract claims and attach them to context
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		// Check expiration
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().After(time.Unix(int64(exp), 0)) {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Token expired"})
			}
		}

		// Attach user info to request context
		c.Locals("user_id", claims["user_id"])
		c.Locals("email", claims["email"])
	} else {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token claims"})
	}

	// Proceed to the next middleware/handler
	return c.Next()
}

type AuditLogEntry struct {
	Actor   string      `json:"actor"`
	Action  string      `json:"action"`
	Module  string      `json:"module"`
	When    time.Time   `json:"when"`
	Details interface{} `json:"details"`
}

func logAuditEvent(actor string, action string, module string, details interface{}) {
	entry := AuditLogEntry{
		Actor:   actor,
		Action:  action,
		Module:  module,
		When:    time.Now(),
		Details: details,
	}

	logEntry, _ := json.Marshal(entry)
	file, _ := os.OpenFile("audit.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer file.Close()

	file.WriteString(string(logEntry) + "\n")
}

func main() {
	app := fiber.New(fiber.Config{
		AppName: "Task-Manager User Service",
	})
	app.Use(logger.New())
	app.Get("/admin/healthchecker", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"success": true,
			"message": "Welcome to Task Manager User Service",
		})
	})

	routes.Routes(app)

	app.All("*", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"success": false,
			"message": "Not Found",
		})
	})
	log.Fatal(app.Listen(":8081"))
	logAuditEvent("Mohamed_Gamal", "password_change", "User Settings", "Changed password for security reasons")

}
