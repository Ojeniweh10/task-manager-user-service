package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/ojeniweh10/task-manager-user-service/routes"
)

func main() {
	app := fiber.New(fiber.Config{
		AppName: "User Service",
	})
	app.Use(logger.New())
	app.Get("/admin/healthchecker", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"success": true,
			"message": "Welcome to Task Manager User Service",
		})
	})

	routes.Routes(app)
	routes.AdminRoutes(app)

	app.All("*", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"success": false,
			"message": "Not Found",
		})
	})
	log.Fatal(app.Listen(":8081"))
}
