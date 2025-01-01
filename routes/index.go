package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ojeniweh10/task-manager-user-service/controllers"
)

var UserController controllers.UserController

func Routes(app *fiber.App) {
	app.Post("/register", UserController.RegisterUser)
}
