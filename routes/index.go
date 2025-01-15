package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ojeniweh10/task-manager-user-service/controllers"
)

var UserController controllers.UserController

func Routes(app *fiber.App) {
	app.Post("/register", UserController.RegisterUser)
	app.Post("/login", UserController.Login)
	app.Patch("/change-password", UserController.ChangePassword)
	app.Patch("/change-email", UserController.ChangeEmail)
	app.Post("/forgot-password", UserController.ForgotPassword)
	app.Post("/reset-password", UserController.ResetPassword)

}
