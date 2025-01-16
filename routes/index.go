package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ojeniweh10/task-manager-user-service/controllers"
)

var UserController controllers.UserController
var TaskController controllers.TaskController

func Routes(app *fiber.App) {
	//user service routes
	app.Post("/register", UserController.RegisterUser)
	app.Post("/login", UserController.Login)
	app.Patch("/change-password", UserController.ChangePassword)
	app.Patch("/change-email", UserController.ChangeEmail)
	app.Post("/forgot-password", UserController.ForgotPassword)
	app.Post("/reset-password", UserController.ResetPassword)
	app.Post("/delete-account", UserController.DeleteAccount)

	//task service routes

	app.Post("/create-task", TaskController.CreateTask)
	app.Get("/tasks", TaskController.GetTasks)

}
