package controllers

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/ojeniweh10/task-manager-user-service/models"
	"github.com/ojeniweh10/task-manager-user-service/responses"
	"github.com/ojeniweh10/task-manager-user-service/servers"
	"github.com/ojeniweh10/task-manager-user-service/utils"
)

type UserController struct{}
type TaskController struct{}

var userServer servers.UserServer

func (*UserController) RegisterUser(c *fiber.Ctx) error {
	var data models.RegisterUser
	if err := c.BodyParser(&data); err != nil {
		return responses.ErrorResponse(c, responses.BAD_DATA, 400)
	}
	if data.Email == "" || data.FirstName == "" || data.LastName == "" || data.Password == "" {
		return responses.ErrorResponse(c, responses.INCOMPLETE_DATA, 400)
	}

	data.Email = strings.TrimSpace(data.Email)
	data.FirstName = utils.CapitilizeName(data.FirstName)
	data.LastName = utils.CapitilizeName(data.LastName)

	if !utils.IsName(data.FirstName) || !utils.IsName(data.LastName) {
		return responses.ErrorResponse(c, responses.INVALID_NAME, 400)
	}

	if !utils.IsEmail(data.Email) {
		return responses.ErrorResponse(c, responses.INVALID_EMAIL, 400)
	}

	res, err := userServer.SetUser(data)

	if err != nil {
		return responses.ErrorResponse(c, err.Error(), 400)
	}
	return responses.SuccessResponse(c, responses.USER_CREATED, res, 201)
}

func (*UserController) Login(c *fiber.Ctx) error {
	var body models.LoginUser
	if err := c.BodyParser(&body); err != nil {
		return responses.ErrorResponse(c, responses.BAD_DATA, 400)
	}

	if body.Email == "" || body.Password == "" {
		return responses.ErrorResponse(c, responses.INCOMPLETE_DATA, 400)
	}

	token, res, err := servers.UserServer{}.AuthenticateUser(body)
	if err != nil {
		return responses.ErrorResponse(c, err.Error(), 400)
	}

	return responses.SuccessResponse(c, responses.LOGIN_SUCCESS, map[string]interface{}{
		"token": token,
		"user":  res,
	}, 200)
}

func (*UserController) ChangePassword(c *fiber.Ctx) error {
	var body models.ChangePasswordReq
	if err := c.BodyParser(&body); err != nil {
		return responses.ErrorResponse(c, responses.BAD_DATA, 400)
	}
	body.Usertag = c.Get("user")
	if body.Old_password == "" || body.Usertag == "" || body.New_password == "" {
		return responses.ErrorResponse(c, responses.INCOMPLETE_DATA, 400)
	}

	if body.Old_password == body.New_password {
		return responses.ErrorResponse(c, responses.PASSWORD_REUSE, 400)
	}
	if err := userServer.UpdatePassword(body); err != nil {
		return responses.ErrorResponse(c, err.Error(), 400)
	}
	return responses.SuccessResponse(c, responses.PASSWORD_CHANGED, nil, 200)
}

func (*UserController) ChangeEmail(c *fiber.Ctx) error {
	var body models.ChangeEmail
	if err := c.BodyParser(&body); err != nil {
		return responses.ErrorResponse(c, responses.BAD_DATA, 400)
	}
	body.Usertag = c.Get("usertag")
	if body.Usertag == "" {
		return responses.ErrorResponse(c, responses.INCOMPLETE_DATA, 400)
	}
	if body.Email == "" || body.Current_password == "" {
		return responses.ErrorResponse(c, responses.INCOMPLETE_DATA, 400)
	}
	if err := userServer.UpdateEmail(body, body.Usertag); err != nil {
		return responses.ErrorResponse(c, err.Error(), 400)
	}

	return responses.SuccessResponse(c, responses.EMAIL_CHANGED, nil, 200)
}

func (UserController) ForgotPassword(c *fiber.Ctx) error {
	var body models.ForgotPasswordRequest
	if err := c.BodyParser(&body); err != nil {
		return responses.ErrorResponse(c, responses.BAD_DATA, 400)
	}

	if body.Email == "" {
		return responses.ErrorResponse(c, responses.INCOMPLETE_DATA, 400)
	}

	if err := userServer.HandleForgotPassword(body.Email); err != nil {
		return responses.ErrorResponse(c, err.Error(), 400)
	}

	return responses.SuccessResponse(c, "Password reset instructions sent", nil, 200)
}

func (UserController) ResetPassword(c *fiber.Ctx) error {
	var body models.ResetPasswordRequest
	if err := c.BodyParser(&body); err != nil {
		return responses.ErrorResponse(c, responses.BAD_DATA, 400)
	}

	if body.Token == "" || body.NewPassword == "" {
		return responses.ErrorResponse(c, responses.INCOMPLETE_DATA, 400)
	}

	if err := userServer.HandleResetPassword(body); err != nil {
		return responses.ErrorResponse(c, err.Error(), 400)
	}

	return responses.SuccessResponse(c, "Password successfully reset", nil, 200)
}

func (UserController) DeleteAccount(c *fiber.Ctx) error {
	var body models.DeleteAccountReq
	if err := c.BodyParser(&body); err != nil {
		return responses.ErrorResponse(c, responses.BAD_DATA, 400)
	}
	body.Usertag = c.Get("usertag")
	if body.Usertag == "" || body.CurrentPassword == "" {
		return responses.ErrorResponse(c, responses.INCOMPLETE_DATA, 400)
	}
	err := userServer.DeleteAccount(body)
	if err != nil {
		return responses.ErrorResponse(c, err.Error(), 400)
	}
	return responses.SuccessResponse(c, responses.USER_DELETED, nil, 200)
}

//controller layer for task service

func (TaskController) CreateTask(c *fiber.Ctx) error {
	var body models.CreateTaskReq
	if err := c.BodyParser(&body); err != nil {
		return responses.ErrorResponse(c, responses.BAD_DATA, 400)
	}
	body.Usertag = c.Get("usertag")
	if body.Title == "" || body.Usertag == "" {
		return responses.ErrorResponse(c, responses.INCOMPLETE_DATA, 400)
	}
	if err := userServer.CreateTask(body); err != nil {
		return responses.ErrorResponse(c, err.Error(), 400)
	}
	return responses.SuccessResponse(c, responses.TASK_CREATED, nil, 200)
}

func (TaskController) GetTasks(c *fiber.Ctx) error {
	usertag := c.Get("usertag")
	if usertag == "" {
		return responses.ErrorResponse(c, responses.INCOMPLETE_DATA, 400)
	}
	tasks, err := userServer.GetTasksByUsertag(usertag)
	if err != nil {
		return responses.ErrorResponse(c, err.Error(), 500)
	}
	return responses.SuccessResponse(c, responses.TASK_FETCHED, tasks, 200)
}

func (TaskController) GetTaskByID(c *fiber.Ctx) error {
	id := c.Params("id")
	task, err := userServer.GetTaskByID(id)
	if err != nil {
		return responses.ErrorResponse(c, err.Error(), 404)
	}
	return responses.SuccessResponse(c, responses.TASK_FETCHED, task, 200)
}

func (TaskController) UpdateTask(c *fiber.Ctx) error {
	id := c.Params("id")
	var body models.UpdateTaskReq
	body.Usertag = c.Get("usertag")
	if body.Usertag == "" {
		return responses.ErrorResponse(c, responses.INCOMPLETE_DATA, 400)
	}
	if err := c.BodyParser(&body); err != nil {
		return responses.ErrorResponse(c, responses.BAD_DATA, 400)
	}
	if err := userServer.UpdateTask(id, body); err != nil {
		return responses.ErrorResponse(c, err.Error(), 500)
	}
	return responses.SuccessResponse(c, responses.TASK_UPDATED, nil, 200)
}

func (TaskController) DeleteTask(c *fiber.Ctx) error {
	id := c.Params("id")
	usertag := c.Get("usertag")
	if err := userServer.DeleteTask(id, usertag); err != nil {
		return responses.ErrorResponse(c, err.Error(), 500)
	}
	return responses.SuccessResponse(c, responses.TASK_DELETED, nil, 200)
}
