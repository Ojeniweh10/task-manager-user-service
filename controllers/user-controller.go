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

var userServer servers.UserServer

func (*UserController) RegisterUser(c *fiber.Ctx) error {
	var data models.RegisterUser
	if err := c.BodyParser(&data); err != nil {
		return responses.ErrorResponse(c, responses.BAD_DATA, 400)
	}
	if data.Email == "" || data.Password == "" {
		return responses.ErrorResponse(c, responses.INCOMPLETE_DATA, 400)
	}

	data.Email = strings.TrimSpace(data.Email)

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
