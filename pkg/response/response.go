package response

import (
	"github.com/gofiber/fiber/v3"
)

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

func JSON(c fiber.Ctx, statusCode int, message string, data interface{}) error {
	return c.Status(statusCode).JSON(Response{
		Success: statusCode >= 200 && statusCode < 300,
		Message: message,
		Data:    data,
	})
}

func Success(c fiber.Ctx, data interface{}) error {
	return JSON(c, fiber.StatusOK, "Success", data)
}

func Created(c fiber.Ctx, data interface{}) error {
	return JSON(c, fiber.StatusCreated, "Created successfully", data)
}

func Error(c fiber.Ctx, statusCode int, errMessage string) error {
	return c.Status(statusCode).JSON(Response{
		Success: false,
		Error:   errMessage,
	})
}
