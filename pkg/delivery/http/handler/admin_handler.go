package handler

import (
	"github.com/Mini-Project-MDP/sso-service/pkg/domain"
	"github.com/Mini-Project-MDP/sso-service/pkg/response"
	"github.com/Mini-Project-MDP/sso-service/pkg/service"
	"github.com/gofiber/fiber/v3"
)

type AdminHandler struct {
	adminService *service.AdminService
}

func NewAdminHandler(adminService *service.AdminService) *AdminHandler {
	return &AdminHandler{adminService: adminService}
}

// Connected Apps
func (h *AdminHandler) GetApps(c fiber.Ctx) error {
	apps, err := h.adminService.GetAllApps(c.Context())
	if err != nil {
		return response.Error(c, fiber.StatusInternalServerError, err.Error())
	}
	return response.Success(c, apps)
}

func (h *AdminHandler) CreateApp(c fiber.Ctx) error {
	var req domain.CreateAppRequest
	if err := c.Bind().Body(&req); err != nil {
		return response.Error(c, fiber.StatusBadRequest, "Invalid request payload")
	}

	app, err := h.adminService.CreateApp(c.Context(), req)
	if err != nil {
		return response.Error(c, fiber.StatusBadRequest, err.Error())
	}
	return response.Created(c, app)
}

func (h *AdminHandler) RotateSecret(c fiber.Ctx) error {
	id := c.Params("id")
	app, err := h.adminService.RotateClientSecret(c.Context(), id)
	if err != nil {
		return response.Error(c, fiber.StatusBadRequest, err.Error())
	}
	return response.Success(c, app)
}

func (h *AdminHandler) ToggleAppStatus(c fiber.Ctx) error {
	id := c.Params("id")
	var req struct {
		IsActive bool `json:"is_active"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return response.Error(c, fiber.StatusBadRequest, "Invalid request payload")
	}

	if err := h.adminService.ToggleAppStatus(c.Context(), id, req.IsActive); err != nil {
		return response.Error(c, fiber.StatusInternalServerError, err.Error())
	}
	return response.Success(c, fiber.Map{"message": "App status updated successfully"})
}

func (h *AdminHandler) DeleteApp(c fiber.Ctx) error {
	id := c.Params("id")
	if err := h.adminService.DeleteApp(c.Context(), id); err != nil {
		return response.Error(c, fiber.StatusInternalServerError, err.Error())
	}
	return response.Success(c, fiber.Map{"message": "App deleted successfully"})
}

// Users
func (h *AdminHandler) GetUsers(c fiber.Ctx) error {
	users, err := h.adminService.GetAllUsers(c.Context())
	if err != nil {
		return response.Error(c, fiber.StatusInternalServerError, err.Error())
	}
	return response.Success(c, users)
}

func (h *AdminHandler) CreateUser(c fiber.Ctx) error {
	var req domain.CreateUserRequest
	if err := c.Bind().Body(&req); err != nil {
		return response.Error(c, fiber.StatusBadRequest, "Invalid request payload")
	}

	user, err := h.adminService.CreateUser(c.Context(), req)
	if err != nil {
		return response.Error(c, fiber.StatusBadRequest, err.Error())
	}
	return response.Created(c, user)
}

func (h *AdminHandler) UpdateUserStatus(c fiber.Ctx) error {
	id := c.Params("id")
	var req struct {
		Status string `json:"status"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return response.Error(c, fiber.StatusBadRequest, "Invalid request payload")
	}

	if err := h.adminService.UpdateUserStatus(c.Context(), id, req.Status); err != nil {
		return response.Error(c, fiber.StatusInternalServerError, err.Error())
	}
	return response.Success(c, fiber.Map{"message": "User status updated"})
}

func (h *AdminHandler) ToggleMaster(c fiber.Ctx) error {
	id := c.Params("id")
	var req struct {
		IsMaster bool `json:"is_master"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return response.Error(c, fiber.StatusBadRequest, "Invalid request payload")
	}

	if err := h.adminService.ToggleMasterUser(c.Context(), id, req.IsMaster); err != nil {
		return response.Error(c, fiber.StatusInternalServerError, err.Error())
	}
	return response.Success(c, fiber.Map{"message": "Master status updated"})
}

// Mappings
func (h *AdminHandler) GetMappings(c fiber.Ctx) error {
	mappings, err := h.adminService.GetAllMappings(c.Context())
	if err != nil {
		return response.Error(c, fiber.StatusInternalServerError, err.Error())
	}
	return response.Success(c, mappings)
}

func (h *AdminHandler) CreateMapping(c fiber.Ctx) error {
	var req domain.CreateUserAppMappingRequest
	if err := c.Bind().Body(&req); err != nil {
		return response.Error(c, fiber.StatusBadRequest, "Invalid request payload")
	}

	mapping, err := h.adminService.CreateUserAppMapping(c.Context(), req)
	if err != nil {
		return response.Error(c, fiber.StatusBadRequest, err.Error())
	}
	return response.Created(c, mapping)
}

func (h *AdminHandler) DeleteMapping(c fiber.Ctx) error {
	id := c.Params("id")
	if err := h.adminService.DeleteMapping(c.Context(), id); err != nil {
		return response.Error(c, fiber.StatusInternalServerError, err.Error())
	}
	return response.Success(c, fiber.Map{"message": "Mapping deleted successfully"})
}

// Sessions
func (h *AdminHandler) GetSessions(c fiber.Ctx) error {
	sessions, err := h.adminService.GetActiveSessions(c.Context())
	if err != nil {
		return response.Error(c, fiber.StatusInternalServerError, err.Error())
	}
	return response.Success(c, sessions)
}

func (h *AdminHandler) RevokeSession(c fiber.Ctx) error {
	id := c.Params("id")
	if err := h.adminService.RevokeSession(c.Context(), id); err != nil {
		return response.Error(c, fiber.StatusInternalServerError, err.Error())
	}
	return response.Success(c, fiber.Map{"message": "Session revoked successfully"})
}

// Audit Logs
func (h *AdminHandler) GetAuditLogs(c fiber.Ctx) error {
	logs, err := h.adminService.GetAuditLogs(c.Context())
	if err != nil {
		return response.Error(c, fiber.StatusInternalServerError, err.Error())
	}
	return response.Success(c, logs)
}

// Stats
func (h *AdminHandler) GetStats(c fiber.Ctx) error {
	stats, err := h.adminService.GetStats(c.Context())
	if err != nil {
		return response.Error(c, fiber.StatusInternalServerError, err.Error())
	}
	return response.Success(c, stats)
}
