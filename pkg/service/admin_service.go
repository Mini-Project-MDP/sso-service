package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Mini-Project-MDP/sso-service/pkg/domain"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AdminService struct {
	db *gorm.DB
}

func NewAdminService(db *gorm.DB) *AdminService {
	return &AdminService{db: db}
}

// --- Connected Applications ---

func (s *AdminService) GetAllApps(ctx context.Context) ([]domain.ClientApp, error) {
	var apps []domain.ClientApp
	err := s.db.WithContext(ctx).Order("created_at desc").Find(&apps).Error
	return apps, err
}

func (s *AdminService) CreateApp(ctx context.Context, req domain.CreateAppRequest) (*domain.ClientApp, error) {
	clientID := "app_" + uuid.New().String()[:8]
	clientSecret := "sec_" + uuid.New().String() + uuid.New().String()

	app := domain.ClientApp{
		ID:            uuid.New().String(),
		Name:          req.Name,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		RedirectURIs:  req.RedirectURIs,
		LogoURL:       req.LogoURL,
		Description:   req.Description,
		AllowedScopes: req.AllowedScopes,
		IsActive:      true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if app.AllowedScopes == "" {
		app.AllowedScopes = "openid profile email"
	}

	if err := s.db.WithContext(ctx).Create(&app).Error; err != nil {
		return nil, err
	}
	return &app, nil
}

func (s *AdminService) RotateClientSecret(ctx context.Context, id string) (*domain.ClientApp, error) {
	var app domain.ClientApp
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&app).Error; err != nil {
		return nil, errors.New("app not found")
	}

	app.ClientSecret = "sec_" + uuid.New().String() + uuid.New().String()
	app.UpdatedAt = time.Now()
	if err := s.db.WithContext(ctx).Save(&app).Error; err != nil {
		return nil, err
	}
	return &app, nil
}

func (s *AdminService) ToggleAppStatus(ctx context.Context, id string, active bool) error {
	return s.db.WithContext(ctx).Model(&domain.ClientApp{}).Where("id = ?", id).Update("is_active", active).Error
}

func (s *AdminService) DeleteApp(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Where("id = ?", id).Delete(&domain.ClientApp{}).Error
}

// --- SSO Users ---

func (s *AdminService) GetAllUsers(ctx context.Context) ([]domain.SSOUser, error) {
	var users []domain.SSOUser
	err := s.db.WithContext(ctx).Order("created_at desc").Find(&users).Error
	return users, err
}

func (s *AdminService) CreateUser(ctx context.Context, req domain.CreateUserRequest) (*domain.SSOUser, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := domain.SSOUser{
		ID:         uuid.New().String(),
		EmployeeNo: req.EmployeeNo,
		Name:       req.Name,
		Email:      req.Email,
		Password:   string(hashed),
		Department: req.Department,
		Position:   req.Position,
		Status:     "ACTIVE",
		IsMaster:   req.IsMaster,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := s.db.WithContext(ctx).Create(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *AdminService) UpdateUserStatus(ctx context.Context, id string, status string) error {
	return s.db.WithContext(ctx).Model(&domain.SSOUser{}).Where("id = ?", id).Update("status", status).Error
}

func (s *AdminService) ToggleMasterUser(ctx context.Context, id string, isMaster bool) error {
	return s.db.WithContext(ctx).Model(&domain.SSOUser{}).Where("id = ?", id).Update("is_master", isMaster).Error
}

// --- User App Mappings ---

func (s *AdminService) GetAllMappings(ctx context.Context) ([]domain.UserAppMapping, error) {
	var mappings []domain.UserAppMapping
	err := s.db.WithContext(ctx).Preload("User").Preload("App").Order("created_at desc").Find(&mappings).Error
	return mappings, err
}

func (s *AdminService) CreateUserAppMapping(ctx context.Context, req domain.CreateUserAppMappingRequest) (*domain.UserAppMapping, error) {
	permsJSON, _ := json.Marshal(req.Permissions)

	// Check if existing mapping
	var existing domain.UserAppMapping
	err := s.db.WithContext(ctx).Where("user_id = ? AND app_id = ?", req.UserID, req.AppID).First(&existing).Error
	if err == nil {
		// Update existing
		existing.ExternalUserID = req.ExternalUserID
		existing.AppRole = req.AppRole
		existing.Permissions = string(permsJSON)
		existing.UpdatedAt = time.Now()
		if err := s.db.WithContext(ctx).Save(&existing).Error; err != nil {
			return nil, err
		}
		return &existing, nil
	}

	mapping := domain.UserAppMapping{
		ID:             uuid.New().String(),
		UserID:         req.UserID,
		AppID:          req.AppID,
		ExternalUserID: req.ExternalUserID,
		AppRole:        req.AppRole,
		Permissions:    string(permsJSON),
		IsActive:       true,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	if err := s.db.WithContext(ctx).Create(&mapping).Error; err != nil {
		return nil, err
	}
	return &mapping, nil
}

func (s *AdminService) DeleteMapping(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Where("id = ?", id).Delete(&domain.UserAppMapping{}).Error
}

// --- Active Sessions ---

func (s *AdminService) GetActiveSessions(ctx context.Context) ([]domain.SSOSession, error) {
	var sessions []domain.SSOSession
	err := s.db.WithContext(ctx).Preload("User").Order("created_at desc").Find(&sessions).Error
	return sessions, err
}

func (s *AdminService) RevokeSession(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Where("id = ?", id).Delete(&domain.SSOSession{}).Error
}

// --- Audit Logs ---

func (s *AdminService) GetAuditLogs(ctx context.Context) ([]domain.AuditLog, error) {
	var logs []domain.AuditLog
	err := s.db.WithContext(ctx).Preload("User").Preload("App").Order("created_at desc").Limit(100).Find(&logs).Error
	return logs, err
}

// --- Stats ---

func (s *AdminService) GetStats(ctx context.Context) (*domain.StatsResponse, error) {
	var totalApps int64
	var totalUsers int64
	var activeSessions int64
	var loginsToday int64

	s.db.WithContext(ctx).Model(&domain.ClientApp{}).Count(&totalApps)
	s.db.WithContext(ctx).Model(&domain.SSOUser{}).Count(&totalUsers)
	s.db.WithContext(ctx).Model(&domain.SSOSession{}).Where("expires_at > ?", time.Now()).Count(&activeSessions)

	todayStart := time.Now().Truncate(24 * time.Hour)
	s.db.WithContext(ctx).Model(&domain.AuditLog{}).Where("event_type = 'LOGIN_SUCCESS' AND created_at >= ?", todayStart).Count(&loginsToday)

	return &domain.StatsResponse{
		TotalApps:      totalApps,
		TotalUsers:     totalUsers,
		ActiveSessions: activeSessions,
		LoginsToday:    loginsToday,
	}, nil
}
