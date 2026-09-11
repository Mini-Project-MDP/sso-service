package repository

import (
	"encoding/json"
	"log"
	"time"

	"github.com/Mini-Project-MDP/sso-service/pkg/domain"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func hashPassword(password string) string {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes)
}

func SeedData(db *gorm.DB) error {
	var count int64
	db.Model(&domain.SSOUser{}).Count(&count)
	if count > 0 {
		log.Println("Database already contains data, skipping seed.")
		return nil
	}

	hashedPwd := hashPassword("Password123!")

	// 1. Seed SSO Users
	users := []domain.SSOUser{
		{
			ID:          uuid.New().String(),
			EmployeeNo:  "EMP001",
			Name:        "Budi Santoso (Master Admin)",
			Email:       "master1@mayora.com",
			Password:    hashedPwd,
			Department:  "IT Enterprise Solutions",
			Position:    "Head of IT System Architecture",
			Status:      "ACTIVE",
			IsMaster:    true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          uuid.New().String(),
			EmployeeNo:  "EMP002",
			Name:        "Siti Rahma (Asset Manager)",
			Email:       "manager1@mayora.com",
			Password:    hashedPwd,
			Department:  "Asset Management Division",
			Position:    "Senior Asset Operations Manager",
			Status:      "ACTIVE",
			IsMaster:    false,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          uuid.New().String(),
			EmployeeNo:  "EMP003",
			Name:        "Ahmad Hidayat (Approver)",
			Email:       "approver1@mayora.com",
			Password:    hashedPwd,
			Department:  "Regional Operations - West Java",
			Position:    "Regional General Manager",
			Status:      "ACTIVE",
			IsMaster:    false,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          uuid.New().String(),
			EmployeeNo:  "EMP004",
			Name:        "Laras Putri (Regular User)",
			Email:       "user1@mayora.com",
			Password:    hashedPwd,
			Department:  "Sales & Field Support",
			Position:    "Sales Administrator",
			Status:      "ACTIVE",
			IsMaster:    false,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	for i := range users {
		if err := db.Create(&users[i]).Error; err != nil {
			return err
		}
	}

	// 2. Seed Connected Client Applications
	apps := []domain.ClientApp{
		{
			ID:            uuid.New().String(),
			Name:          "Mayora Asset System",
			ClientID:      "app_asset_mgmt_123",
			ClientSecret:  "secret_asset_mgmt_999",
			RedirectURIs:  "http://localhost:5173/sso/callback,http://localhost:5173/auth/callback,http://localhost:5174/sso/demo-client,https://asset-system-frontend.vercel.app/sso/callback,https://asset-system-frontend.vercel.app/auth/callback",
			LogoURL:       "https://images.unsplash.com/photo-1586528116311-ad8dd3c8310d?w=100&auto=format&fit=crop",
			Description:   "Corporate Asset Tracking, Fulfillment, & Approval System",
			AllowedScopes: "openid profile email roles",
			IsActive:      true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		},
		{
			ID:            uuid.New().String(),
			Name:          "Mayora HRIS Portal",
			ClientID:      "app_hris_portal_456",
			ClientSecret:  "secret_hris_portal_888",
			RedirectURIs:  "http://localhost:3000/sso/callback",
			LogoURL:       "https://images.unsplash.com/photo-1522071820081-009f0129c71c?w=100&auto=format&fit=crop",
			Description:   "Human Resource Information System & Payroll",
			AllowedScopes: "openid profile email",
			IsActive:      true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		},
		{
			ID:            uuid.New().String(),
			Name:          "Procurement Hub",
			ClientID:      "app_procurement_789",
			ClientSecret:  "secret_procurement_777",
			RedirectURIs:  "http://localhost:3001/sso/callback",
			LogoURL:       "https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?w=100&auto=format&fit=crop",
			Description:   "Vendor Management & Purchase Request Workflows",
			AllowedScopes: "openid profile email roles",
			IsActive:      true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		},
	}

	for i := range apps {
		if err := db.Create(&apps[i]).Error; err != nil {
			return err
		}
	}

	// 3. Seed User App Mappings
	fullPerms, _ := json.Marshal([]string{"*"})
	mgrPerms, _ := json.Marshal([]string{"asset:read", "asset:create", "asset:edit", "asset:approve"})
	apprPerms, _ := json.Marshal([]string{"asset:read", "asset:approve"})
	userPerms, _ := json.Marshal([]string{"asset:read", "asset:create"})

	mappings := []domain.UserAppMapping{
		{
			ID:             uuid.New().String(),
			UserID:         users[0].ID,
			AppID:          apps[0].ID,
			ExternalUserID: "usr_master1",
			AppRole:        "MASTER_ADMIN",
			Permissions:    string(fullPerms),
			IsActive:       true,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
		{
			ID:             uuid.New().String(),
			UserID:         users[1].ID,
			AppID:          apps[0].ID,
			ExternalUserID: "usr_mgr1",
			AppRole:        "ASSET_MANAGER",
			Permissions:    string(mgrPerms),
			IsActive:       true,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
		{
			ID:             uuid.New().String(),
			UserID:         users[2].ID,
			AppID:          apps[0].ID,
			ExternalUserID: "usr_appr1",
			AppRole:        "APPROVER",
			Permissions:    string(apprPerms),
			IsActive:       true,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
		{
			ID:             uuid.New().String(),
			UserID:         users[3].ID,
			AppID:          apps[0].ID,
			ExternalUserID: "usr_user1",
			AppRole:        "SALES_ADMIN",
			Permissions:    string(userPerms),
			IsActive:       true,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
	}

	for i := range mappings {
		if err := db.Create(&mappings[i]).Error; err != nil {
			return err
		}
	}

	// 4. Seed Audit Logs
	auditLogs := []domain.AuditLog{
		{
			ID:        uuid.New().String(),
			UserID:    users[0].ID,
			AppID:     apps[0].ID,
			EventType: "SYSTEM_INITIALIZED",
			IPAddress: "127.0.0.1",
			UserAgent: "System Auto-Seed",
			Details:   `{"message":"Mayora SSO Database initialized with default identity seeds"}`,
			CreatedAt: time.Now(),
		},
		{
			ID:        uuid.New().String(),
			UserID:    users[0].ID,
			AppID:     apps[0].ID,
			EventType: "LOGIN_SUCCESS",
			IPAddress: "192.168.1.50",
			UserAgent: "Mozilla/5.0 (X11; Linux x86_64)",
			Details:   `{"client_id":"app_asset_mgmt_123","method":"password"}`,
			CreatedAt: time.Now().Add(-10 * time.Minute),
		},
	}

	for i := range auditLogs {
		if err := db.Create(&auditLogs[i]).Error; err != nil {
			return err
		}
	}

	log.Println("Seeding completed successfully!")
	return nil
}
