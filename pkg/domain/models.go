package domain

import (
	"time"
)

// ClientApp represents an external application registered with the SSO server.
type ClientApp struct {
	ID           string    `gorm:"primaryKey;size:64" json:"id"`
	Name         string    `gorm:"size:100;not null" json:"name"`
	ClientID     string    `gorm:"size:64;uniqueIndex;not null" json:"client_id"`
	ClientSecret string    `gorm:"size:128;not null" json:"client_secret"`
	RedirectURIs string    `gorm:"type:text;not null" json:"redirect_uris"` // Comma-separated or JSON array
	LogoURL      string    `gorm:"size:255" json:"logo_url"`
	Description  string    `gorm:"size:255" json:"description"`
	AllowedScopes string   `gorm:"size:255" json:"allowed_scopes"` // e.g. "openid profile email roles"
	IsActive     bool      `gorm:"default:true" json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// SSOUser represents a centralized user identity in the Mayora SSO system.
type SSOUser struct {
	ID          string    `gorm:"primaryKey;size:64" json:"id"`
	EmployeeNo  string    `gorm:"size:30;uniqueIndex;not null" json:"employee_no"`
	Name        string    `gorm:"size:100;not null" json:"name"`
	Email       string    `gorm:"size:100;uniqueIndex;not null" json:"email"`
	Password    string    `gorm:"size:255;not null" json:"-"`
	Department  string    `gorm:"size:100" json:"department"`
	Position    string    `gorm:"size:100" json:"position"`
	Status      string    `gorm:"size:20;default:'ACTIVE'" json:"status"` // ACTIVE, INACTIVE, SUSPENDED
	IsMaster    bool      `gorm:"default:false" json:"is_master"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// UserAppMapping represents the mapping of an SSO user to a specific connected application.
type UserAppMapping struct {
	ID             string    `gorm:"primaryKey;size:64" json:"id"`
	UserID         string    `gorm:"size:64;index;not null" json:"user_id"`
	AppID          string    `gorm:"size:64;index;not null" json:"app_id"`
	ExternalUserID string    `gorm:"size:64" json:"external_user_id"` // User ID in target application
	AppRole        string    `gorm:"size:50" json:"app_role"`         // Role in target application e.g. ADMIN, MANAGER
	Permissions    string    `gorm:"type:text" json:"permissions"`    // JSON array of strings e.g. ["asset:read", "asset:write"]
	IsActive       bool      `gorm:"default:true" json:"is_active"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`

	User SSOUser   `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"user,omitempty"`
	App  ClientApp `gorm:"foreignKey:AppID;constraint:OnDelete:CASCADE" json:"app,omitempty"`
}

// SSOSession tracks active user sessions across SSO and client apps.
type SSOSession struct {
	ID           string    `gorm:"primaryKey;size:64" json:"id"`
	UserID       string    `gorm:"size:64;index;not null" json:"user_id"`
	SessionToken string    `gorm:"size:128;uniqueIndex;not null" json:"session_token"`
	IPAddress    string    `gorm:"size:45" json:"ip_address"`
	UserAgent    string    `gorm:"size:255" json:"user_agent"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`

	User SSOUser `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"user,omitempty"`
}

// AuthCode stores temporary OAuth2 authorization codes.
type AuthCode struct {
	ID            string     `gorm:"primaryKey;size:64" json:"id"`
	Code          string     `gorm:"size:128;uniqueIndex;not null" json:"code"`
	ClientID      string     `gorm:"size:64;not null" json:"client_id"`
	UserID        string     `gorm:"size:64;not null" json:"user_id"`
	RedirectURI   string     `gorm:"type:text;not null" json:"redirect_uri"`
	Scope         string     `gorm:"size:255" json:"scope"`
	State         string     `gorm:"size:255" json:"state"`
	CodeChallenge string     `gorm:"size:255" json:"code_challenge,omitempty"`
	Used          bool       `gorm:"default:false" json:"used"`
	UsedAt        *time.Time `json:"used_at,omitempty"`
	ExpiresAt     time.Time  `json:"expires_at"`
	CreatedAt     time.Time  `json:"created_at"`
}

// AuditLog captures SSO authentication & management events.
type AuditLog struct {
	ID        string    `gorm:"primaryKey;size:64" json:"id"`
	UserID    string    `gorm:"size:64;index" json:"user_id,omitempty"`
	AppID     string    `gorm:"size:64;index" json:"app_id,omitempty"`
	EventType string    `gorm:"size:50;not null" json:"event_type"` // LOGIN_SUCCESS, LOGIN_FAILED, AUTHORIZATION_GRANTED, TOKEN_ISSUED, SESSION_REVOKED, APP_CREATED, USER_MAPPED
	IPAddress string    `gorm:"size:45" json:"ip_address"`
	UserAgent string    `gorm:"size:255" json:"user_agent"`
	Details   string    `gorm:"type:text" json:"details"`
	CreatedAt time.Time `json:"created_at"`

	User *SSOUser   `gorm:"foreignKey:UserID" json:"user,omitempty"`
	App  *ClientApp `gorm:"foreignKey:AppID" json:"app,omitempty"`
}

// DTO Requests & Responses

type AuthorizeRequest struct {
	ClientID     string `json:"client_id" query:"client_id"`
	RedirectURI  string `json:"redirect_uri" query:"redirect_uri"`
	ResponseType string `json:"response_type" query:"response_type"`
	Scope        string `json:"scope" query:"scope"`
	State        string `json:"state" query:"state"`
}

type SSOLoginRequest struct {
	UsernameOrEmail string `json:"username_or_email"`
	Password        string `json:"password"`
	ClientID        string `json:"client_id"`
	RedirectURI     string `json:"redirect_uri"`
	State           string `json:"state"`
	Scope           string `json:"scope"`
}

type SSOLoginResponse struct {
	SessionToken string    `json:"session_token"`
	AuthCode     string    `json:"auth_code,omitempty"`
	RedirectURI  string    `json:"redirect_uri,omitempty"`
	User         *SSOUser  `json:"user"`
}

type TokenExchangeRequest struct {
	GrantType    string `json:"grant_type" form:"grant_type"`
	Code         string `json:"code" form:"code"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri"`
	ClientID     string `json:"client_id" form:"client_id"`
	ClientSecret string `json:"client_secret" form:"client_secret"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IDToken     string `json:"id_token,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

type UserInfoResponse struct {
	Sub            string         `json:"sub"`
	EmployeeNo     string         `json:"employee_no"`
	Name           string         `json:"name"`
	Email          string         `json:"email"`
	Department     string         `json:"department"`
	Position       string         `json:"position"`
	IsMaster       bool           `json:"is_master"`
	AppMapping     *MappedAppData `json:"app_mapping,omitempty"`
}

type MappedAppData struct {
	AppID          string   `json:"app_id"`
	AppName        string   `json:"app_name"`
	ExternalUserID string   `json:"external_user_id"`
	AppRole        string   `json:"app_role"`
	Permissions    []string `json:"permissions"`
}

type CreateAppRequest struct {
	Name         string `json:"name"`
	RedirectURIs string `json:"redirect_uris"`
	LogoURL      string `json:"logo_url"`
	Description  string `json:"description"`
	AllowedScopes string `json:"allowed_scopes"`
}

type CreateUserRequest struct {
	EmployeeNo string `json:"employee_no"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	Department string `json:"department"`
	Position   string `json:"position"`
	IsMaster   bool   `json:"is_master"`
}

type CreateUserAppMappingRequest struct {
	UserID         string   `json:"user_id"`
	AppID          string   `json:"app_id"`
	ExternalUserID string   `json:"external_user_id"`
	AppRole        string   `json:"app_role"`
	Permissions    []string `json:"permissions"`
}

type StatsResponse struct {
	TotalApps      int64 `json:"total_apps"`
	TotalUsers     int64 `json:"total_users"`
	ActiveSessions int64 `json:"active_sessions"`
	LoginsToday    int64 `json:"logins_today"`
}
