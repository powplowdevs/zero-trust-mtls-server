package main

import (
	"sync"
	"time"
)

// ~~~~~Permissions~~~~~
var Permissions = struct {
	SystemAdmin   string
	ManageDevices string
	ManageUsers   string
	ManagePending string
	ViewAuditLogs string
}{
	SystemAdmin:   "system_admin",
	ManageDevices: "manage_devices",
	ManageUsers:   "manage_users",
	ManagePending: "manage_pending",
	ViewAuditLogs: "view_audit_logs",
}

// ~~~~~Data structures~~~~~
type Device struct {
	DeviceID        string `json:"device_id"`
	DeviceName      string `json:"device_name"`
	CertFingerprint string `json:"cert_fingerprint"`
	OwnerUser       string `json:"owner_user"`
	IssuedAt        string `json:"issued_at"`
	ExpiresAt       string `json:"expires_at"`
	Revoked         bool   `json:"revoked"`
	LastSeen        string `json:"last_seen"`
}

type User struct {
	Username     string   `json:"username"`
	DisplayName  string   `json:"display_name"`
	PasswordHash string   `json:"password_hash"`
	Permissions  []string `json:"permissions"`
	Devices      []string `json:"devices"`
	CreatedAt    string   `json:"created_at"`
}

type Session struct {
	ID              string
	Username        string
	CertFingerprint string
	ExpiresAt       time.Time
}

type Config struct {
	BasePath               string   `json:"base_path"`
	ServerPort             int      `json:"server_port"`
	SessionTimeoutSec      int      `json:"session_timeout_seconds"`
	MaxLogFileSizeBytes    int      `json:"max_log_file_size_bytes"`
	MaxBufferSizeBytes     int      `json:"max_buffer_size_bytes"`
	LogAutoFlush           bool     `json:"log_auto_flush"`
	AuditLogPath           string   `json:"audit_log_path"`
	MaxLoginAttempts       int      `json:"max_login_attempts"`
	RateLimitWindowSeconds int      `json:"rate_limit_window_seconds"`
	PermissionsList        []string `json:"permissions_list"`
	SMTPHost               string   `json:"smtp_host"`
	SMTPPort               int      `json:"smtp_port"`
	SMTPUsername           string   `json:"smtp_username"`
	SMTPPassword           string   `json:"smtp_password"`
}

type rateLimit struct {
	WindowStart  int64 `json:"windowStart"`
	LastAttempt  int64 `json:"lastAttempt"`
	RequestCount int   `json:"requestCount"`
}

type PendingRequest struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	DeviceName   string `json:"device_name"`
	CSR          string `json:"csr"`
	Email        string `json:"email"`
	SubmittedAt  string `json:"submitted_at"`
	Status       string `json:"status"`
}

type PendingView struct {
	Username    string `json:"username"`
	DeviceName  string `json:"device_name"`
	SubmittedAt string `json:"submitted_at"`
	Status      string `json:"status"`
}

type MeView struct {
	Username    string       `json:"username"`
	DisplayName string       `json:"display_name"`
	Permissions []string     `json:"permissions"`
	Devices     []DeviceView `json:"devices"`
}

// For exposing data to front end
type DeviceView struct {
	DeviceName string `json:"device_name"`
	DeviceID   string `json:"device_id"`
	IssuedAt   string `json:"issued_at"`
	ExpiresAt  string `json:"expires_at"`
	LastSeen   string `json:"last_seen"`
}

type UserView struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"display_name"`
	Permissions []string `json:"permissions"`
	Devices     []string `json:"devices"`
	CreatedAt   string   `json:"created_at"`
}

// Stores
type rateLimiter struct {
	mutex         sync.Mutex
	rateLimitPath string
}

type DeviceStore struct {
	mutex       sync.Mutex
	devicesPath string
}

type UserStore struct {
	mutex     sync.Mutex
	usersPath string
}

type SessionStore struct {
	mutex        sync.Mutex
	sessionsPath string
}

type PendingStore struct {
	mutex       sync.Mutex
	pendingPath string
}
