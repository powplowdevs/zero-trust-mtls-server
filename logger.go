// Known issues:
// 1. No log rotation implemented
// 2. Logging is synchronous, but at this scale that is ok.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ~~~~~ Audit Logging ~~~~~
type Action string
type Outcome string

var Actions = struct {
	MTLS_STARTUP       Action
	MTLS_HANDSHAKE     Action
	SUBMIT_LOGIN       Action
	SUBMIT_ENROLLMENT  Action
	CREATE_SESSION     Action
	CREATE_COOKIE      Action
	SESSION_EXPIRY     Action
	NAVIGATE_ENDPOINT  Action
	VALIDATE_SESSION   Action
	EDIT_SESSION       Action
	LOAD_DATA          Action
	SAVE_DATA          Action
	CHECK_RATE_LIMIT   Action
	APPROVE_ENROLLMENT Action
	REJECT_ENROLLMENT  Action
}{
	MTLS_STARTUP:       "MTLS_STARTUP",
	MTLS_HANDSHAKE:     "MTLS_HANDSHAKE",
	SUBMIT_LOGIN:       "SUBMIT_LOGIN",
	SUBMIT_ENROLLMENT:  "SUBMIT_ENROLLMENT",
	CREATE_SESSION:     "CREATE_SESSION",
	CREATE_COOKIE:      "CREATE_COOKIE",
	SESSION_EXPIRY:     "SESSION_EXPIRY",
	NAVIGATE_ENDPOINT:  "NAVIGATE_ENDPOINT",
	VALIDATE_SESSION:   "VALIDATE_SESSION",
	EDIT_SESSION:       "EDIT_SESSION",
	LOAD_DATA:          "LOAD_DATA",
	SAVE_DATA:          "SAVE_DATA",
	CHECK_RATE_LIMIT:   "CHECK_RATE_LIMIT",
	APPROVE_ENROLLMENT: "APPROVE_ENROLLMENT",
	REJECT_ENROLLMENT:  "REJECT_ENROLLMENT",
}

var Outcomes = struct {
	NO_CERT             Outcome
	NO_COOKIE           Outcome
	NO_SESSION          Outcome
	CERT_MISMATCH       Outcome
	INVALID_CREDENTIALS Outcome
	NO_PERMISSION       Outcome
	SUCCESS             Outcome
	REJECTED            Outcome
	ERROR               Outcome
	RATE_LIMITED        Outcome
	CERT_USER_MISMATCH  Outcome
}{
	NO_CERT:             "NO_CERT",
	NO_COOKIE:           "NO_COOKIE",
	NO_SESSION:          "NO_SESSION",
	CERT_MISMATCH:       "CERT_MISMATCH",
	INVALID_CREDENTIALS: "INVALID_CREDENTIALS",
	NO_PERMISSION:       "NO_PERMISSION",
	SUCCESS:             "SUCCESS",
	REJECTED:            "REJECTED",
	ERROR:               "ERROR",
	RATE_LIMITED:        "RATE_LIMITED",
	CERT_USER_MISMATCH:  "CERT_USER_MISMATCH",
}

// AuditEvent struct
type AuditEvent struct {
	Timestamp   int64             `json:"timestamp"`
	Action      Action            `json:"action"`
	Outcome     Outcome           `json:"outcome"`
	Username    string            `json:"username"`
	Fingerprint string            `json:"fingerprint"`
	IP          string            `json:"ip,omitempty"`
	DeviceID    string            `json:"deviceID,omitempty"`
	Endpoint    string            `json:"endpoint,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Logger struct
type Logger struct {
	writer         *bufio.Writer
	maxBufferSize  int
	maxLogFileSize int
	currentLogFile *os.File
	mu             sync.Mutex
}

// Rotate log file
func rotateLogFile(l *Logger) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Close current writer
	if err := l.writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush log before rotation: %v", err)
	}
	// Make new log file
	newLogFile, err := os.OpenFile(filepath.Join(filepath.Dir(l.currentLogFile.Name()), fmt.Sprintf("audit_%s.log", time.Now().Format("2006-01-02_15-04-05")))+".txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create new log file: %v", err)
	}
	l.writer = bufio.NewWriter(newLogFile)
	return nil
}

// Make a new logger for the script
func NewLogger(w io.Writer, maxBufferSize int, maxLogFileSize int, currLogFile *os.File) *Logger {
	return &Logger{bufio.NewWriter(w), maxBufferSize, maxLogFileSize, currLogFile, sync.Mutex{}}
}

func escapeField(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", " ")
	return s
}

func (l *Logger) LogEvent(event AuditEvent, flush bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	event.Timestamp = time.Now().Unix()

	// marshal metadata safely or fallback to empty object on error
	metaJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	logLine := fmt.Sprintf(
		`{"timestamp": %d, "username": "%s", "deviceID": "%s", "fingerprint": "%s", "action": "%s", "outcome": "%s", "endpoint": "%s", "metadata": %s}`+"\n",
		event.Timestamp,
		escapeField(event.Username),
		escapeField(event.DeviceID),
		escapeField(event.Fingerprint),
		escapeField(string(event.Action)),
		escapeField(string(event.Outcome)),
		escapeField(event.Endpoint),
		string(metaJSON),
	)

	if _, err := l.writer.WriteString(logLine); err != nil {
		// fallback to unescaped logging on write error
		logLine := fmt.Sprintf(
			`{"timestamp": %d, "username": "%s", "deviceID": "%s", "fingerprint": "%s", "action": "%s", "outcome": "%s", "endpoint": "%s", "metadata": %s}`+"\n",
			event.Timestamp,
			event.Username,
			event.DeviceID,
			event.Fingerprint,
			string(event.Action),
			string(event.Outcome),
			event.Endpoint,
			string(metaJSON),
		)
		if _, err := l.writer.WriteString(logLine); err != nil {
			logLine := fmt.Sprintf("FATAL LOG WRITE ERROR, LOG LOST %v\n", err)
			if _, err := l.writer.WriteString(logLine); err != nil {
				fmt.Fprintf(os.Stderr, "logger fatal write error: %v\n", err)
			}
		}
	}

	if flush || l.writer.Buffered() > l.maxBufferSize {
		if err := l.writer.Flush(); err != nil {
			fmt.Fprintf(os.Stderr, "logger flush error: %v\n", err)
		}
	}
}

func (l *Logger) checkFlush() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.writer.Buffered() > l.maxBufferSize {
		if err := l.writer.Flush(); err != nil {
			fmt.Fprintf(os.Stderr, "logger checkFlush error: %v\n", err)
		}
		return true
	}
	return false
}

func (l *Logger) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.writer.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "logger flush error: %v\n", err)
	}
	info, err := l.currentLogFile.Stat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger stat error: %v\n", err)
		fmt.Fprintf(os.Stderr, "logger flush error: %v\n", err)
		return
	}
	size := info.Size()
	if size > int64(l.maxLogFileSize) {
		if err := rotateLogFile(l); err != nil {
			fmt.Fprintf(os.Stderr, "logger rotate log file error: %v\n", err)
		}
	}
}

// ~~~~ Pre build audit logs ~~~~
func systemAuditEvent(action Action, outcome Outcome, err error, note ...string) AuditEvent {
	metadata := map[string]string{}
	if err != nil {
		metadata["error"] = err.Error()
	}
	if len(note) > 0 {
		metadata["note"] = note[0]
	}
	event := AuditEvent{
		Action:      action,
		Outcome:     outcome,
		Username:    "System",
		Fingerprint: "System",
		DeviceID:    "System",
		Metadata:    metadata,
	}

	return event
}

func jsonUnmarshalAuditEvent(outcome Outcome, err error, note ...string) AuditEvent {
	metadata := map[string]string{}
	if err != nil {
		metadata["error"] = err.Error()
	}
	if len(note) > 0 {
		metadata["note"] = note[0]
	}
	event := AuditEvent{
		Action:      Actions.LOAD_DATA,
		Outcome:     outcome,
		Username:    "System",
		DeviceID:    "System",
		Fingerprint: "System",
		Metadata:    metadata,
	}

	return event
}

func caCertLoadAuditEvent(outcome Outcome, err error) AuditEvent {
	metadata := map[string]string{}
	if err != nil {
		metadata["error"] = err.Error()
	}
	event := AuditEvent{
		Action:      Actions.MTLS_STARTUP,
		Outcome:     outcome,
		Username:    "System",
		DeviceID:    "System",
		Fingerprint: "System",
		Metadata:    metadata,
	}

	return event
}

func certMissingAuditEvent(r *http.Request) AuditEvent {
	metadata := map[string]string{
		"requestMethod": r.Method,
		"requestURL":    r.URL.String(),
		"userAgent":     r.UserAgent(),
		"note":          "ATTEMPTED ACCESS WITHOUT CERTIFICATE",
	}

	event := AuditEvent{
		Action:      Actions.MTLS_HANDSHAKE,
		Outcome:     Outcomes.NO_CERT,
		Username:    "Unknown",
		Fingerprint: "Unknown",
		Endpoint:    r.URL.Path,
		Metadata:    metadata,
	}

	return event
}

func certMismatchAuditEvent(username string, fingerprint string, r *http.Request) AuditEvent {
	metadata := map[string]string{
		"requestMethod": r.Method,
		"requestURL":    r.URL.String(),
		"userAgent":     r.UserAgent(),
	}
	event := AuditEvent{
		Action:      Actions.MTLS_HANDSHAKE,
		Outcome:     Outcomes.CERT_MISMATCH,
		Username:    username,
		Fingerprint: fingerprint,
		Endpoint:    r.URL.Path,
		Metadata:    metadata,
	}

	return event
}

func sessionCreationAuditEvent(outcome Outcome, username string, fingerprint string, endpoint string, err error) AuditEvent {
	metadata := map[string]string{}
	if err != nil {
		metadata["error"] = err.Error()
	}
	event := AuditEvent{
		Action:      Actions.CREATE_SESSION,
		Outcome:     outcome,
		Username:    username,
		Fingerprint: fingerprint,
		Endpoint:    endpoint,
		Metadata:    metadata,
	}

	return event
}

func sessionExpiryAuditEvent(username string, fingerprint string, sessionID string) AuditEvent {
	event := AuditEvent{
		Action:      Actions.SESSION_EXPIRY,
		Outcome:     Outcomes.SUCCESS,
		Username:    "System",
		Fingerprint: fingerprint,
		Metadata: map[string]string{
			"sessionID":          sessionID,
			"sessionUser":        username,
			"sessionFingerprint": fingerprint,
		},
	}

	return event
}

func missingSessionAuditEvent(username string, fingerprint string, r *http.Request, err error, note ...string) AuditEvent {
	metadata := map[string]string{
		"requestMethod": r.Method,
		"requestURL":    r.URL.String(),
		"userAgent":     r.UserAgent(),
	}
	if len(note) > 0 {
		metadata["note"] = note[0]
	}
	if err != nil {
		metadata["error"] = err.Error()
	}
	event := AuditEvent{
		Action:      Actions.VALIDATE_SESSION,
		Outcome:     Outcomes.NO_SESSION,
		Username:    username,
		Fingerprint: fingerprint,
		Endpoint:    r.URL.Path,
		Metadata:    metadata,
	}

	return event
}

func missingCookieAuditEvent(username string, fingerprint string, r *http.Request, err error) AuditEvent {
	metadata := map[string]string{
		"requestMethod": r.Method,
		"requestURL":    r.URL.String(),
		"userAgent":     r.UserAgent(),
	}
	if err != nil {
		metadata["error"] = err.Error()
	}
	event := AuditEvent{
		Action:      Actions.VALIDATE_SESSION,
		Outcome:     Outcomes.NO_COOKIE,
		Username:    username,
		Fingerprint: fingerprint,
		Endpoint:    r.URL.Path,
		Metadata:    metadata,
	}

	return event
}

func createCookieAuditEvent(username string, fingerprint string, r *http.Request) AuditEvent {
	metadata := map[string]string{
		"requestMethod": r.Method,
		"requestURL":    r.URL.String(),
		"userAgent":     r.UserAgent(),
	}
	event := AuditEvent{
		Action:      Actions.CREATE_COOKIE,
		Outcome:     Outcomes.SUCCESS,
		Username:    username,
		Fingerprint: fingerprint,
		Endpoint:    r.URL.Path,
		Metadata:    metadata,
	}

	return event
}

func loginAuditEvent(username string, outcome Outcome, fingerprint string, r *http.Request, err error, note ...string) AuditEvent {
	metadata := map[string]string{
		"requestMethod": r.Method,
		"requestURL":    r.URL.String(),
		"userAgent":     r.UserAgent(),
	}
	if err != nil {
		metadata["error"] = err.Error()
	}
	if len(note) > 0 {
		metadata["note"] = note[0]
	}

	event := AuditEvent{
		Action:      Actions.SUBMIT_LOGIN,
		Outcome:     outcome,
		Username:    username,
		Fingerprint: fingerprint,
		Endpoint:    r.URL.Path,
		Metadata:    metadata,
	}

	return event
}

func enrollmentAuditEvent(username string, deviceName string, outcome Outcome, r *http.Request, err error, note ...string) AuditEvent {
	metadata := map[string]string{
		"requestMethod": r.Method,
		"requestURL":    r.URL.String(),
		"userAgent":     r.UserAgent(),
		"deviceName":    deviceName,
	}
	if err != nil {
		metadata["error"] = err.Error()
	}
	if len(note) > 0 {
		metadata["note"] = note[0]
	}

	event := AuditEvent{
		Action:      Actions.SUBMIT_ENROLLMENT,
		Outcome:     outcome,
		Username:    username,
		Fingerprint: "Unknown",
		Endpoint:    r.URL.Path,
		Metadata:    metadata,
	}

	return event
}

func approveEnrollmentAuditEvent(username string, deviceName string, fingerprint string, outcome Outcome, r *http.Request, err error, note ...string) AuditEvent {
	metadata := map[string]string{
		"requestMethod": r.Method,
		"requestURL":    r.URL.String(),
		"userAgent":     r.UserAgent(),
		"deviceName":    deviceName,
	}
	if err != nil {
		metadata["error"] = err.Error()
	}
	if len(note) > 0 {
		metadata["note"] = note[0]
	}

	event := AuditEvent{
		Action:      Actions.APPROVE_ENROLLMENT,
		Outcome:     outcome,
		Username:    username,
		Fingerprint: fingerprint,
		Endpoint:    r.URL.Path,
		Metadata:    metadata,
	}
	return event
}

func rejectEnrollmentAuditEvent(username string, deviceName string, outcome Outcome, r *http.Request, err error, note ...string) AuditEvent {
	metadata := map[string]string{
		"requestMethod": r.Method,
		"requestURL":    r.URL.String(),
		"userAgent":     r.UserAgent(),
		"deviceName":    deviceName,
	}
	if err != nil {
		metadata["error"] = err.Error()
	}
	if len(note) > 0 {
		metadata["note"] = note[0]
	}

	event := AuditEvent{
		Action:      Actions.REJECT_ENROLLMENT,
		Outcome:     outcome,
		Username:    username,
		Fingerprint: "Unknown",
		Endpoint:    r.URL.Path,
		Metadata:    metadata,
	}
	return event
}

func endpointPermissionAuditEvent(outcome Outcome, username string, fingerprint string, r *http.Request) AuditEvent {
	metadata := map[string]string{
		"requestMethod": r.Method,
		"requestURL":    r.URL.String(),
		"userAgent":     r.UserAgent(),
	}
	event := AuditEvent{
		Action:      Actions.NAVIGATE_ENDPOINT,
		Outcome:     outcome,
		Username:    username,
		Fingerprint: fingerprint,
		Endpoint:    r.URL.Path,
		Metadata:    metadata,
	}

	return event
}

func rateLimitAuditEvent(outcome Outcome, ip string, fingerprint string, r *http.Request) AuditEvent {
	metadata := map[string]string{
		"requestMethod": r.Method,
		"requestURL":    r.URL.String(),
		"userAgent":     r.UserAgent(),
	}
	event := AuditEvent{
		Action:      Actions.CHECK_RATE_LIMIT,
		Outcome:     Outcomes.RATE_LIMITED,
		IP:          ip,
		Fingerprint: fingerprint,
		Endpoint:    r.URL.Path,
		Metadata:    metadata,
	}

	return event
}

func deviceRevokeAuditEvent(outcome Outcome, username string, fingerprint string, deviceID string, r *http.Request, err error, note ...string) AuditEvent {
	metadata := map[string]string{
		"requestMethod": r.Method,
		"requestURL":    r.URL.String(),
		"userAgent":     r.UserAgent(),
	}
	if err != nil {
		metadata["error"] = err.Error()
	}
	if len(note) > 0 {
		metadata["note"] = note[0]
	}

	event := AuditEvent{
		Action:      Actions.EDIT_SESSION,
		Outcome:     outcome,
		Username:    username,
		Fingerprint: fingerprint,
		DeviceID:    deviceID,
		Endpoint:    r.URL.Path,
		Metadata:    metadata,
	}

	return event
}

func userDeleteAuditEvent(outcome Outcome, username string, fingerprint string, deletedUsername string, r *http.Request, err error, note ...string) AuditEvent {
	metadata := map[string]string{
		"requestMethod":   r.Method,
		"requestURL":      r.URL.String(),
		"userAgent":       r.UserAgent(),
		"deletedUsername": deletedUsername,
	}
	if err != nil {
		metadata["error"] = err.Error()
	}
	if len(note) > 0 {
		metadata["note"] = note[0]
	}

	event := AuditEvent{
		Action:      Actions.EDIT_SESSION,
		Outcome:     outcome,
		Username:    username,
		Fingerprint: fingerprint,
		Endpoint:    r.URL.Path,
		Metadata:    metadata,
	}

	return event
}
