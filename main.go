// ~~~~ Known issues ~~~~~
// 1. No mutex or locks around data file access, can lead to race conditions
// 2. No rate limiting on login attempts
// 3. Not much of an issue, but every log write does a file flush so buffer is pointless. Nice to have flush just in case though.

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ~~~~~ Logger setup ~~~~~
var logger *Logger
var auditLogFile *os.File
var shouldAutoFlush bool
var config *Config

// ~~~~~ Data stores ~~~~~
var sessionStore = &SessionStore{sessionsPath: getAbsPath("data/sessions.json")}
var deviceStore = &DeviceStore{devicesPath: getAbsPath("data/devices.json")}
var userStore = &UserStore{usersPath: getAbsPath("data/users.json")}
var rateLimiterStore = &rateLimiter{rateLimitPath: getAbsPath("data/rateLimits.json")}
var pendingStore = &PendingStore{pendingPath: getAbsPath("data/pending.json")}

// ~~~~~ constatns ~~~~~
var nameRegex = regexp.MustCompile(`^[a-zA-Z0-9]{3,32}$`)

// ~~~~~ Initialize func ~~~~~
func init() {
	// Load config
	var err error
	config, err = LoadConfig(getAbsPath("data/config.json"))
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	auditLogFile, err = os.OpenFile(getAbsPath(config.AuditLogPath), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening audit log file: %v", err)
	}
	logger = NewLogger(auditLogFile, config.MaxBufferSizeBytes, config.MaxLogFileSizeBytes, auditLogFile)
	shouldAutoFlush = config.LogAutoFlush
}

// Helpers
func getAbsPath(relPath string) string {
	basePath := os.Getenv("ZERO_TRUST_BASE_PATH")
	if basePath == "" {
		basePath = "."
	}
	return filepath.Join(basePath, relPath)
}

func writeJSON(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"message": message})
}

func readLogLines(path string, offset, limit int) ([]json.RawMessage, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}

	rawLines := strings.Split(strings.TrimSpace(string(data)), "\n")
	lines := []string{}
	for _, l := range rawLines {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	total := len(lines)

	out := []json.RawMessage{}
	start := total - 1 - offset
	for i := start; i >= 0 && len(out) < limit; i-- {
		out = append(out, json.RawMessage(lines[i]))
	}
	return out, total, nil
}

// ~~~~~Data loading functions~~~~~
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// ~~~~~mTLS helpers~~~~~
func getFingerprintFromCert(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	hexString := fmt.Sprintf("%x", hash)
	formatted := ""
	for i, r := range hexString {
		formatted += string(r)
		if i%2 == 1 && i < len(hexString)-1 {
			formatted += ":"
		}
	}
	return "SHA256:" + formatted
}

func getUserFromFingerprint(fingerprint string, devices []Device) string {
	if devices == nil {
		devices, _ = deviceStore.LoadDevices(true)
	}

	for _, device := range devices {
		if strings.EqualFold(device.CertFingerprint, fingerprint) && !device.Revoked {
			return device.OwnerUser
		}
	}
	return ""
}

func cookieToMetadata(cookie *http.Cookie) string {
	if cookie == nil {
		return "none"
	}

	var parts []string
	parts = append(parts, fmt.Sprintf("name=%s", cookie.Name))
	parts = append(parts, fmt.Sprintf("value=%s", cookie.Value))

	if cookie.Path != "" {
		parts = append(parts, fmt.Sprintf("path=%s", cookie.Path))
	}
	if cookie.Domain != "" {
		parts = append(parts, fmt.Sprintf("domain=%s", cookie.Domain))
	}
	if !cookie.Expires.IsZero() {
		parts = append(parts, fmt.Sprintf("expires=%s", cookie.Expires.Format(time.RFC3339)))
	}
	if cookie.MaxAge != 0 {
		parts = append(parts, fmt.Sprintf("max_age=%d", cookie.MaxAge))
	}
	if cookie.Secure {
		parts = append(parts, "secure=true")
	}
	if cookie.HttpOnly {
		parts = append(parts, "httponly=true")
	}
	if cookie.SameSite != 0 {
		parts = append(parts, fmt.Sprintf("samesite=%v", cookie.SameSite))
	}

	return strings.Join(parts, "; ")
}

func signCSR(csrPEM string) ([]byte, string, error) {
	//Parse the CSR
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, "", fmt.Errorf("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse CSR: %w", err)
	}
	// Verify
	if err := csr.CheckSignature(); err != nil {
		return nil, "", fmt.Errorf("CSR signature invalid: %w", err)
	}

	// Load CA
	caCertPEM, err := os.ReadFile(getAbsPath("certs/ca.crt"))
	if err != nil {
		return nil, "", fmt.Errorf("read ca.crt: %w", err)
	}
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse ca.crt: %w", err)
	}
	caKeyPEM, err := os.ReadFile(getAbsPath("certs/ca.key"))
	if err != nil {
		return nil, "", fmt.Errorf("read ca.key: %w", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse ca.key: %w", err)
	}

	// build cert template
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", fmt.Errorf("serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: csr.Subject.CommonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0), // valid 1 year
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Signing
	der, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		caCert,
		csr.PublicKey,
		caKey,
	)
	if err != nil {
		return nil, "", fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", fmt.Errorf("parse signed cert: %w", err)
	}
	fingerprint := getFingerprintFromCert(cert)

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	return certPEM, fingerprint, nil
}

func sendCertEmail(toEmail, username string, certPEM []byte) error {
	smtpHost := config.SMTPHost
	smtpPort := fmt.Sprintf("%d", config.SMTPPort)
	from := config.SMTPUsername
	password := config.SMTPPassword

	// Auth
	auth := smtp.PlainAuth("", from, password, smtpHost)

	// Build the email
	subject := "Your Zero Trust device certificate"
	body := fmt.Sprintf(
		"Hello %s,\r\n\r\nYour enrollment was approved. Your signed certificate is below.\r\n"+
			"Save it as client.crt and install it alongside your client.key.\r\n\r\n%s\r\n",
		username, string(certPEM),
	)

	msg := []byte(
		"From: " + from + "\r\n" +
			"To: " + toEmail + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"\r\n" +
			body,
	)

	// Send
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{toEmail}, msg)
	if err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	return nil
}

// ~~~~~Main function ~~~~~
func main() {
	defer func() {
		logger.Flush()
		auditLogFile.Close()
	}()

	// Startup msgs
	log.Println("Starting Zero Trust Server...")

	// Load CA cert
	caCert, err := os.ReadFile(getAbsPath("certs/ca.crt"))
	if err != nil {
		logger.LogEvent(caCertLoadAuditEvent(Outcomes.NO_CERT, err), shouldAutoFlush) //LOG
		log.Fatalf("Error reading CA certificate: %v", err)
	}
	logger.LogEvent(caCertLoadAuditEvent(Outcomes.SUCCESS, nil), shouldAutoFlush) //LOG

	// Create Cert Pool
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// TLS config
	cfg := tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	// Server setup
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", config.ServerPort),
		TLSConfig: &cfg,
	}

	// ~~~~~ Routing ~~~~~

	// Login page
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// Check for client cert
		if len(r.TLS.PeerCertificates) > 0 {
			logger.LogEvent(endpointPermissionAuditEvent(Outcomes.SUCCESS, getUserFromFingerprint(getFingerprintFromCert(r.TLS.PeerCertificates[0]), nil), getFingerprintFromCert(r.TLS.PeerCertificates[0]), r), shouldAutoFlush) //LOG

			if r.Method == http.MethodGet {
				// Serve login page UI
				http.ServeFile(w, r, getAbsPath("static/login.html"))
				return
			}

			if r.Method == http.MethodPost {
				cert := r.TLS.PeerCertificates[0]
				fingerprint := getFingerprintFromCert(cert)

				// Check rate limit
				ip, _, err := net.SplitHostPort(r.RemoteAddr)
				if err != nil {
					ip = r.RemoteAddr
				}
				isLimited, err := rateLimiterStore.isRateLimited(ip)
				if err != nil {
					logger.LogEvent(systemAuditEvent(Actions.CHECK_RATE_LIMIT, Outcomes.ERROR, err, fmt.Sprintf("Checking rate limit for IP %s", ip)), shouldAutoFlush) //LOG
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}
				if isLimited {
					logger.LogEvent(rateLimitAuditEvent(Outcomes.RATE_LIMITED, ip, getFingerprintFromCert(r.TLS.PeerCertificates[0]), r), shouldAutoFlush) //LOG
					http.Error(w, "Too many login attempts. Please try again later.", http.StatusTooManyRequests)                                          // TODO: replace with html popup
					return
				}

				// Obtain username and password input
				r.ParseForm()
				username := r.FormValue("username")
				password := r.FormValue("password")

				// Obtain hashed password for comparison
				users, _ := userStore.LoadUsers(true)
				devices, _ := deviceStore.LoadDevices(true)
				for _, user := range users {
					if user.Username == username {
						storedHashedPassword := user.PasswordHash
						err := bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(password))

						if err != nil {
							logger.LogEvent(loginAuditEvent(user.Username, Outcomes.INVALID_CREDENTIALS, getFingerprintFromCert(r.TLS.PeerCertificates[0]), r, err), shouldAutoFlush) //LOG
							rateLimiterStore.incrementRateLimit(ip, true)
							http.Error(w, "Invalid credentials", http.StatusUnauthorized)

							return // TODO show popup on UI
						} else {
							// Confirm creds belong to cert
							certOwner := getUserFromFingerprint(fingerprint, nil)

							if certOwner != username {
								logger.LogEvent(loginAuditEvent(user.Username, Outcomes.CERT_USER_MISMATCH, fingerprint, r, nil), shouldAutoFlush) //LOG
								http.Error(w, "Certificate does not match user", http.StatusForbidden)
								return
							}

							rateLimiterStore.resetRateLimit(ip, true)

							// Issue session
							session, err := sessionStore.createSession(user, fingerprint, time.Duration(config.SessionTimeoutSec)*time.Second)
							if err != nil {
								logger.LogEvent(sessionCreationAuditEvent(Outcomes.ERROR, user.Username, fingerprint, r.URL.Path, err), shouldAutoFlush) //LOG
								http.Error(w, fmt.Sprintf("Error creating session: %v", err), http.StatusInternalServerError)
								return
							}

							logger.LogEvent(sessionCreationAuditEvent(Outcomes.SUCCESS, user.Username, fingerprint, r.URL.Path, nil), shouldAutoFlush) //LOG

							// Save session to DB
							sessionStore.SaveSession(session)

							// Provide client with cookie
							cookie := http.Cookie{
								Name:     "session_id",
								Value:    session.ID,
								HttpOnly: true,
								Secure:   true,
								SameSite: http.SameSiteStrictMode,
								Expires:  session.ExpiresAt,
							}
							http.SetCookie(w, &cookie)

							logger.LogEvent(createCookieAuditEvent(user.Username, fingerprint, r), shouldAutoFlush)                 //LOG
							logger.LogEvent(loginAuditEvent(user.Username, Outcomes.SUCCESS, fingerprint, r, nil), shouldAutoFlush) //LOG

							if checkAdmin(fingerprint, devices, users) {
								http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
							} else {
								http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
							}
						}

						return
					}
				}

				// User not found
				rateLimiterStore.incrementRateLimit(ip, true)

				logger.LogEvent(loginAuditEvent(username, Outcomes.INVALID_CREDENTIALS, getFingerprintFromCert(r.TLS.PeerCertificates[0]), r, fmt.Errorf("user not found")), shouldAutoFlush) //LOG

				http.Error(w, "Invalid credentials", http.StatusUnauthorized)

				return // TODO show popup on UI
			}
		} else {
			// No certificate
			logger.LogEvent(certMissingAuditEvent(r), shouldAutoFlush) //LOG
			// TODO serve page saying cert required
			fmt.Fprintf(w, `
            <h1>Zero Trust System</h1>
            <p>You need a client certificate to access this system.</p>
            <a href="/enroll">Enroll New Device</a>
            `)

		}

	})

	// Logout page
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err == nil {
			sessionStore.deleteSession(cookie.Value, nil)
		}
		// expire the cookie client-side
		http.SetCookie(w, &http.Cookie{
			Name:   "session_id",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	// Self data enpoint
	http.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		if valid, err := sessionStore.validateSession(r, logger); !valid {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		fingerprint := getFingerprintFromCert(r.TLS.PeerCertificates[0])
		username := getUserFromFingerprint(fingerprint, nil)
		if username == "" {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		users, _ := userStore.LoadUsers(true)
		var DisplayName string
		var Permissions []string
		for _, user := range users {
			if user.Username == username {
				DisplayName = user.DisplayName
				Permissions = user.Permissions
				break
			}
		}

		devices, _ := deviceStore.LoadDevices(true)
		var userDevices []DeviceView
		for _, device := range devices {
			if device.OwnerUser == username && !device.Revoked {
				userDevices = append(userDevices, DeviceView{
					DeviceID:   device.DeviceID,
					DeviceName: device.DeviceName,
					IssuedAt:   device.IssuedAt,
					ExpiresAt:  device.ExpiresAt,
					LastSeen:   device.LastSeen,
				})
			}
		}

		meView := struct {
			Username    string       `json:"username"`
			DisplayName string       `json:"display_name"`
			Permissions []string     `json:"permissions"`
			Devices     []DeviceView `json:"devices"`
		}{
			Username:    username,
			DisplayName: DisplayName,
			Permissions: Permissions,
			Devices:     userDevices,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meView)
	})

	// Admin dashboard
	http.HandleFunc("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
		// Validate session
		if valid, err := sessionStore.validateSession(r, logger); !valid {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		fingerprint := getFingerprintFromCert(cert)

		if !checkAdmin(fingerprint, nil, nil) {
			logger.LogEvent(endpointPermissionAuditEvent(Outcomes.NO_PERMISSION, getUserFromFingerprint(fingerprint, nil), fingerprint, r), shouldAutoFlush) //LOG
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		logger.LogEvent(endpointPermissionAuditEvent(Outcomes.SUCCESS, getUserFromFingerprint(fingerprint, nil), fingerprint, r), shouldAutoFlush) //LOG

		if r.Method == http.MethodGet {
			http.ServeFile(w, r, getAbsPath("static/admin_dashboard.html"))
			return
		}

	})

	// User dashboard
	http.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		// Validate session
		if valid, err := sessionStore.validateSession(r, logger); !valid {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		fingerprint := getFingerprintFromCert(cert)

		logger.LogEvent(endpointPermissionAuditEvent(Outcomes.SUCCESS, getUserFromFingerprint(fingerprint, nil), fingerprint, r), shouldAutoFlush) //LOG

		if r.Method == http.MethodGet {
			http.ServeFile(w, r, getAbsPath("static/dashboard.html"))
			return
		}

	})

	// Pending requests dashboard
	http.HandleFunc("/pending", func(w http.ResponseWriter, r *http.Request) {
		// Validate session
		if valid, err := sessionStore.validateSession(r, logger); !valid {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		fingerprint := getFingerprintFromCert(cert)

		if !checkPermission(fingerprint, Permissions.ManagePending, nil, nil) {
			logger.LogEvent(endpointPermissionAuditEvent(Outcomes.NO_PERMISSION, getUserFromFingerprint(fingerprint, nil), fingerprint, r), shouldAutoFlush) //LOG
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		if r.Method == http.MethodGet {
			http.ServeFile(w, r, getAbsPath("static/pending.html"))
			return
		}

		if r.Method == http.MethodPost {
			r.ParseForm()
			action := r.FormValue("action")
			username := r.FormValue("username")
			devicename := r.FormValue("device_name")
			permissions := r.Form["permissions"]

			// Find the pending request for the given username
			req, err := pendingStore.findPending(username, devicename)
			if err != nil {
				writeJSON(w, http.StatusNotFound, "Pending request not found")
				return
			}

			if action == "approve" {
				// Sign their csr
				cert, fingerprint, err := signCSR(req.CSR)
				if err != nil {
					logger.LogEvent(enrollmentAuditEvent(username, req.DeviceName, Outcomes.ERROR, r, err), shouldAutoFlush) //LOG
					writeJSON(w, http.StatusInternalServerError, "Error signing certificate: "+err.Error())
					return
				}

				// Create device record
				newDevice := Device{
					DeviceID:        fmt.Sprintf("%s-%d", req.DeviceName, time.Now().Unix()),
					DeviceName:      req.DeviceName,
					CertFingerprint: fingerprint,
					OwnerUser:       req.Username,
					IssuedAt:        time.Now().Format(time.RFC3339),
					ExpiresAt:       time.Now().AddDate(1, 0, 0).Format(time.RFC3339),
					Revoked:         false,
				}

				// Create user record
				newUser := User{
					Username:     req.Username,
					DisplayName:  req.Username,
					PasswordHash: req.PasswordHash,
					Permissions:  permissions,
					Devices:      []string{newDevice.DeviceID},
					CreatedAt:    time.Now().Format(time.RFC3339),
				}

				// Add records to DB
				err = deviceStore.AddDevice(newDevice, true)
				if err != nil {
					logger.LogEvent(enrollmentAuditEvent(username, req.DeviceName, Outcomes.ERROR, r, err), shouldAutoFlush) //LOG
					writeJSON(w, http.StatusInternalServerError, "Error adding device: "+err.Error())
					return
				}
				err = userStore.AddUser(newUser, true)
				if err != nil {
					logger.LogEvent(enrollmentAuditEvent(username, req.DeviceName, Outcomes.ERROR, r, err), shouldAutoFlush) //LOG
					// Remove device
					deviceStore.RemoveDevice(newDevice.DeviceID, true)
					writeJSON(w, http.StatusInternalServerError, "Error adding user: "+err.Error())
					return
				}

				// Cleanup pending request
				err = pendingStore.RemovePending(username, req.DeviceName)
				if err != nil {
					logger.LogEvent(enrollmentAuditEvent(username, req.DeviceName, Outcomes.ERROR, r, err), shouldAutoFlush) //LOG
					deviceStore.RemoveDevice(newDevice.DeviceID, true)
					userStore.RemoveUser(newUser.Username, true)
					writeJSON(w, http.StatusInternalServerError, "Error removing pending request: "+err.Error())
					return
				}

				if err := sendCertEmail(req.Email, req.Username, cert); err != nil {
					logger.LogEvent(enrollmentAuditEvent(username, req.DeviceName, Outcomes.ERROR, r, err, "cert email failed, NO ROLLBACK"), shouldAutoFlush)
					writeJSON(w, http.StatusOK, fmt.Sprintf("Approved %s's device %q — however certificate failed to be emailed.", req.Username, req.DeviceName))
				} else {
					writeJSON(w, http.StatusOK, fmt.Sprintf("Approved %s's device %q — certificate emailed.", req.Username, req.DeviceName))
				}

				logger.LogEvent(approveEnrollmentAuditEvent(username, req.DeviceName, fingerprint, Outcomes.SUCCESS, r, nil), shouldAutoFlush) //LOG

				return
			}

			if action == "reject" {
				// Just remove pending request
				err := pendingStore.RemovePending(username, req.DeviceName)
				if err != nil {
					logger.LogEvent(rejectEnrollmentAuditEvent(username, req.DeviceName, Outcomes.ERROR, r, err), shouldAutoFlush) //LOG
					writeJSON(w, http.StatusInternalServerError, "Error removing pending request: "+err.Error())
					return
				}

				logger.LogEvent(rejectEnrollmentAuditEvent(username, req.DeviceName, Outcomes.SUCCESS, r, nil), shouldAutoFlush) //LOG
				writeJSON(w, http.StatusOK, fmt.Sprintf("Rejected %s's request for %q.", username, req.DeviceName))
				return
			}

		}

	})

	// Pending list data endpoint
	http.HandleFunc("/pending/list", func(w http.ResponseWriter, r *http.Request) {
		if valid, err := sessionStore.validateSession(r, logger); !valid {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		fingerprint := getFingerprintFromCert(r.TLS.PeerCertificates[0])
		if !checkPermission(fingerprint, Permissions.ManagePending, nil, nil) {
			logger.LogEvent(endpointPermissionAuditEvent(Outcomes.NO_PERMISSION, getUserFromFingerprint(fingerprint, nil), fingerprint, r), shouldAutoFlush)
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		pending, err := pendingStore.loadPendingViews(true)
		if err != nil {
			http.Error(w, "Could not load pending requests", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(pending); err != nil {
			http.Error(w, "Could not encode pending requests", http.StatusInternalServerError)
			return
		}
	})

	// Enrollment page
	http.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.ServeFile(w, r, getAbsPath("static/enroll.html"))
			return
		}

		if r.Method == http.MethodPost {
			r.ParseForm()
			username := r.FormValue("username")
			password := r.FormValue("password")
			deviceName := r.FormValue("device_name")
			csr := r.FormValue("csr")
			email := r.FormValue("email")

			// validation
			if username == "" || password == "" || deviceName == "" || csr == "" || email == "" {
				http.Error(w, "All fields are required", http.StatusBadRequest)
				return
			}
			if _, err := mail.ParseAddress(email); err != nil {
				http.Error(w, "Invalid email address", http.StatusBadRequest)
				return
			}
			if !nameRegex.MatchString(username) || !nameRegex.MatchString(deviceName) {
				http.Error(w, "Username and device name must be 3-32 characters, letters and numbers only", http.StatusBadRequest)
				return
			}
			if len(password) < 8 || !strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") || !strings.ContainsAny(password, "1234567890") {
				http.Error(w, "Password must be at least 8 characters and include an uppercase letter and a number", http.StatusBadRequest)
				return
			}

			block, _ := pem.Decode([]byte(csr))
			if block == nil || block.Type != "CERTIFICATE REQUEST" {
				http.Error(w, "CSR is not valid PEM. Paste the full contents of client.csr, including the BEGIN/END lines.", http.StatusBadRequest)
				return
			}

			parsedCSR, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				http.Error(w, "CSR could not be parsed. Make sure you submitted client.csr (not client.key).", http.StatusBadRequest)
				return
			}

			if parsedCSR.Subject.CommonName != username {
				http.Error(w, "Username in CSR does not match submitted username. Make sure the value after /CN= matches your username.", http.StatusBadRequest)
				return
			}

			// Hash password instantly
			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				logger.LogEvent(enrollmentAuditEvent(username, deviceName, Outcomes.ERROR, r, err), shouldAutoFlush) //LOG
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			req := PendingRequest{
				Username:     username,
				PasswordHash: string(hash),
				DeviceName:   deviceName,
				CSR:          csr,
				Email:        email,
				SubmittedAt:  time.Now().Format(time.RFC3339),
				Status:       "pending",
			}

			// Save to file
			if err := pendingStore.AddPending(req); err != nil {
				logger.LogEvent(enrollmentAuditEvent(username, deviceName, Outcomes.ERROR, r, err), shouldAutoFlush) //LOG
				http.Error(w, "Could not save enrollment request", http.StatusInternalServerError)
				return
			}

			logger.LogEvent(enrollmentAuditEvent(username, deviceName, Outcomes.SUCCESS, r, nil, "enrollment request submitted"), shouldAutoFlush) //LOG

			fmt.Fprintf(w, `<h1>Request submitted</h1>
			<p>Your enrollment request for "%s" is pending admin approval.</p>`, deviceName) //TODO: nice popup
			return
		}
	})

	// Devices endpoint
	http.HandleFunc("/devices", func(w http.ResponseWriter, r *http.Request) {
		if valid, err := sessionStore.validateSession(r, logger); !valid {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		fingerprint := getFingerprintFromCert(cert)

		if !checkPermission(fingerprint, Permissions.ManageDevices, nil, nil) {
			logger.LogEvent(endpointPermissionAuditEvent(Outcomes.NO_PERMISSION, getUserFromFingerprint(fingerprint, nil), fingerprint, r), shouldAutoFlush) //LOG
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		if r.Method == http.MethodGet {
			http.ServeFile(w, r, getAbsPath("static/devices.html"))
			return
		}

		if r.Method == http.MethodPost {
			r.ParseForm()
			revoked := r.FormValue("revoked") == "true"
			deviceID := r.FormValue("device_id")

			device, err := deviceStore.getDeviceByID(deviceID, false)
			if err != nil {
				logger.LogEvent(deviceRevokeAuditEvent(Outcomes.ERROR, getUserFromFingerprint(fingerprint, nil), fingerprint, deviceID, r, err), shouldAutoFlush) //LOG
				http.Error(w, "Device not found", http.StatusNotFound)
				return
			}
			device.Revoked = revoked

			if revoked {
				err := deviceStore.EditDevice(deviceID, device, true)
				if err != nil {
					logger.LogEvent(deviceRevokeAuditEvent(Outcomes.ERROR, getUserFromFingerprint(fingerprint, nil), fingerprint, deviceID, r, err), shouldAutoFlush) //LOG
					writeJSON(w, http.StatusInternalServerError, "Device "+deviceID+" could not be revoked")
					return
				}

				logger.LogEvent(deviceRevokeAuditEvent(Outcomes.SUCCESS, getUserFromFingerprint(fingerprint, nil), fingerprint, deviceID, r, nil, "Device revoked"), shouldAutoFlush) //LOG
				writeJSON(w, http.StatusOK, "Device "+deviceID+" revoked successfully")
				return
			}

			if !revoked {
				err := deviceStore.EditDevice(deviceID, device, true)
				if err != nil {
					logger.LogEvent(deviceRevokeAuditEvent(Outcomes.ERROR, getUserFromFingerprint(fingerprint, nil), fingerprint, deviceID, r, err), shouldAutoFlush) //LOG
					writeJSON(w, http.StatusInternalServerError, "Device "+deviceID+" could not be unrevoked")
					return
				}

				logger.LogEvent(deviceRevokeAuditEvent(Outcomes.SUCCESS, getUserFromFingerprint(fingerprint, nil), fingerprint, deviceID, r, nil, "Device unrevoked"), shouldAutoFlush) //LOG
				writeJSON(w, http.StatusOK, "Device "+deviceID+" unrevoked successfully")
				return
			}
		}

	})

	// Device data endpoint
	http.HandleFunc("/devices/list", func(w http.ResponseWriter, r *http.Request) {
		if valid, err := sessionStore.validateSession(r, logger); !valid {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		fingerprint := getFingerprintFromCert(cert)

		if !checkPermission(fingerprint, Permissions.ManageDevices, nil, nil) {
			logger.LogEvent(endpointPermissionAuditEvent(Outcomes.NO_PERMISSION, getUserFromFingerprint(fingerprint, nil), fingerprint, r), shouldAutoFlush) //LOG
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		devices, err := deviceStore.LoadDevices(true)
		if err != nil {
			http.Error(w, "Could not load devices", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(devices); err != nil {
			http.Error(w, "Could not encode devices", http.StatusInternalServerError)
			return
		}
	})

	// Users endpoint
	http.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		if valid, err := sessionStore.validateSession(r, logger); !valid {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		fingerprint := getFingerprintFromCert(cert)

		if !checkPermission(fingerprint, Permissions.ManageUsers, nil, nil) {
			logger.LogEvent(endpointPermissionAuditEvent(Outcomes.NO_PERMISSION, getUserFromFingerprint(fingerprint, nil), fingerprint, r), shouldAutoFlush) //LOG
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		if r.Method == http.MethodGet {
			http.ServeFile(w, r, getAbsPath("static/users.html"))
			return
		}

		if r.Method == http.MethodPost {
			r.ParseForm()
			action := r.FormValue("action")
			username := r.FormValue("username")

			// Stop self deleting & validate actions
			if action != "delete" {
				writeJSON(w, http.StatusBadRequest, "Unknown action")
				return
			}
			if username == "" {
				writeJSON(w, http.StatusBadRequest, "Missing username")
				return
			}

			if username == getUserFromFingerprint(fingerprint, nil) {
				writeJSON(w, http.StatusForbidden, "You cannot delete your own account")
				return
			}

			err := userStore.PurgeUser(username, true)
			if err != nil {
				logger.LogEvent(userDeleteAuditEvent(Outcomes.ERROR, getUserFromFingerprint(fingerprint, nil), fingerprint, username, r, err), shouldAutoFlush) //LOG
				writeJSON(w, http.StatusInternalServerError, "Could not delete user "+username)
				return
			}

			logger.LogEvent(userDeleteAuditEvent(Outcomes.SUCCESS, getUserFromFingerprint(fingerprint, nil), fingerprint, username, r, nil, "User purged"), shouldAutoFlush) //LOG
			writeJSON(w, http.StatusOK, "User "+username+" deleted successfully")
			return
		}

	})

	// User data endpoint
	http.HandleFunc("/users/list", func(w http.ResponseWriter, r *http.Request) {
		if valid, err := sessionStore.validateSession(r, logger); !valid {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		fingerprint := getFingerprintFromCert(cert)

		if !checkPermission(fingerprint, Permissions.ManageUsers, nil, nil) {
			logger.LogEvent(endpointPermissionAuditEvent(Outcomes.NO_PERMISSION, getUserFromFingerprint(fingerprint, nil), fingerprint, r), shouldAutoFlush) //LOG
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		users, err := userStore.loadUserViews(true)
		if err != nil {
			http.Error(w, "Could not load user views", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(users); err != nil {
			http.Error(w, "Could not encode user views", http.StatusInternalServerError)
			return
		}
	})

	// Logging endpoint
	http.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		if valid, err := sessionStore.validateSession(r, logger); !valid {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		fingerprint := getFingerprintFromCert(cert)

		if !checkPermission(fingerprint, Permissions.ViewAuditLogs, nil, nil) {
			logger.LogEvent(endpointPermissionAuditEvent(Outcomes.NO_PERMISSION, getUserFromFingerprint(fingerprint, nil), fingerprint, r), shouldAutoFlush) //LOG
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		if r.Method == http.MethodGet {
			http.ServeFile(w, r, getAbsPath("static/logs.html"))
			return
		}
	})

	// Audit log data endpoint
	http.HandleFunc("/logs/list", func(w http.ResponseWriter, r *http.Request) {
		if valid, err := sessionStore.validateSession(r, logger); !valid {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		fingerprint := getFingerprintFromCert(cert)

		if !checkPermission(fingerprint, Permissions.ViewAuditLogs, nil, nil) {
			logger.LogEvent(endpointPermissionAuditEvent(Outcomes.NO_PERMISSION, getUserFromFingerprint(fingerprint, nil), fingerprint, r), shouldAutoFlush) //LOG
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		logger.Flush()

		offset := 0
		if v := r.URL.Query().Get("offset"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				offset = n
			}
		}

		logPath := logger.currentLogFile.Name()

		lines, total, err := readLogLines(logPath, offset, 1000)
		if err != nil {
			http.Error(w, "Could not read logs", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"lines": lines,
			"total": total,
		}); err != nil {
			http.Error(w, "Could not encode logs", http.StatusInternalServerError)
			return
		}
	})

	// start server
	log.Println("Server listening on https://localhost:8443")
	log.Fatal(server.ListenAndServeTLS(
		getAbsPath("certs/server.crt"),
		getAbsPath("certs/server.key"),
	))
}
