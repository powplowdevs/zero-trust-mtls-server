// zero-trust-mtls-server — Standalone Admin Setup Wizard
//
// This is a SELF-CONTAINED program. It does NOT import the server package.
// Run it ONCE from the project root (the directory that contains ./data and ./certs)
// to bootstrap the first admin account, because the normal enrollment flow can't
// approve the very first user (no admin exists yet to approve them).
//
// Build:   go build -o setup ./setup
//          (place this file in a ./setup subfolder of your project — NOT next to main.go,
//           or it will collide with the server's package main)
// Run:     ./setup
//          (run from the project root — the folder containing ./data and ./certs)
//
// What it does:
//   1. Generates a CA (certs/ca.key + certs/ca.crt) if one doesn't exist (reuse by default).
//   2. Generates an admin key + certificate signed by that CA.
//   3. Writes/replaces the "admin" user in data/users.json and the admin device in
//      data/devices.json (only the admin records — other users are left untouched).
//   4. Bundles the admin cert+key and prints instructions to import + log in.
//
// IMPORTANT FOR DEVS: the fingerprint logic below (fingerprintFromCert) is copied VERBATIM from the
// server's getFingerprintFromCert. If you EVER change the server's version, change this too,
// or the admin's stored fingerprint won't match what the server computes and login will fail.

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ----- paths (relative to where you run the program — the project root) -----
const (
	certsDir    = "certs"
	dataDir     = "data"
	caCertPath  = "certs/ca.crt"
	caKeyPath   = "certs/ca.key"
	serverCert  = "certs/server.crt"
	serverKey   = "certs/server.key"
	usersPath   = "data/users.json"
	devicesPath = "data/devices.json"

	adminUsername = "admin"
	adminDeviceID = "admin-device-001"
)

// ----- structs: shape must match the server's models -----
type User struct {
	Username     string   `json:"username"`
	DisplayName  string   `json:"display_name"`
	PasswordHash string   `json:"password_hash"`
	Permissions  []string `json:"permissions"`
	Devices      []string `json:"devices"`
	CreatedAt    string   `json:"created_at"`
}

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

// ===== fingerprint — COPIED VERBATIM FROM SERVER. KEEP IN SYNC. =====
func fingerprintFromCert(cert *x509.Certificate) string {
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

func main() {
	fmt.Println("=====================================================")
	fmt.Println("  zero-trust-mtls-server — Admin Setup Wizard")
	fmt.Println("=====================================================")
	fmt.Println()

	// flags (very small, no flag package needed)
	newCA := false
	for _, a := range os.Args[1:] {
		if a == "--new-ca" {
			newCA = true
		}
		if a == "--help" || a == "-h" {
			fmt.Println("Usage: ./setup [--new-ca]")
			fmt.Println("  --new-ca   Force-regenerate the CA (DANGER: invalidates all existing certs).")
			fmt.Println("Run from the project root (the folder containing ./data and ./certs).")
			return
		}
	}

	reader := bufio.NewReader(os.Stdin)

	// Guard: this must be run from the PROJECT ROOT (the folder containing data/ and certs/),
	// not from inside the setup/ folder. Catch the most common mistake.
	if cwd, err := os.Getwd(); err == nil && filepath.Base(cwd) == "setup" {
		fatal("It looks like you're running this from the setup/ folder.\n" +
			"Run it from the project root instead (the folder that contains data/ and certs/):\n" +
			"    cd ..\n" +
			"    ./setup")
	}

	// sanity: make sure we're in the right place (data/ and certs/ are relative)
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		fatal("could not create certs/ directory: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		fatal("could not create data/ directory: %v", err)
	}

	// ---------- Step 1: CA ----------
	fmt.Println("Step 1: Certificate Authority")
	caExists := fileExists(caCertPath) && fileExists(caKeyPath)
	caRegenerated := false

	if caExists && !newCA {
		fmt.Printf("  Existing CA found at %s — reusing it.\n", caCertPath)
		fmt.Println("  (Run with --new-ca to regenerate, but that invalidates ALL existing certificates.)")
	} else {
		if caExists && newCA {
			fmt.Println("  --new-ca given. WARNING: regenerating the CA invalidates every existing certificate.")
			fmt.Print("  Type 'REGEN' to confirm: ")
			line, _ := reader.ReadString('\n')
			if strings.TrimSpace(line) != "REGEN" {
				fatal("aborted — CA not regenerated.")
			}
		}
		caName := prompt(reader, "  Name for the CA (Common Name)", "zero-trust-mtls-server-CA")
		fmt.Println("  Generating a new CA…")
		if err := generateCA(caName); err != nil {
			fatal("CA generation failed: %v", err)
		}
		caRegenerated = true
		fmt.Printf("  CA written to %s and %s\n", caCertPath, caKeyPath)
	}
	fmt.Println()

	// ---------- Step 2: Server certificate ----------
	fmt.Println("Step 2: Server certificate")
	serverExists := fileExists(serverCert) && fileExists(serverKey)
	makeServer := false
	if !serverExists {
		fmt.Println("  No server certificate found — one will be generated (the server needs it to start).")
		makeServer = true
	} else if caRegenerated {
		fmt.Println("  CA was regenerated, so the existing server cert no longer chains to it — regenerating.")
		makeServer = true
	} else {
		ans := prompt(reader, "  A server certificate already exists. Regenerate it? (y/N)", "N")
		if strings.EqualFold(strings.TrimSpace(ans), "y") {
			makeServer = true
		} else {
			fmt.Println("  Keeping the existing server certificate.")
		}
	}

	if makeServer {
		// auto-detect this machine's non-loopback IPs
		detected := detectIPs()
		sanList := []string{"localhost", "127.0.0.1"}
		sanList = append(sanList, detected...)
		if len(detected) > 0 {
			fmt.Printf("  Detected address(es): %s\n", strings.Join(detected, ", "))
		}
		fmt.Printf("  The server certificate will be valid for: %s\n", strings.Join(sanList, ", "))
		extra := prompt(reader, "  Add any other hostnames or IPs? (comma-separated, or blank to skip)", "")
		if strings.TrimSpace(extra) != "" {
			for _, e := range strings.Split(extra, ",") {
				e = strings.TrimSpace(e)
				if e != "" {
					sanList = append(sanList, e)
				}
			}
		}
		if err := generateServerCert(sanList); err != nil {
			fatal("server certificate generation failed: %v", err)
		}
		fmt.Printf("  Server certificate written to %s and %s\n", serverCert, serverKey)
	}
	fmt.Println()

	// ---------- Step 2: gather admin details ----------
	fmt.Println("Step 3: Admin account")
	deviceName := prompt(reader, "  Admin device name", "Admin-Laptop")

	var password string
	for {
		fmt.Print("  Admin password (visible as you type): ")
		line, _ := reader.ReadString('\n')
		password = strings.TrimSpace(line)
		// Same rule as the server's /enroll flow: >=8 chars, >=1 uppercase, >=1 digit.
		// KEEP IN SYNC with the server's password validation.
		if !passwordValid(password) {
			fmt.Println("  Password must be at least 8 characters and include an uppercase letter and a number. Try again.")
			continue
		}
		fmt.Print("  Confirm password: ")
		confirmLine, _ := reader.ReadString('\n')
		if strings.TrimSpace(confirmLine) != password {
			fmt.Println("  Passwords didn't match. Try again.")
			continue
		}
		break
	}
	fmt.Println()

	// ---------- Step 4: generate admin key + cert ----------
	fmt.Println("Step 4: Generating admin certificate…")

	adminKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fatal("generate admin key: %v", err)
	}

	// build a CSR with CN=admin (matches the server's CN==username rule)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: adminUsername},
	}, adminKey)
	if err != nil {
		fatal("create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// sign it with the CA (same logic as the server's signCSR)
	certPEM, fingerprint, notBefore, notAfter, err := signCSRWithCA(string(csrPEM))
	if err != nil {
		fatal("sign admin cert: %v", err)
	}

	// write the admin's private key + cert to disk so they can build a .p12
	adminKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: mustMarshalPKCS8(adminKey),
	})
	if err := os.WriteFile("certs/admin.key", adminKeyPEM, 0600); err != nil {
		fatal("write admin.key: %v", err)
	}
	if err := os.WriteFile("certs/admin.crt", certPEM, 0644); err != nil {
		fatal("write admin.crt: %v", err)
	}
	fmt.Printf("  Admin certificate generated. Fingerprint:\n  %s\n", fingerprint)
	fmt.Println()

	// ---------- Step 5: write JSON records (replace admin only) ----------
	fmt.Println("Step 5: Writing records…")

	if err := upsertAdminUser(password); err != nil {
		fatal("update users.json: %v", err)
	}
	if err := upsertAdminDevice(deviceName, fingerprint, notBefore, notAfter); err != nil {
		fatal("update devices.json: %v", err)
	}
	fmt.Printf("  Admin user written to %s\n", usersPath)
	fmt.Printf("  Admin device written to %s\n", devicesPath)
	fmt.Println()

	// ---------- Step 6: bundle .p12 + instructions ----------
	fmt.Println("Step 6: Bundle certificate for your browser")
	p12Made := tryMakeP12()

	printInstructions(p12Made, deviceName)
}

// ===== CA generation =====
func generateCA(commonName string) error {
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // CA valid 10 years
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}

	// write cert
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(caCertPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write ca.crt: %w", err)
	}

	// write key as PKCS8 (server reads it with ParsePKCS8PrivateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(caKey)})
	if err := os.WriteFile(caKeyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write ca.key: %w", err)
	}
	return nil
}

// ===== detect this machine's non-loopback IPv4 addresses =====
func detectIPs() []string {
	ips := []string{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue // skip IPv6 for simplicity
		}
		ips = append(ips, ip4.String())
	}
	return ips
}

// ===== generate the server's TLS cert (signed by the CA), valid for the given SANs =====
func generateServerCert(sans []string) error {
	// load CA
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("read ca.crt: %w", err)
	}
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse ca.crt: %w", err)
	}
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("read ca.key: %w", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse ca.key: %w", err)
	}

	// server keypair
	srvKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("serial: %w", err)
	}

	// split SANs into DNS names vs IP addresses
	var dnsNames []string
	var ipAddrs []net.IP
	cn := "localhost"
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsNames = append(dnsNames, s)
		}
	}
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0), // server cert valid 1 year
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, // SERVER auth (vs client for admin)
		DNSNames:     dnsNames,
		IPAddresses:  ipAddrs,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create server cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(serverCert, certPEM, 0644); err != nil {
		return fmt.Errorf("write server.crt: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(srvKey)})
	if err := os.WriteFile(serverKey, keyPEM, 0600); err != nil {
		return fmt.Errorf("write server.key: %w", err)
	}
	return nil
}

// ===== sign a CSR with the on-disk CA (mirrors server's signCSR) =====
func signCSRWithCA(csrPEM string) (certPEM []byte, fingerprint string, notBefore, notAfter time.Time, err error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, "", time.Time{}, time.Time{}, fmt.Errorf("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, "", time.Time{}, time.Time{}, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, "", time.Time{}, time.Time{}, fmt.Errorf("CSR signature invalid: %w", err)
	}

	// load CA
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, "", time.Time{}, time.Time{}, fmt.Errorf("read ca.crt: %w", err)
	}
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, "", time.Time{}, time.Time{}, fmt.Errorf("parse ca.crt: %w", err)
	}
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, "", time.Time{}, time.Time{}, fmt.Errorf("read ca.key: %w", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, "", time.Time{}, time.Time{}, fmt.Errorf("parse ca.key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", time.Time{}, time.Time{}, fmt.Errorf("serial: %w", err)
	}

	notBefore = time.Now()
	notAfter = time.Now().AddDate(1, 0, 0) // valid 1 year (matches server)

	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: csr.Subject.CommonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, "", time.Time{}, time.Time{}, fmt.Errorf("create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", time.Time{}, time.Time{}, fmt.Errorf("parse signed cert: %w", err)
	}

	fingerprint = fingerprintFromCert(cert)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certPEM, fingerprint, notBefore, notAfter, nil
}

// ===== users.json: replace admin, keep others =====
func upsertAdminUser(plainPassword string) error {
	users := []User{}
	if data, err := os.ReadFile(usersPath); err == nil && len(strings.TrimSpace(string(data))) > 0 {
		if err := json.Unmarshal(data, &users); err != nil {
			return fmt.Errorf("parse existing users.json: %w", err)
		}
	}

	// drop any existing admin (fresh slice — no aliasing of the original backing array)
	filtered := []User{}
	for _, u := range users {
		if u.Username != adminUsername {
			filtered = append(filtered, u)
		}
	}

	hash, err := bcryptHash(plainPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	filtered = append(filtered, User{
		Username:     adminUsername,
		DisplayName:  "Admin",
		PasswordHash: hash,
		Permissions:  []string{"system_admin"},
		Devices:      []string{adminDeviceID},
		CreatedAt:    time.Now().Format(time.RFC3339),
	})

	return writeJSON(usersPath, filtered)
}

// ===== devices.json: replace admin device, keep others =====
func upsertAdminDevice(deviceName, fingerprint string, notBefore, notAfter time.Time) error {
	devices := []Device{}
	if data, err := os.ReadFile(devicesPath); err == nil && len(strings.TrimSpace(string(data))) > 0 {
		if err := json.Unmarshal(data, &devices); err != nil {
			return fmt.Errorf("parse existing devices.json: %w", err)
		}
	}

	// drop any existing admin device (fresh slice — no aliasing)
	filtered := []Device{}
	for _, d := range devices {
		if d.DeviceID != adminDeviceID && d.OwnerUser != adminUsername {
			filtered = append(filtered, d)
		}
	}

	filtered = append(filtered, Device{
		DeviceID:        adminDeviceID,
		DeviceName:      deviceName,
		CertFingerprint: fingerprint,
		OwnerUser:       adminUsername,
		IssuedAt:        notBefore.Format(time.RFC3339),
		ExpiresAt:       notAfter.Format(time.RFC3339),
		Revoked:         false,
		LastSeen:        "",
	})

	return writeJSON(devicesPath, filtered)
}

// ===== try to build a .p12 via openssl if available =====
func tryMakeP12() bool {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		return false
	}
	// openssl pkcs12 -export -inkey certs/admin.key -in certs/admin.crt -out certs/admin.p12 -name "zero-trust-mtls-server-admin" -passout pass:
	cmd := exec.Command(openssl, "pkcs12", "-export",
		"-inkey", "certs/admin.key",
		"-in", "certs/admin.crt",
		"-out", "certs/admin.p12",
		"-name", "zero-trust-mtls-server-admin",
		"-passout", "pass:", // empty export password for convenience; change if you prefer
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// ===== final instructions =====
func printInstructions(p12Made bool, deviceName string) {
	abs, _ := filepath.Abs(".")
	fmt.Println("=====================================================")
	fmt.Println("  Setup complete!")
	fmt.Println("=====================================================")
	fmt.Println()
	fmt.Println("Admin account created:")
	fmt.Printf("  username:     %s\n", adminUsername)
	fmt.Printf("  device name:  %s\n", deviceName)
	fmt.Println()
	fmt.Println("Files written (in " + abs + "):")
	fmt.Println("  certs/admin.key   — the admin's PRIVATE key (keep it safe, never commit)")
	fmt.Println("  certs/admin.crt   — the admin's certificate")
	if p12Made {
		fmt.Println("  certs/admin.p12   — cert+key bundle ready to import (empty export password)")
	}
	fmt.Println()
	fmt.Println("Next steps:")
	if !p12Made {
		fmt.Println("  1. Bundle the cert + key into a .p12 (openssl was not found, so do this manually):")
		fmt.Println("       openssl pkcs12 -export -inkey certs/admin.key -in certs/admin.crt -out certs/admin.p12 -name \"zero-trust-mtls-server-admin\"")
		fmt.Println()
		fmt.Println("  2. Import certs/admin.p12 into your browser:")
	} else {
		fmt.Println("  1. Import certs/admin.p12 into your browser:")
	}
	fmt.Println("       Firefox: Settings -> Privacy & Security -> Certificates ->")
	fmt.Println("                View Certificates -> Your Certificates -> Import -> certs/admin.p12")
	fmt.Println("       Chrome/Edge: Settings -> Privacy and security -> Security ->")
	fmt.Println("                Manage certificates -> Import -> certs/admin.p12 (uses your OS cert store)")
	fmt.Println()
	step := "2"
	if !p12Made {
		step = "3"
	}
	fmt.Printf("  %s. Start the server, open https://localhost:8443/login, present the admin\n", step)
	fmt.Println("     certificate when prompted, and log in with username 'admin' + your password.")
}

// ===== helpers =====
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func prompt(r *bufio.Reader, label, def string) string {
	fmt.Printf("%s [%s]: ", label, def)
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

// passwordValid mirrors the server's /enroll password rule EXACTLY:
// at least 8 characters, at least one uppercase letter, at least one digit.
// KEEP IN SYNC with the server's validation.
func passwordValid(p string) bool {
	return len(p) >= 8 &&
		strings.ContainsAny(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") &&
		strings.ContainsAny(p, "1234567890")
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func mustMarshalPKCS8(key any) []byte {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fatal("marshal PKCS8 key: %v", err)
	}
	return b
}

// bcryptHash hashes a password the same way the server does, so the server can verify it.
// Uses bcrypt.DefaultCost (10) — matches the $2a$10$ hashes the server produces.
func bcryptHash(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\nERROR: "+format+"\n", args...)
	os.Exit(1)
}

