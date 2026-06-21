<!-- Banner Divider -->
<img align="center" src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

<!-- Project Name -->
<div align="center">
  <h1><code>zero-trust-mtls-server</code></h1>
  <h3>Version 1.0</h3>
</div>

<!-- Typing Banner -->
<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&pause=1000&color=3B82F6&center=true&vCenter=true&width=600&lines=Mutual-TLS+zero-trust+authentication" />
</p>

<p align="center">
  <img src="https://img.shields.io/github/license/powplowdevs/zero-trust-mtls-server?style=flat-square" />
  <img src="https://img.shields.io/github/stars/powplowdevs/zero-trust-mtls-server?style=flat-square" />
  <img src="https://img.shields.io/github/issues/powplowdevs/zero-trust-mtls-server?style=flat-square" />
  <img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white" />
</p>

---

## 📌 What is this?

A **mutual-TLS (mTLS) authentication server** written in Go, built as a portfolio and learning project.

Every user authenticates with a client certificate that the server cryptographically verifies, instead of relying on a password or token alone. It runs as a single Go binary with a small web UI, and a setup wizard that gets you from a fresh clone to a running server in a few commands.

---

## ✨ What it can do

- **Certificate-based login** — users authenticate with a CA-signed client certificate plus a password.
- **Device enrollment** — users generate a key and CSR, submit a request, and an admin approves and signs it. The private key never leaves the user's machine.
- **Permission-based access** — granular permissions (`system_admin`, `manage_devices`, `manage_users`, `manage_pending`, `view_audit_logs`) gate every page and endpoint.
- **Instant device revocation** — revoke a device with one toggle and it's denied on its next request.
- **User & device management** — review and remove users and devices from the browser.
- **Audit logging** — every login and access event is logged as structured JSON, with a built-in filterable, color-coded log viewer.

---

## ⚙️ How a request flows

The client certificate is the identity anchor. Everything is derived from it on every request:

```
client certificate  ──►  SHA256 fingerprint  ──►  device  ──►  owner  ──►  permissions
```

**Logging in:**

1. The browser presents a client certificate during the TLS handshake. If it isn't signed by the server's CA, the connection is refused so unenrolled clients can't get in at all.
2. The server hashes the certificate into a fingerprint and looks it up to find the device, its owner, and that user's permissions.
3. The user submits their password. The server checks it **and** checks that the certificate belongs to the same user, so a valid certificate can't be used to log in as someone else.
4. On success, a session is created server side. The session stores the certificate's fingerprint, and the browser gets only a random session ID in a cookie.

**Every request after that:**

1. The server recomputes the fingerprint from the certificate presented on *this* request and confirms it matches the one bound to the session. A stolen cookie is useless without the matching certificate and key.
2. Permissions are looked up fresh from the certificate every time, never cached in the session.

Because authorization is re-derived from the live certificate on every request, **revoking a device takes effect immediately**, the fingerprint stops resolving, and the next request is denied with no sessions to clear.

---

## 📦 Setup

> **Requirements:** [Go 1.22+](https://go.dev/dl/). Run all commands from the **project root** (the folder containing `data/`, `certs/`, and `static/`).

### 1. Clone

```bash
git clone https://github.com/powplowdevs/zero-trust-mtls-server.git
cd zero-trust-mtls-server
```

### 2. Run the setup wizard

The wizard will handle creating a first admin and its certificates along with the Certificate Authority and the server's own TLS certificate.

```bash
go build -o setup ./setup
./setup
```

The wizard will:

1. **Generate a Certificate Authority** (`certs/ca.crt` + `certs/ca.key`), the root of trust for every certificate. *(Re-running reuses the existing CA by default; pass `--new-ca` to regenerate, which invalidates all existing certificates.)*
2. **Generate the server's TLS certificate**, automatically valid for `localhost`, `127.0.0.1`, and your machine's detected LAN IP.
3. **Create the first admin account**, prompts for a device name and password (minimum 8 characters, with at least one uppercase letter and one number).

It writes the admin's certificate bundle to **`certs/admin.p12`** and prints import instructions.

### 3. Import the admin certificate into your browser

The admin (and every user) logs in with a certificate held by their browser. Import `certs/admin.p12`:

- **Firefox:** Settings → Privacy & Security → Certificates → *View Certificates* → *Your Certificates* → *Import* → select `certs/admin.p12`
- **Chrome / Edge:** Settings → Privacy and security → Security → *Manage certificates* → *Import* → select `certs/admin.p12`

> The `.p12` has an empty export password for convenience. After importing, you can delete `certs/admin.crt` and `certs/admin.p12` from the server, keep `certs/admin.key` private and never commit it.

### 4. Configure email (for certificate delivery)

When an admin approves an enrollment, the signed certificate is **emailed** to the user. Set your SMTP details in `config.json`:

```jsonc
{
  "smtp_host":     "smtp.gmail.com",        // your SMTP server
  "smtp_port":     "587",                   // typically 587 (TLS) or 465 (SSL)
  "smtp_username": "you@example.com",       // the sending account
  "smtp_password": "your-app-password"      // see note below
}
```

> **Use an App Password, not your real password.** Most providers (Gmail included) won't accept your normal account password for SMTP. Enable 2-factor authentication on the account, generate a dedicated **App Password**, and use that as `smtp_password`.

You can skip this for local testing, but enrollment approvals won't be able to deliver certificates until SMTP is configured.

### 5. Build and run the server

```bash
go build -o zts .
./zts
```

The server starts on `https://localhost:8443`. Open it, present the admin certificate when prompted, and log in as `admin` with the password you set.

### 6. Enroll more users

Once you're logged in as admin, other users enroll through the web UI:

1. They visit `/enroll`, follow the steps to generate a key and CSR, and submit the request.
2. You review it under **Pending**, grant permissions, and approve, the server signs their certificate and emails it.
3. They import their certificate and log in.

---
