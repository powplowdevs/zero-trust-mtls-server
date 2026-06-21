package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Rate limter
func (rl *rateLimiter) LoadRateLimits(safety bool) (map[string]rateLimit, error) {
	if safety {
		rl.mutex.Lock()
		defer rl.mutex.Unlock()
	}

	data, err := os.ReadFile(getAbsPath(rl.rateLimitPath))
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.LOAD_DATA, Outcomes.ERROR, err, "Loaded rateLimits.json"), shouldAutoFlush) //LOG
		return nil, err
	}

	var rateLimits map[string]rateLimit
	err = json.Unmarshal(data, &rateLimits)
	if err != nil {
		logger.LogEvent(jsonUnmarshalAuditEvent(Outcomes.ERROR, err, "Loading rateLimits.json"), shouldAutoFlush) //LOG
		return nil, err
	}

	logger.LogEvent(systemAuditEvent(Actions.LOAD_DATA, Outcomes.SUCCESS, nil, "Loaded rateLimits.json"), shouldAutoFlush) //LOG
	return rateLimits, nil
}

func (rl *rateLimiter) incrementRateLimit(ip string, safety bool) error {
	if safety {
		rl.mutex.Lock()
		defer rl.mutex.Unlock()
	}

	rateLimits, err := rl.LoadRateLimits(false)
	if err != nil {
		return err
	}

	now := time.Now()
	requestCount := 1
	WindowStart := now.Unix()
	if limit, ok := rateLimits[ip]; ok {
		WindowStart = limit.WindowStart
		requestCount = limit.RequestCount + 1
	}

	rateLimits[ip] = rateLimit{
		WindowStart:  WindowStart,
		LastAttempt:  now.Unix(),
		RequestCount: requestCount,
	}

	data, err := json.MarshalIndent(rateLimits, "", "  ")
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.ERROR, err, "Saving rate limits"), shouldAutoFlush) //LOG
		return err
	}
	logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.SUCCESS, nil, "Saving rate limits"), shouldAutoFlush) //LOG
	return os.WriteFile(getAbsPath(rl.rateLimitPath), data, 0644)
}

func (rl *rateLimiter) resetRateLimit(ip string, safety bool) error {
	if safety {
		rl.mutex.Lock()
		defer rl.mutex.Unlock()
	}

	rateLimits, err := rl.LoadRateLimits(false)
	if err != nil {
		return err
	}

	delete(rateLimits, ip)

	data, err := json.MarshalIndent(rateLimits, "", "  ")
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.ERROR, err, "Saving rate limits"), shouldAutoFlush) //LOG
		return err
	}
	logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.SUCCESS, nil, "Saving rate limits"), shouldAutoFlush) //LOG
	return os.WriteFile(getAbsPath(rl.rateLimitPath), data, 0644)
}

func (rl *rateLimiter) isRateLimited(ip string) (bool, error) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	rateLimits, err := rl.LoadRateLimits(false)
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.LOAD_DATA, Outcomes.ERROR, err, "Loading rate limits"), shouldAutoFlush) //LOG
		return false, err
	}

	if limit, ok := rateLimits[ip]; ok {
		if time.Now().Unix()-limit.WindowStart > int64(config.RateLimitWindowSeconds) {
			rl.resetRateLimit(ip, false)
			return false, nil
		}
		if limit.RequestCount >= config.MaxLoginAttempts {
			return true, nil
		}
	}

	return false, nil
}

// Devivce store
func (ds *DeviceStore) LoadDevices(safety bool) ([]Device, error) {
	if safety {
		ds.mutex.Lock()
		defer ds.mutex.Unlock()
	}

	data, err := os.ReadFile(getAbsPath(ds.devicesPath))
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.LOAD_DATA, Outcomes.ERROR, err, "Loaded devices.json"), shouldAutoFlush) //LOG
		return nil, err
	}

	var devices []Device
	err = json.Unmarshal(data, &devices)
	if err != nil {
		logger.LogEvent(jsonUnmarshalAuditEvent(Outcomes.ERROR, err, "Loading devices.json"), shouldAutoFlush) //LOG
		return nil, err
	}

	logger.LogEvent(systemAuditEvent(Actions.LOAD_DATA, Outcomes.SUCCESS, nil, "Loaded devices.json"), shouldAutoFlush) //LOG

	return devices, nil
}

func (ds *DeviceStore) AddDevice(device Device, safety bool) error {
	if safety {
		ds.mutex.Lock()
		defer ds.mutex.Unlock()
	}

	devices, err := ds.LoadDevices(!safety)
	if err != nil {
		return err
	}

	devices = append(devices, device)

	data, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.ERROR, err, "Saving devices"), shouldAutoFlush) //LOG
		return err
	}
	logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.SUCCESS, nil, "Saving devices"), shouldAutoFlush) //LOG
	return os.WriteFile(getAbsPath(ds.devicesPath), data, 0644)
}

func (ds *DeviceStore) RemoveDevice(deviceID string, safety bool) error {
	if safety {
		ds.mutex.Lock()
		defer ds.mutex.Unlock()
	}

	devices, err := ds.LoadDevices(false)
	if err != nil {
		return err
	}

	newDevices := []Device{}
	for _, device := range devices {
		if device.DeviceID != deviceID {
			newDevices = append(newDevices, device)
		}
	}

	data, err := json.MarshalIndent(newDevices, "", "  ")
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.ERROR, err, "Saving devices"), shouldAutoFlush) //LOG
		return err
	}
	logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.SUCCESS, nil, "Saving devices"), shouldAutoFlush) //LOG
	return os.WriteFile(getAbsPath(ds.devicesPath), data, 0644)
}

func (ds *DeviceStore) getDeviceByID(deviceID string, safety bool) (Device, error) {
	if safety {
		ds.mutex.Lock()
		defer ds.mutex.Unlock()
	}

	devices, err := ds.LoadDevices(false)
	if err != nil {
		return Device{}, err
	}

	for _, device := range devices {
		if device.DeviceID == deviceID {
			return device, nil
		}
	}

	return Device{}, fmt.Errorf("device with ID %s not found", deviceID)
}

func (ds *DeviceStore) EditDevice(deviceID string, updated Device, safety bool) error {
	if safety {
		ds.mutex.Lock()
		defer ds.mutex.Unlock()
	}

	found := false

	devices, err := ds.LoadDevices(!safety)
	if err != nil {
		return err
	}

	newDevices := []Device{}
	for _, device := range devices {
		if device.DeviceID == deviceID {
			newDevices = append(newDevices, updated)
			found = true
		} else {
			newDevices = append(newDevices, device)
		}
	}

	if !found {
		return fmt.Errorf("device with ID %s not found", deviceID)
	}

	data, err := json.MarshalIndent(newDevices, "", "  ")
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.ERROR, err, "Saving devices"), shouldAutoFlush) //LOG
		return err
	}
	logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.SUCCESS, nil, "Saving devices"), shouldAutoFlush) //LOG
	return os.WriteFile(getAbsPath(ds.devicesPath), data, 0644)
}

// user store
func (us *UserStore) LoadUsers(safety bool) ([]User, error) {
	if safety {
		us.mutex.Lock()
		defer us.mutex.Unlock()
	}

	data, err := os.ReadFile(getAbsPath(us.usersPath))
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.LOAD_DATA, Outcomes.ERROR, err, "Loaded users.json"), shouldAutoFlush) //LOG
		return nil, err
	}

	var users []User
	err = json.Unmarshal(data, &users)
	if err != nil {
		logger.LogEvent(jsonUnmarshalAuditEvent(Outcomes.ERROR, err, "Loading users.json"), shouldAutoFlush) //LOG
		return nil, err
	}

	logger.LogEvent(systemAuditEvent(Actions.LOAD_DATA, Outcomes.SUCCESS, nil, "Loaded users.json"), shouldAutoFlush) //LOG

	return users, nil

}

func (us *UserStore) loadUserViews(safety bool) ([]UserView, error) {
	if safety {
		us.mutex.Lock()
		defer us.mutex.Unlock()
	}

	users, err := us.LoadUsers(false)
	if err != nil {
		return nil, err
	}

	views := []UserView{}
	for _, user := range users {
		deviceNames := []string{}
		for _, deviceID := range user.Devices {
			device, err := deviceStore.getDeviceByID(deviceID, false)
			if err == nil {
				deviceNames = append(deviceNames, device.DeviceName)
			}
		}

		view := UserView{
			Username:    user.Username,
			DisplayName: user.DisplayName,
			Permissions: user.Permissions,
			Devices:     deviceNames,
			CreatedAt:   user.CreatedAt,
		}
		views = append(views, view)
	}

	return views, nil
}

func (us *UserStore) AddUser(user User, safety bool) error {
	if safety {
		us.mutex.Lock()
		defer us.mutex.Unlock()
	}

	users, err := us.LoadUsers(!safety)
	if err != nil {
		return err
	}

	// Check if user already exists
	for _, existingUser := range users {
		if existingUser.Username == user.Username {
			return nil // Only down side here is if later in flow add devices fails it will remove entire instance of the user
		}
	}

	users = append(users, user)

	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.ERROR, err, "Saving users"), shouldAutoFlush) //LOG
		return err
	}
	logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.SUCCESS, nil, "Saving users"), shouldAutoFlush) //LOG
	return os.WriteFile(getAbsPath(us.usersPath), data, 0644)
}

func (us *UserStore) RemoveUser(username string, safety bool) error {
	if safety {
		us.mutex.Lock()
		defer us.mutex.Unlock()
	}

	users, err := us.LoadUsers(false)
	if err != nil {
		return err
	}

	newUsers := []User{}
	for _, user := range users {
		if user.Username != username {
			newUsers = append(newUsers, user)
		}
	}

	data, err := json.MarshalIndent(newUsers, "", "  ")
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.ERROR, err, "Saving users"), shouldAutoFlush) //LOG
		return err
	}
	logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.SUCCESS, nil, "Saving users"), shouldAutoFlush) //LOG
	return os.WriteFile(getAbsPath(us.usersPath), data, 0644)
}

func (us *UserStore) PurgeUser(username string, safety bool) error {
	if safety {
		us.mutex.Lock()
		defer us.mutex.Unlock()
	}

	// First remove user's devices
	users, err := us.LoadUsers(false)
	if err != nil {
		return err
	}

	var userToPurge User
	found := false
	for _, user := range users {
		if user.Username == username {
			userToPurge = user
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("user not found")
	}
	fmt.Printf("users deivce list: %v\n", userToPurge.Devices)
	for _, deviceID := range userToPurge.Devices {
		err := deviceStore.RemoveDevice(deviceID, false)
		if err != nil {
			logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.ERROR, err, "Deleting device during user purge"), shouldAutoFlush) //LOG
			return err
		}
	}

	us.RemoveUser(username, false)

	return nil
}

// session store
func (ss *SessionStore) LoadSessions(safety bool) ([]Session, error) {
	if safety {
		ss.mutex.Lock()
		defer ss.mutex.Unlock()
	}

	data, err := os.ReadFile(getAbsPath(ss.sessionsPath))
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.LOAD_DATA, Outcomes.ERROR, err, "Loaded sessions.json"), shouldAutoFlush) //LOG
		return nil, err
	}

	var sessions []Session
	err = json.Unmarshal(data, &sessions)
	if err != nil {
		logger.LogEvent(jsonUnmarshalAuditEvent(Outcomes.ERROR, err, "Loading sessions.json"), shouldAutoFlush) //LOG
		return nil, err
	}

	logger.LogEvent(systemAuditEvent(Actions.LOAD_DATA, Outcomes.SUCCESS, nil, "Loaded sessions.json"), shouldAutoFlush) //LOG

	return sessions, nil
}

func (ss *SessionStore) SaveSessions(sessions []Session, safety bool) error {
	if safety {
		ss.mutex.Lock()
		defer ss.mutex.Unlock()
	}

	data, err := json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.LOAD_DATA, Outcomes.ERROR, err, "Loading sessions"), shouldAutoFlush) //LOG
		return err
	}
	logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.SUCCESS, nil, "Saving sessions"), shouldAutoFlush) //LOG
	return os.WriteFile(getAbsPath(ss.sessionsPath), data, 0644)
}

func (ss *SessionStore) SaveSession(session Session) error {
	ss.mutex.Lock()
	defer ss.mutex.Unlock()

	sessions, err := ss.LoadSessions(false)
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.ERROR, err), shouldAutoFlush) //LOG
		return err
	}
	sessions = append(sessions, session)
	return ss.SaveSessions(sessions, false)
}

func (ss *SessionStore) createSession(usr User, fingerprint string, sessionLength time.Duration) (Session, error) {
	var session Session
	// Generate session ID
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	if err != nil {
		return Session{}, fmt.Errorf("random read: %w", err)
	}

	base64String := base64.URLEncoding.EncodeToString(randBytes)
	session.ID = base64String

	// Fill session struct
	session.Username = usr.Username
	session.CertFingerprint = fingerprint
	session.ExpiresAt = time.Now().Add(sessionLength)
	//fmt.Println("Session will expire at:", session.ExpiresAt.String(), " we got that value from adding ", sessionLength, " to current time ", time.Now().String())

	return session, nil
}

func (ss *SessionStore) getSession(sessionID string, fingerprint string, sessions []Session) (Session, error) {
	if sessions == nil {
		sessions, _ = ss.LoadSessions(true)
	}

	for _, session := range sessions {
		//fmt.Printf("Saved fingerprint is %s, Given fingerprint is: %s\nGiven session ID is: %s, Saved session ID is: %s\n", session.CertFingerprint, fingerprint, sessionID, session.ID)
		if session.CertFingerprint == fingerprint && session.ID == sessionID {
			return session, nil
		}
	}
	return Session{}, fmt.Errorf("Session not found in server DB")
}

func (ss *SessionStore) deleteSession(id string, sessions []Session) error {
	ss.mutex.Lock()
	defer ss.mutex.Unlock()

	if sessions == nil {
		sessions, _ = ss.LoadSessions(false)
	}

	currentSessions := []Session{}
	found := false

	for _, session := range sessions {
		if session.ID != id {
			currentSessions = append(currentSessions, session)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("session not found")
	} else {
		ss.SaveSessions(currentSessions, false)
		return nil
	}
}

func (ss *SessionStore) cleanupExpiredSessions() {
	ss.mutex.Lock()
	defer ss.mutex.Unlock()

	sessions, _ := ss.LoadSessions(false)
	newSessions := []Session{}

	for _, session := range sessions {
		if time.Now().After(session.ExpiresAt) {
			logger.LogEvent(sessionExpiryAuditEvent(session.Username, session.CertFingerprint, session.ID), shouldAutoFlush) //LOG
			log.Printf("Session for user %s expired, removing\n session timeout was: %s and current time is: %s", session.Username, session.ExpiresAt, time.Now().String())
		} else {
			newSessions = append(newSessions, session)
		}
	}
	ss.SaveSessions(newSessions, false)
}

func (ss *SessionStore) validateSession(r *http.Request, logger *Logger) (bool, error) {
	//  Update server side sessions
	ss.cleanupExpiredSessions()

	// Validate mTLS
	if len(r.TLS.PeerCertificates) <= 0 {
		logger.LogEvent(certMissingAuditEvent(r), shouldAutoFlush) //LOG
		return false, fmt.Errorf("client certificate required")
	}

	// Get session cookie
	fingerprint := getFingerprintFromCert(r.TLS.PeerCertificates[0])
	cookie, err := r.Cookie("session_id")
	if err != nil {
		logger.LogEvent(missingCookieAuditEvent(getUserFromFingerprint(fingerprint, nil), fingerprint, r, err), shouldAutoFlush) //LOG
		return false, fmt.Errorf("session cookie not found")
	}
	sessions, _ := ss.LoadSessions(true)
	session, err := ss.getSession(cookie.Value, fingerprint, sessions)
	// Check session exists
	if err != nil {
		//fmt.Printf("Invalid session cookie: %s\n", cookie.Value)
		logger.LogEvent(missingSessionAuditEvent(getUserFromFingerprint(fingerprint, nil), fingerprint, r, err, "invalid session cookie"), shouldAutoFlush) //LOG
		return false, fmt.Errorf("invalid session cookie")
	}

	// Update last seen
	devices, _ := deviceStore.LoadDevices(true)
	for _, device := range devices {
		if strings.EqualFold(device.CertFingerprint, fingerprint) {
			device.LastSeen = time.Now().Format(time.RFC3339)
			deviceStore.EditDevice(device.DeviceID, device, true)
			break
		}
	}

	// Check session not expired
	if time.Now().After(session.ExpiresAt) {
		//cleanupExpiredSessions() - redundent i think
		return false, fmt.Errorf("session expired")
	}
	// Check cert fingerprint matches
	if !strings.EqualFold(session.CertFingerprint, fingerprint) {
		logger.LogEvent(certMismatchAuditEvent(session.Username, session.CertFingerprint, r), shouldAutoFlush) //LOG
		return false, fmt.Errorf("client certificate does not match session")
	}

	return true, nil
}

// Pending store
func (ps *PendingStore) LoadPending(safety bool) ([]PendingRequest, error) {
	if safety {
		ps.mutex.Lock()
		defer ps.mutex.Unlock()
	}
	data, err := os.ReadFile(getAbsPath(ps.pendingPath))
	if err != nil {
		if os.IsNotExist(err) {
			return []PendingRequest{}, nil
		}
		logger.LogEvent(systemAuditEvent(Actions.LOAD_DATA, Outcomes.ERROR, err, "Loaded pending.json"), shouldAutoFlush)
		return nil, err
	}
	var pending []PendingRequest
	if err := json.Unmarshal(data, &pending); err != nil {
		logger.LogEvent(jsonUnmarshalAuditEvent(Outcomes.ERROR, err, "Loading pending.json"), shouldAutoFlush)
		return nil, err
	}
	logger.LogEvent(systemAuditEvent(Actions.LOAD_DATA, Outcomes.SUCCESS, nil, "Loaded pending.json"), shouldAutoFlush)
	return pending, nil
}

func (ps *PendingStore) loadPendingViews(safety bool) ([]PendingView, error) {
	if safety {
		ps.mutex.Lock()
		defer ps.mutex.Unlock()
	}

	pending, err := ps.LoadPending(false)
	if err != nil {
		return nil, err
	}

	views := []PendingView{}
	for _, req := range pending {
		view := PendingView{
			Username:    req.Username,
			DeviceName:  req.DeviceName,
			SubmittedAt: req.SubmittedAt,
			Status:      req.Status,
		}
		views = append(views, view)
	}

	return views, nil
}

func (ps *PendingStore) findPending(username string, deviceName string) (PendingRequest, error) {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	pending, err := ps.LoadPending(false)
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.LOAD_DATA, Outcomes.ERROR, err, "Loaded pending.json"), shouldAutoFlush)
		return PendingRequest{}, err
	}

	for _, req := range pending {
		if req.Username == username && req.DeviceName == deviceName {
			return req, nil
		}
	}

	return PendingRequest{}, fmt.Errorf("pending request not found for user: %s", username)
}

func (ps *PendingStore) AddPending(req PendingRequest) error {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	pending, err := ps.LoadPending(false)
	if err != nil {
		return err
	}
	pending = append(pending, req)

	data, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.ERROR, err, "Saving pending.json"), shouldAutoFlush)
		return err
	}
	logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.SUCCESS, nil, "Saving pending.json"), shouldAutoFlush)
	return os.WriteFile(getAbsPath(ps.pendingPath), data, 0644)
}

func (ps *PendingStore) UpdatePending(updatedReq PendingRequest) error {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	pending, err := ps.LoadPending(false)
	if err != nil {
		return err
	}

	for i, req := range pending {
		if req.Username == updatedReq.Username && req.DeviceName == updatedReq.DeviceName {
			pending[i] = updatedReq
			break
		}
	}

	data, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.ERROR, err, "Saving pending.json"), shouldAutoFlush)
		return err
	}
	logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.SUCCESS, nil, "Saving pending.json"), shouldAutoFlush)
	return os.WriteFile(getAbsPath(ps.pendingPath), data, 0644)
}

func (ps *PendingStore) RemovePending(username string, deviceName string) error {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	pending, err := ps.LoadPending(false)
	if err != nil {
		return err
	}

	newPending := []PendingRequest{}
	for _, req := range pending {
		if !(req.Username == username && req.DeviceName == deviceName) {
			newPending = append(newPending, req)
		}
	}

	data, err := json.MarshalIndent(newPending, "", "  ")
	if err != nil {
		logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.ERROR, err, "Saving pending.json"), shouldAutoFlush)
		return err
	}
	logger.LogEvent(systemAuditEvent(Actions.SAVE_DATA, Outcomes.SUCCESS, nil, "Saving pending.json"), shouldAutoFlush)
	return os.WriteFile(getAbsPath(ps.pendingPath), data, 0644)
}
