package main

import (
	"strings"
)

func checkAdmin(fingerprint string, devices []Device, users []User) bool {
	// Load devices and users
	if devices == nil {
		devices, _ = deviceStore.LoadDevices(true)
	}
	if users == nil {
		users, _ = userStore.LoadUsers(true)
	}

	for _, device := range devices {
		// Match fingerprint and check not revoked
		if strings.EqualFold(device.CertFingerprint, fingerprint) && !device.Revoked {
			// Check if user tied to device is admin
			for _, user := range users {
				if user.Username == device.OwnerUser && checkPermission(fingerprint, Permissions.SystemAdmin, devices, users) {
					for _, role := range user.Permissions {
						if role == Permissions.SystemAdmin {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

func checkPermission(fingerprint string, permission string, devices []Device, users []User) bool {
	// Load devices and users
	if devices == nil {
		devices, _ = deviceStore.LoadDevices(true)
	}
	if users == nil {
		users, _ = userStore.LoadUsers(true)
	}

	for _, device := range devices {
		if strings.EqualFold(device.CertFingerprint, fingerprint) && !device.Revoked {
			for _, user := range users {
				if user.Username == device.OwnerUser {
					for _, role := range user.Permissions {
						if role == Permissions.SystemAdmin || role == permission {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

func getPermissions(fingerprint string, devices []Device, users []User) []string {
	// Load devices and users
	if devices == nil {
		devices, _ = deviceStore.LoadDevices(true)
	}
	if users == nil {
		users, _ = userStore.LoadUsers(true)
	}

	permissions := []string{}

	for _, device := range devices {
		if strings.EqualFold(device.CertFingerprint, fingerprint) && !device.Revoked {
			for _, user := range users {
				if user.Username == device.OwnerUser {
					for _, role := range user.Permissions {
						permissions = append(permissions, role)
					}
				}
			}
		}
	}

	return permissions
}
