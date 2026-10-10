package handler

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/user"
)

// DefaultDeviceCookie recognizes a browser across sign-ins, for the
// new-device notice and step-up. It grants nothing by itself; assign another
// at composition time to change its attributes.
var DefaultDeviceCookie = &TrustedDeviceCookie{
	Name: "keel_device",
	Path: "/",
	TTL:  400 * 24 * time.Hour,
}

// sessionDevice describes the device of r. With mint, a request without a
// device cookie gets one, so its next sign-in is recognized.
func sessionDevice(w http.ResponseWriter, r *http.Request, mint bool) (user.SessionDevice, error) {
	device := user.SessionDevice{
		UserAgent:    r.UserAgent(),
		ClientIP:     common.TrustedClientIP(r),
		DeviceSecret: DefaultDeviceCookie.Get(r),
	}
	if mint && !validDeviceSecret(device.DeviceSecret) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return device, err
		}
		device.DeviceSecret = hex.EncodeToString(b)
		DefaultDeviceCookie.Set(w, device.DeviceSecret)
	}
	if !validDeviceSecret(device.DeviceSecret) {
		device.DeviceSecret = ""
	}
	return device, nil
}

func validDeviceSecret(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
