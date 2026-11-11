// Package sharedsecretmac computes HMAC-SHA1 registration signatures required by Synapse and Tuwunel.
package sharedsecretmac

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
)

// Compute calculates the lowercase hex HMAC-SHA1 digest mandated by /_synapse/admin/v1/register.
// Synapse and Tuwunel hardcode SHA-1 for this shared-secret protocol endpoint.
func Compute(secret, nonce, username, password string, admin bool) string {
	role := "notadmin"
	if admin {
		role = "admin"
	}

	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(nonce))
	mac.Write([]byte{0})
	mac.Write([]byte(username))
	mac.Write([]byte{0})
	mac.Write([]byte(password))
	mac.Write([]byte{0})
	mac.Write([]byte(role))
	return hex.EncodeToString(mac.Sum(nil))
}
