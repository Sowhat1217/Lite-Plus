package inboundcfg

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

func DefaultSSMethod() string {
	return "2022-blake3-aes-128-gcm"
}

func IsSS2022(method string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(method)), "2022-")
}

func SS2022KeyBytes(method string) int {
	if strings.Contains(strings.ToLower(method), "256") {
		return 32
	}
	return 16
}

func GenerateSS2022Key(method string) (string, error) {
	buf := make([]byte, SS2022KeyBytes(method))
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func SS2022Key(secret, method string) string {
	secret = strings.TrimSpace(secret)
	n := SS2022KeyBytes(method)
	if raw, err := base64.StdEncoding.DecodeString(secret); err == nil && len(raw) == n {
		return secret
	}
	sum := sha256.Sum256([]byte(secret))
	return base64.StdEncoding.EncodeToString(sum[:n])
}

func SS2022SharePassword(serverKey, userSecret, inboundID, method string) string {
	if strings.TrimSpace(serverKey) == "" {
		serverKey = SS2022Key("ss-server:"+strings.TrimSpace(inboundID), method)
	} else {
		serverKey = SS2022Key(serverKey, method)
	}
	return serverKey + ":" + SS2022Key(userSecret, method)
}
