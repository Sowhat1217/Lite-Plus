package secretcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/nuomiiiii/lite/utils/instancekey"
)

const Prefix = "enc:v1:"

func Seal(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	if strings.HasPrefix(plain, Prefix) {
		return plain, nil
	}
	key, err := instancekey.LoadOrCreate()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return Prefix + base64.StdEncoding.EncodeToString(payload), nil
}

func Open(stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	if !strings.HasPrefix(stored, Prefix) {
		return stored, nil
	}
	key, err := instancekey.Load()
	if err != nil {
		return "", fmt.Errorf("instance key is required to decrypt nodemgt secrets")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, Prefix))
	if err != nil {
		return "", fmt.Errorf("nodemgt secret is unreadable")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("nodemgt secret is unreadable")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("nodemgt secret is unreadable")
	}
	return string(plain), nil
}
