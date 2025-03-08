package vault

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

func parseRSAKey(encryptedKey string) (key []byte, err error) {
	components := strings.Split(encryptedKey, ".")
	if len(components) != 2 {
		return nil, fmt.Errorf("parsing RSA key expected exactly 2 components got %d", len(components))
	}

	return base64.StdEncoding.DecodeString(components[1])
}

func decryptRSA(data, privateKey []byte) (decryptedKey []byte, err error) {
	anyKey, err := x509.ParsePKCS8PrivateKey(privateKey)
	if err != nil {
		return
	}

	rsaKey, ok := anyKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("parsing RSA private key")
	}

	return rsaKey.Decrypt(nil, data, &rsa.OAEPOptions{
		Hash:    crypto.SHA1,
		MGFHash: 0,
		Label:   nil,
	})
}
