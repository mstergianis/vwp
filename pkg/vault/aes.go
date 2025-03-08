package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

func decryptAES(encKey, macKey []byte, encryptedKey string) ([]byte, error) {
	inputVector, data, mac, err := parseAES(encryptedKey)
	if err != nil {
		return nil, err
	}
	macData := append(inputVector, data...)
	maccer := hmac.New(sha256.New, macKey)
	_, err = maccer.Write(macData)
	if err != nil {
		return nil, err
	}
	computedMAC := maccer.Sum(nil)
	if !hmac.Equal(mac, computedMAC) {
		return nil, errors.New("computed MAC does not equal key MAC")
	}

	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("encrypted key is not a multiple of the block size")
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, inputVector)

	decryptedUserKey := make([]byte, len(data))
	mode.CryptBlocks(decryptedUserKey, data)

	return StripPadding(decryptedUserKey), nil
}

func parseAES(key string) (inputVector, data, mac []byte, err error) {
	components := strings.Split(key, "|")
	if len(components) != 3 {
		err = errors.New("user key should have exactly 3 components separated by pipe \"|\" chars")
		return
	}

	inputVector, err = base64.StdEncoding.DecodeString(components[0][2:])
	if err != nil {
		return
	}

	data, err = base64.StdEncoding.DecodeString(components[1])
	if err != nil {
		return
	}

	mac, err = base64.StdEncoding.DecodeString(components[2])
	if err != nil {
		return
	}
	return
}
