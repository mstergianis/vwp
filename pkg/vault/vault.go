package vault

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"unicode"

	"github.com/mstergianis/vwp/pkg/config"
)

type VaultwardenInterface struct {
	config config.Config
}

func New(config config.Config) *VaultwardenInterface {
	return &VaultwardenInterface{
		config: config,
	}
}

type Secret struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (vw *VaultwardenInterface) GetAllSecrets() ([]Secret, error) {
	req, err := http.NewRequest("GET", vw.config.Server()+"/api/sync", nil)
	if err != nil {
		return nil, err
	}

	token, err := vw.config.Token()
	if err != nil {
		return nil, err
	}
	accessToken := token.AccessToken

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// try again on 401?
		log.Println(resp.Status)
		return nil, errors.New("received a non-200 status code")
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// fmt.Println(string(respBody))
	syncResponse := SyncResponse{}
	json.Unmarshal(respBody, &syncResponse)

	masterKey, err := vw.config.MasterKey()
	if err != nil {
		return nil, err
	}
	masterEncKey, err := hkdf.Expand(sha256.New, masterKey, "enc", HKDF_BIT_LENGTH)
	if err != nil {
		return nil, err
	}
	masterMacKey, err := hkdf.Expand(sha256.New, masterKey, "mac", HKDF_BIT_LENGTH)
	if err != nil {
		return nil, err
	}

	key := syncResponse.Profile.Key
	decryptedUserKey, err := decryptAES(masterEncKey, masterMacKey, key)
	if err != nil {
		return nil, fmt.Errorf("decrypting user key: %w", err)
	}
	userEncKey, userMacKey, err := splitCombinedKey(decryptedUserKey)
	if err != nil {
		return nil, fmt.Errorf("splitting userKey: %w", err)
	}

	if token.PrivateKey == nil {
		return nil, errors.New("sync: could not find private key")
	}
	privateKey := *token.PrivateKey
	decryptedPrivateKey, err := decryptAES(userEncKey, userMacKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting private key: %w", err)
	}

	secrets := []Secret{}
	for _, cipher := range syncResponse.Ciphers {
		var encKey = userEncKey
		var macKey = userMacKey
		if cipher.Key != nil {
			cipherKey, err := decryptAES(userEncKey, userMacKey, *cipher.Key)
			if err != nil {
				return nil, fmt.Errorf("decrypting item (%s) key: %w", cipher.ID, err)
			}
			encKey, macKey, err = splitCombinedKey(cipherKey)
			if err != nil {
				return nil, fmt.Errorf("splitting cipher key (%s): %w", cipher.ID, err)
			}
		}

		if cipher.OrganizationID != "" {
			var org *Organization
			for _, o := range syncResponse.Profile.Organizations {
				if o.ID == cipher.OrganizationID {
					org = &o
				}
			}
			if org == nil {
				return nil, fmt.Errorf("could not find organization (%s) in user profile", cipher.OrganizationID)
			}

			encryptedRSAKey, err := parseRSAKey(org.Key)
			if err != nil {
				return nil, err
			}

			orgKey, err := decryptRSA(encryptedRSAKey, decryptedPrivateKey)
			if err != nil {
				return nil, fmt.Errorf("decrypting org key for cipher (%s) key: %w", cipher.ID, err)
			}

			encKey, macKey, err = splitCombinedKey(orgKey)
			if err != nil {
				return nil, fmt.Errorf("splitting cipher key (%s): %w", cipher.ID, err)
			}
		}

		decryptedCipherName, err := decryptAES(encKey, macKey, cipher.Name)
		if err != nil {
			return nil, fmt.Errorf("decrypting cipher name (%s): %w", cipher.ID, err)
		}

		if cipher.Login == nil {
			continue
		}

		var decryptedCipherUsername []byte
		// if the username is nil that's okay
		if cipher.Login.Username != nil {
			decryptedCipherUsername, err = decryptAES(encKey, macKey, *cipher.Login.Username)
			if err != nil {
				return nil, fmt.Errorf("decrypting cipher username (%s): %w", cipher.ID, err)
			}
		}

		if cipher.Login.Password == nil {
			// no point if there's no password. Not doing fido2 passkeys yet
			continue
		}

		decryptedCipherPassword, err := decryptAES(encKey, macKey, *cipher.Login.Password)
		if err != nil {
			return nil, fmt.Errorf("decrypting cipher password (%s, %s): %w", cipher.ID, decryptedCipherName, err)
		}

		secrets = append(secrets, Secret{
			Name:     normalizeSecretValue(string(decryptedCipherName)),
			Username: normalizeSecretValue(string(decryptedCipherUsername)),
			Password: normalizeSecretValue(string(decryptedCipherPassword)),
		})
	}

	return secrets, nil
}

func normalizeSecretValue(s string) string {
	result := strings.Builder{}
	for _, r := range s {
		if unicode.IsGraphic(r) {
			result.WriteRune(r)
		}
	}
	return strings.TrimSpace(result.String())
}

// byteArrToJSBufferOutput is a debugging function.
//
// In the course of writing this program I often needed to compare values to the
// bitwarden CLI counterpart, so this was a convenience function I'm not willing
// to get rid of.
func byteArrToJSBufferOutput(arr []byte) string {
	s := &strings.Builder{}
	fmt.Fprint(s, "<Buffer ")
	for i, b := range arr {
		fmt.Fprintf(s, "%02x", b)
		if i != len(arr)-1 {
			fmt.Fprint(s, " ")
		}
	}
	fmt.Fprint(s, ">")

	return s.String()
}

// splitCombinedKey separates a key that has both enc and mac components.
//
// https://github.com/bitwarden/clients/blob/895b36a3d8a2e4e789c4c6c4498c7531af78833c/libs/common/src/platform/models/domain/symmetric-crypto-key.ts#L38-L49
func splitCombinedKey(combinedKey []byte) (encKey, macKey []byte, err error) {
	switch len(combinedKey) {
	case 32:
		return combinedKey[0:16], combinedKey[16:], nil
	case 64:
		return combinedKey[0:32], combinedKey[32:], nil
	}

	return nil, nil, fmt.Errorf("splitting combined key: unsupported key length %d", len(combinedKey))
}

// StripPadding strips the trailing repeated characters off of a byte slice
//
// bitwarden (or vaultwarden) appears to be using repeated bytes to pad out
// encrypted values. But it isn't clear to me currently how they're choosing the
// byte they use. Not sure why, nor how the JS libs are removing that padding.
func StripPadding(decryptedKey []byte) []byte {
	if len(decryptedKey) < 1 {
		return decryptedKey
	}
	lastChar := decryptedKey[len(decryptedKey)-1]

	var i int
	for i = len(decryptedKey) - 2; decryptedKey[i] == lastChar && i >= 0; i-- {
	}
	if i == len(decryptedKey)-2 {
		return decryptedKey
	}
	return decryptedKey[:i+1]
}

const (
	HKDF_BIT_LENGTH int = 32
)
