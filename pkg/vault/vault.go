package vault

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

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

func (vw *VaultwardenInterface) Sync() error {
	req, err := http.NewRequest("GET", vw.config.Server()+"/api/sync", nil)
	if err != nil {
		return err
	}

	token, err := vw.config.Token()
	if err != nil {
		return err
	}
	accessToken := token.AccessToken

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// try again on 401?
		log.Println(resp.Status)
		return errors.New("received a non-200 status code")
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// fmt.Println(string(respBody))
	syncResponse := SyncResponse{}
	json.Unmarshal(respBody, &syncResponse)

	masterKey, err := pbkdf2.Key(
		sha256.New,
		vw.config.Password(),
		[]byte(vw.config.Username()),
		int(token.KdfIterations),
		32,
	)
	if err != nil {
		return err
	}
	masterEncKey, err := hkdf.Expand(sha256.New, masterKey, "enc", 32)
	if err != nil {
		return err
	}
	masterMacKey, err := hkdf.Expand(sha256.New, masterKey, "mac", 32)
	if err != nil {
		return err
	}

	key := syncResponse.Profile.Key
	decryptedUserKey, err := decryptAES(masterEncKey, masterMacKey, key)
	if err != nil {
		return fmt.Errorf("decrypting user key: %w", err)
	}
	userEncKey, userMacKey, err := splitCombinedKey(decryptedUserKey)
	if err != nil {
		return fmt.Errorf("splitting userKey: %w", err)
	}

	if token.PrivateKey == nil {
		return errors.New("sync: could not find private key")
	}
	privateKey := *token.PrivateKey
	decryptedPrivateKey, err := decryptAES(userEncKey, userMacKey, privateKey)
	if err != nil {
		return fmt.Errorf("decrypting private key: %w", err)
	}

	vals := []map[string]string{}
	for _, cipher := range syncResponse.Ciphers {
		var encKey = userEncKey
		var macKey = userMacKey
		if cipher.Key != nil {
			cipherKey, err := decryptAES(userEncKey, userMacKey, *cipher.Key)
			if err != nil {
				return fmt.Errorf("decrypting item (%s) key: %w", cipher.ID, err)
			}
			encKey, macKey, err = splitCombinedKey(cipherKey)
			if err != nil {
				return fmt.Errorf("splitting cipher key (%s): %w", cipher.ID, err)
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
				return fmt.Errorf("could not find organization (%s) in user profile", cipher.OrganizationID)
			}

			encryptedRSAKey, err := parseRSAKey(org.Key)
			if err != nil {
				return err
			}

			orgKey, err := decryptRSA(encryptedRSAKey, decryptedPrivateKey)
			if err != nil {
				return fmt.Errorf("decrypting org key for cipher (%s) key: %w", cipher.ID, err)
			}

			encKey, macKey, err = splitCombinedKey(orgKey)
			if err != nil {
				return fmt.Errorf("splitting cipher key (%s): %w", cipher.ID, err)
			}
		}

		decryptedCipherName, err := decryptAES(encKey, macKey, cipher.Name)
		if err != nil {
			return fmt.Errorf("decrypting cipher name (%s): %w", cipher.ID, err)
		}

		if cipher.Login == nil {
			continue
		}

		var decryptedCipherUsername []byte
		// if the username is nil that's okay
		if cipher.Login.Username != nil {
			decryptedCipherUsername, err = decryptAES(encKey, macKey, *cipher.Login.Username)
			if err != nil {
				return fmt.Errorf("decrypting cipher username (%s): %w", cipher.ID, err)
			}
		}

		if cipher.Login.Password == nil {
			// no point if there's no password. Not doing fido2 passkeys yet
			continue
		}

		decryptedCipherPassword, err := decryptAES(encKey, macKey, *cipher.Login.Password)
		if err != nil {
			return fmt.Errorf("decrypting cipher password (%s, %s): %w", cipher.ID, decryptedCipherName, err)
		}

		vals = append(vals, map[string]string{
			"name":     string(decryptedCipherName),
			"username": string(decryptedCipherUsername),
			"password": string(decryptedCipherPassword),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	err = enc.Encode(vals)
	if err != nil {
		return err
	}

	return nil
}

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

func parseRSAKey(encryptedKey string) (key []byte, err error) {
	components := strings.Split(encryptedKey, ".")
	if len(components) != 2 {
		return nil, fmt.Errorf("parsing RSA key expected exactly 2 components got %d", len(components))
	}

	return base64.StdEncoding.DecodeString(components[1])
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

func splitCombinedKey(combinedKey []byte) (encKey, macKey []byte, err error) {
	switch len(combinedKey) {
	case 32:
		return combinedKey[0:16], combinedKey[16:], nil
	case 64:
		return combinedKey[0:32], combinedKey[32:], nil
	default:
		return nil, nil, fmt.Errorf("splitting combined key: unsupported key length %d", len(combinedKey))
	}
}

// stripPadding strips the trailing repeated characters off of a byte slice
//
// bitwarden (or vaultwarden) appears to be using repeated bytes to pad out
// encrypted values. But it isn't clear to me currently how they're choosing the
// byte they use. Not sure why, nor why the JS libs are removing that padding.
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
