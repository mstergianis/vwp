package config

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/mstergianis/vwp/pkg/pass"
	"github.com/mstergianis/vwp/pkg/xdg"
	"gopkg.in/yaml.v3"
)

type Config interface {
	CurrentContextName() string
	Username() string
	Password() (string, error)
	Server() string
	Token() (*Token, error)
	PrivateKey() string
	MasterKey() ([]byte, error)
}

type PassFactory func() pass.Pass

func New(fileName string, passFactory PassFactory) (Config, error) {
	configFile, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	c := &config{
		configFile: configFile.Name(),
		pass:       passFactory(),
	}
	decoder := yaml.NewDecoder(configFile)
	err = decoder.Decode(c)
	if err != nil {
		return nil, fmt.Errorf("config: error parsing config file %w", err)
	}

	for i, context := range c.Contexts {
		if c.CurrentContext == context.Name {
			c.context = &c.Contexts[i]
		}
	}

	if err := validate(c); err != nil {
		return nil, err
	}

	return c, nil
}

type config struct {
	configFile string

	Contexts       []Context `yaml:"contexts"`
	CurrentContext string    `yaml:"currentContext"`

	kdfConfig KdfConfig

	context *Context
	token   *Token

	pass pass.Pass
}

type Context struct {
	Name     string    `yaml:"name"`
	Server   string    `yaml:"server"`
	Username string    `yaml:"username"`
	Password *Password `yaml:"password"`
}

type Password struct {
	Typ   string `yaml:"type"`
	Value string `yaml:"value"`
}

func (c *config) CurrentContextName() string {
	return c.CurrentContext
}

func (c *config) getCurrentContext() Context {
	return *c.context
}

func (c *config) Server() string {
	return c.getCurrentContext().Server
}

func (c *config) Username() string {
	return c.context.Username
}

func (c *config) Password() (string, error) {
	switch c.context.Password.Typ {
	case "plaintext":
		return c.context.Password.Value, nil
	case "pass":
		{
			return c.pass.Read(c.context.Password.Value)
		}
	}

	return "", UnsupportedPasswordTypeErr(c.context.Password.Typ)
}

func (c *config) Token() (*Token, error) {
	if c.token != nil {
		return c.token, nil
	}

	var err error
	c.kdfConfig, err = c.fetchKDFConfig()
	if err != nil {
		return nil, err
	}

	token, err := GetJWTFromFileCache()
	switch {
	case errors.Is(err, TokenExpiryError):
		break
	case errors.Is(err, GetJWTResumableError):
		break
	case err != nil:
		return nil, err
	default:
		return token, nil
	}

	return c.fetchNewToken()
}

func (c *config) fetchNewToken() (token *Token, err error) {
	masterKey, err := c.MasterKey()
	if err != nil {
		return nil, err
	}

	password, err := c.Password()
	if err != nil {
		return nil, err
	}
	hashed, err := pbkdf2.Key(sha256.New, string(masterKey), []byte(password), 1, 32)
	if err != nil {
		return nil, err
	}
	tokenPassword := base64.StdEncoding.EncodeToString(hashed)

	// fetch a new token
	creds := url.Values{
		"scope":             []string{"api offline_access"},
		"client_id":         []string{"some_client"},
		"device_type":       []string{"14"},
		"grant_type":        []string{"password"},
		"username":          []string{c.Username()},
		"password":          []string{tokenPassword},
		"device_name":       []string{"vwp"},
		"device_identifier": []string{"vwp"},
	}

	resp, err := http.PostForm(c.Server()+"/identity/connect/token", creds)
	if err != nil {
		return nil, fmt.Errorf("config: fetching new token: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// try again on 401?
		return nil, fmt.Errorf("config: fetching new token recieved status %d, %s", resp.StatusCode, resp.Status)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("config: reading new token resp body: %w", err)
	}

	token = &Token{}
	err = json.Unmarshal(respBody, token)
	if err != nil {
		return nil, fmt.Errorf("config: unmarshalling json of new token: %w", err)
	}

	err = WriteJWTToFileCache(token)
	if err != nil {
		return nil, err
	}

	c.token = token
	return c.token, nil
}

func (c *config) PrivateKey() string {
	if p := c.token.PrivateKey; p != nil {
		return *p
	}
	return ""
}

func (c *config) KdfIterations() int32 {
	return c.kdfConfig.KdfIterations
}

func (c *config) fetchKDFConfig() (KdfConfig, error) {
	preloginReqBody := &bytes.Buffer{}
	fmt.Fprintf(preloginReqBody, `{"email": %q}`, c.Username())
	preloginResp, err := http.Post(c.Server()+"/identity/accounts/prelogin", "application/json", preloginReqBody)
	if err != nil {
		return KdfConfig{}, err
	}
	preloginRespBody, err := io.ReadAll(preloginResp.Body)
	if err != nil {
		return KdfConfig{}, err
	}

	kdfConfig := KdfConfig{}
	err = json.Unmarshal(preloginRespBody, &kdfConfig)
	if err != nil {
		return KdfConfig{}, err
	}
	return kdfConfig, nil
}

func (c *config) MasterKey() ([]byte, error) {
	email := []byte(strings.ToLower(strings.TrimSpace(c.Username())))

	password, err := c.Password()
	if err != nil {
		return nil, err
	}
	masterKey, err := pbkdf2.Key(
		sha256.New,
		password,
		email,
		int(c.KdfIterations()),
		32,
	)
	return masterKey, err
}

func GetJWTFromFileCache() (token *Token, err error) {
	dataHome, err := xdg.DataHome()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errPrefix, err)
	}

	f, err := os.Open(path.Join(dataHome, "token"))
	if err != nil {
		return nil, jwtResumableWrap(err)
	}

	fstat, err := f.Stat()
	if err != nil {
		return nil, err
	}

	tokenFile, err := io.ReadAll(f)
	if err != nil {
		return nil, jwtResumableWrap(err)
	}

	token = new(Token)
	err = json.Unmarshal(tokenFile, token)
	if err != nil {
		return nil, jwtResumableWrap(err)
	}

	modTime := fstat.ModTime()
	expiryTime := modTime.Add(time.Duration(token.ExpiresIn) * time.Second)
	now := time.Now()
	if now.After(expiryTime) {
		return nil, TokenExpiryError
	}

	return token, nil
}

func WriteJWTToFileCache(token *Token) error {
	dataHome, err := xdg.DataHome()
	if err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}

	bytes, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}

	os.WriteFile(path.Join(dataHome, "token"), bytes, 0600)

	return nil
}

const errPrefix = "VaultWardenInterface.getJWTFromFileCache"

var (
	GetJWTResumableError = errors.New("getting JWT from file cache failed, fetching a fresh token")
	TokenExpiryError     = errors.New("token expried, fetching a fresh token")
)

func jwtResumableWrap(err error) error {
	return fmt.Errorf("%w: %w", GetJWTResumableError, err)
}

// https://github.com/dani-garcia/vaultwarden/blob/6edceb5f7acfee8ffe1ae2f07afd76dc588dda60/src/api/identity.rs#L451
type Token struct {
	AccessToken string  `json:"access_token"`
	ExpiresIn   int64   `json:"expires_in"`
	TokenType   string  `json:"token_type"`
	Key         string  `json:"Key"`
	PrivateKey  *string `json:"PrivateKey"`

	KdfConfig
	ResetMasterPassword bool   `json:"ResetMasterPassword"`
	Scope               string `json:"scope"`
}
