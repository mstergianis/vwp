package pass

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
)

type Pass interface {
	// Add a secret at the given location, if the location exists, overwrite it with the new value.
	//
	// Add will use pass insert -f by default. So without prompting the user it will
	// overwrite secrets.
	Add(secret, location string) error

	// Read a secret at the given location.
	Read(location string) (string, error)

	// LocationExists validates that a secret exists at location without decrypting it.
	LocationExists(location string) (bool, error)
}

type pass struct {
	subdir string
	logger *log.Logger
}

type Option func(*pass)

// New returns a new [*Pass] struct.
//
// It is configured to run pass in the subdir.
func New(subdir string, opts ...Option) Pass {
	p := &pass{subdir: subdir}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func WithLogger(l *log.Logger) Option {
	return func(p *pass) {
		p.logger = l
	}
}

func (p *pass) Add(secret, location string) error {
	stdinContents := fmt.Sprintf("%s\n%s\n", secret, secret)
	stdout, err := runPass(stdinContents, "insert", "-f", p.resolveLocation(location))
	if err != nil {
		return err
	}
	if stdout := strings.TrimSpace(stdout); p.logger != nil && stdout != "" {
		p.logger.Printf("PassRunner.Add: %s", stdout)
	}
	return nil
}

func (p *pass) Read(location string) (string, error) {
	secret, err := runPass("", "show", p.resolveLocation(location))
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(secret), nil
}

func (p *pass) LocationExists(location string) (bool, error) {
	resolvedPath, err := p.resolveFilesystemLocation(location)
	if err != nil {
		return false, err
	}

	switch _, err := os.Stat(resolvedPath); {
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	case err != nil:
		return false, err
	}

	return true, nil
}

func (p *pass) resolveLocation(location string) string {
	return path.Join(p.subdir, location)
}

func (p *pass) resolveFilesystemLocation(location string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	// TODO: allow configuration of the .password-store location
	return path.Join(homeDir, ".password-store", p.subdir, location+".gpg"), nil
}

func runPass(stdinContents string, args ...string) (string, error) {
	cmd := exec.Command("pass", args...)

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if stdinContents != "" {
		cmd.Stdin = strings.NewReader(stdinContents)
	}

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, stderr.String())
	}

	return stdout.String(), nil
}
