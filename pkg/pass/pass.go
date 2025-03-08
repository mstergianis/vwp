package pass

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"path"
	"strings"
)

type Pass struct {
	subdir string
	logger *log.Logger
}

type Option func(*Pass)

// New returns a new [*Pass] struct.
//
// It is configured to run pass in the subdir.
func New(subdir string, opts ...Option) *Pass {
	p := &Pass{subdir: subdir}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func WithLogger(l *log.Logger) Option {
	return func(p *Pass) {
		p.logger = l
	}
}

// Add a secret at the given location.
//
// Add will use pass insert -f by default. So without prompting the user it will
// overwrite secrets.
func (p *Pass) Add(secret, location string) error {
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

// Read a secret at the given location.
func (p *Pass) Read(location string) (string, error) {
	secret, err := runPass("", "show", p.resolveLocation(location))
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(secret), nil
}

func (p *Pass) resolveLocation(location string) string {
	return path.Join(p.subdir, location)
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
