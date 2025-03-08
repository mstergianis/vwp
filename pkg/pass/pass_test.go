package pass_test

import (
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"path"
	"testing"

	"github.com/mstergianis/vwp/pkg/pass"
	"github.com/stretchr/testify/assert"
)

func TestPass(t *testing.T) {
	// TODO set up this test to use a GPG key that is generated within the test
	// in a fully sanitized environment.
	testDir := fmt.Sprintf("vwp-testing-%05d", rand.Uint32N(10_000))

	p := pass.New(testDir, pass.WithLogger(log.Default()))
	err := p.Add("mysecret", "foo")
	assert.NoError(t, err)
	defer func() {
		homeDir, err := os.UserHomeDir()
		assert.NoError(t, err, "could not get user home dir: %q needs to be cleaned up manually", testDir)
		err = os.RemoveAll(path.Join(homeDir, ".password-store", testDir))
		assert.NoError(t, err, "cleanup failed: testDir: %q needs to be cleaned up manually", testDir)
	}()

	secret, err := p.Read("foo")
	assert.Equal(t, "mysecret", secret, "reading the secret should give back the same text")
}
