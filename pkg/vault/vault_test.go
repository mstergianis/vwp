package vault_test

import (
	"testing"

	"github.com/mstergianis/vwp/pkg/vault"
	"github.com/stretchr/testify/assert"
)

func TestStripPadding(t *testing.T) {
	type testCase struct {
		input    []byte
		expected []byte
		name     string
	}

	cases := []testCase{
		{
			input:    []byte{16, 18, 17, 20, 19, 5, 5, 5, 5},
			expected: []byte{16, 18, 17, 20, 19},
			name:     "happy path",
		},
		{
			input:    []byte{},
			expected: []byte{},
			name:     "empty input",
		},
		{
			input:    []byte{16, 18, 17, 20, 19},
			expected: []byte{16, 18, 17, 20, 19},
			name:     "no padding",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actual := vault.StripPadding(tc.input)
			assert.Equal(t, tc.expected, actual)
		})
	}

}
