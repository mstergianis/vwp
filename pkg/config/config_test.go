package config_test

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"text/template"

	"github.com/mstergianis/vwp/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestNewConfig(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		f, err := os.CreateTemp(os.TempDir(), "new-config-*")
		assert.NoError(t, err)

		contents := `
currentContext: mine
contexts:
  - name: mine
    server: https://myserver.io
    username: myusername
    password:
      type: plaintext
      value: mypassword
`
		fmt.Fprint(f, contents)

		fileName := f.Name()
		f.Close()

		conf, err := config.New(fileName)
		assert.NoError(t, err, "creating config")

		assert.Equal(t, "mine", conf.CurrentContextName())

		s := conf.Server()
		assert.Equal(t, "https://myserver.io", s)

		u := conf.Username()
		assert.Equal(t, "myusername", u)

		p, err := conf.Password()
		assert.NoError(t, err)
		assert.Equal(t, "mypassword", p)

		assert.NoError(t, os.Remove(fileName))
	})

	t.Run("empty config", func(t *testing.T) {
		f, err := os.CreateTemp(os.TempDir(), "new-config-*")
		assert.NoError(t, err)
		fileName := f.Name()
		f.Close()

		_, err = config.New(fileName)
		assert.Error(t, err, "creating config")
		assert.ErrorContains(t, err, "vwp: error parsing config file EOF")

		assert.NoError(t, os.Remove(fileName))
	})

	t.Run("does not provide map", func(t *testing.T) {
		f, err := os.CreateTemp(os.TempDir(), "new-config-*")
		assert.NoError(t, err)

		contents := `
true
`
		fmt.Fprint(f, contents)

		fileName := f.Name()
		f.Close()

		_, err = config.New(fileName)
		assert.ErrorContains(
			t,
			err,
			"vwp: error parsing config file yaml: unmarshal errors:\n  line 2: cannot unmarshal !!bool `true` into config.config",
		)
		assert.NoError(t, os.Remove(fileName))
	})

	t.Run("currentContext not in the list", func(t *testing.T) {
		f, err := os.CreateTemp(os.TempDir(), "new-config-*")
		assert.NoError(t, err)

		contents := `
currentContext: mine
contexts:
  - name: theirs
    server: https://myserver.io
    username: myusername
    password:
      type: plaintext
      value: mypassword
  - name: ours
    server: https://myserver.io
    username: myusername
    password:
      type: plaintext
      value: mypassword
`
		fmt.Fprint(f, contents)

		fileName := f.Name()
		f.Close()

		_, err = config.New(fileName)
		assert.ErrorContains(t, err, "vwp: selected context mine is not available in the list of contexts theirs, ours", "creating config")

		assert.NoError(t, os.Remove(fileName))
	})

	for _, field := range []string{"name", "username", "password.value", "password.type", "server"} {
		t.Run(fmt.Sprintf("empty %s", field), func(t *testing.T) {
			f, err := os.CreateTemp(os.TempDir(), "new-config-*")
			assert.NoError(t, err)

			contents := templateEmptyField(t, field)
			fmt.Fprint(f, contents)

			fileName := f.Name()
			f.Close()

			_, err = config.New(fileName)
			assert.ErrorContains(t, err, fmt.Sprintf("vwp: error parsing config missing field %s", field))

			assert.NoError(t, os.Remove(fileName))
		})
	}
}

func templateEmptyField(t *testing.T, field string) string {
	defaults := config.Context{
		Name:     "mine",
		Server:   "https://myserver.io",
		Username: "myusername",
		Password: &config.Password{
			Typ:   "plaintext",
			Value: "mypassword",
		},
	}

	switch field {
	case "name":
		defaults.Name = ""
	case "server":
		defaults.Server = ""
	case "username":
		defaults.Username = ""
	case "password.value":
		defaults.Password.Value = ""
	case "password.type":
		defaults.Password.Typ = ""
	}

	templateLiteral := `
currentContext: mine
contexts:
  - name: mine
    server: https://myserver.io
    username: myusername
    password:
      type: plaintext
      value: mypassword
  - name: {{ .Name }}
    server: {{ .Server }}
    username: {{ .Username }}
    password:
      type: {{ .Password.Typ }}
      value: {{ .Password.Value }}
`
	tmpl := template.Must(template.New("emptyField").Parse(templateLiteral))

	s := &strings.Builder{}
	err := tmpl.Execute(s, defaults)
	if err != nil {
		t.Fatal(err)
	}

	return s.String()
}
