package config

import (
	"fmt"
	"strings"

	"github.com/mstergianis/vwp/pkg/pass"
)

func validate(c *config) error {
	contextList := []string{}
	for _, context := range c.Contexts {
		contextList = append(contextList, context.Name)
	}

	if c.context == nil {
		return fmt.Errorf(
			"config: selected context %s is not available in the list of contexts %s",
			c.CurrentContext,
			strings.Join(contextList, ", "),
		)
	}

	for _, context := range c.Contexts {
		fields := [][2]string{
			{context.Name, "name"},
			{context.Server, "server"},
			{context.Username, "username"},
		}
		for _, field := range fields {
			if strings.TrimSpace(field[0]) == "" {
				return emptyField(field[1])
			}

		}

		if err := validatePassword(context.Password, c.pass); err != nil {
			return err
		}
	}
	return nil
}

func validatePassword(password *Password, p pass.Pass) error {
	switch password.Typ {
	case "plaintext":
		{
			// validate that password is not empty
			if strings.TrimSpace(password.Value) == "" {
				return emptyField("password.value")
			}
			return nil
		}
	case "pass":
		{
			// validate connection to pass

			// validate that password is in pass, but don't check the value (don't decrypt the file)
			exists, err := p.LocationExists(password.Value)
			if err != nil {
				return err
			}

			if !exists {
				return fmt.Errorf("config: pass does not have a secret at the location: %q", password.Value)
			}
			return nil
		}
	}
	return UnsupportedPasswordTypeErr(password.Typ)
}

func emptyField(field string) error {
	return fmt.Errorf("config: error parsing config missing field %s", field)
}
