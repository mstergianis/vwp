package config

type Password struct {
	Typ   string `yaml:"type"`
	Value string `yaml:"value"`
}

func NewPassword() (*Password, error) {
	// validate connection to pass
	return nil, nil
}

func validatePassword(p *Password) error {
	switch p.Typ {
	case "plaintext":
		{
			// validate that password is not empty
			return nil
		}
	case "pass":
		{
			// validate connection to pass

			// validate that password is in pass, but don't check the value (don't decrypt the file)
			return nil
		}
	}
	return nil
}

func (p *Password) Password() (string, error) {
	switch p.Typ {
	case "plaintext":
		return p.Value, nil
	case "pass":
		{
			return "", nil
		}
	}
	return "", nil
}
