package config

import "fmt"

func EmptyConfigErr(file string) error {
	return fmt.Errorf("config: config file %q is empty", file)
}

func UnsupportedPasswordTypeErr(typ string) error {
	return fmt.Errorf("config: received an unsupported password.type: %q", typ)
}
