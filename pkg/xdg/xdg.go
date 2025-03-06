package xdg

import (
	"errors"
	"os"
	"path"
)

const appDir = "vwp"

func DataHome() (string, error) {
	xdgDataHome, ok := os.LookupEnv("XDG_DATA_HOME")
	if ok {
		return path.Join(xdgDataHome, appDir), nil
	}

	// default
	home, ok := os.LookupEnv("HOME")
	if !ok {
		return "", errors.New("xdg: HOME directory not set")
	}

	appData := path.Join(home, ".local", "share", appDir)
	err := os.Mkdir(appData, 0750)
	if err != nil && !os.IsExist(err) {
		return "", err
	}

	return appData, nil
}

func ConfigHome() (string, error) {
	xdgConfigHome, ok := os.LookupEnv("XDG_CONFIG_HOME")
	if ok {
		return path.Join(xdgConfigHome, appDir), nil
	}

	// default
	home, ok := os.LookupEnv("HOME")
	if !ok {
		return "", errors.New("xdg: HOME directory not set")
	}

	appConfig := path.Join(home, ".config", appDir)
	err := os.Mkdir(appConfig, 0755)
	if err != nil && !os.IsExist(err) {
		return "", err
	}

	return appConfig, nil
}
