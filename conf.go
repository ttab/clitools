package clitools

import (
	"os"
)

// UserConfigDir gives preference to XDG_CONFIG_HOME, otherwise it behaves just
// like os.UserConfigDir().
func UserConfigDir() (string, error) {
	// Give preference to XDG_CONFIG_HOME.
	ucDir := os.Getenv("XDG_CONFIG_HOME")

	if ucDir != "" {
		return ucDir, nil
	}

	return os.UserConfigDir()
}
