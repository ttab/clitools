package clitools

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/joho/godotenv"
)

// UserConfigDir gives preference to XDG_CONFIG_HOME, letting users in any OS
// specify a linux-style user config location. If XDG_CONFIG_HOME is empty it
// behaves just like os.UserConfigDir().
func UserConfigDir() (string, error) {
	// Give preference to XDG_CONFIG_HOME.
	ucDir := os.Getenv("XDG_CONFIG_HOME")

	if ucDir != "" {
		return ucDir, nil
	}

	return os.UserConfigDir()
}

// LoadEnv loads any ".env" (override by setting DOT_ENV) in the current path
// and "[user config dir]/[app]/config.env" if they exist.

// This will not override any variables that are set, and the .env file takes
// precedence over config.env.
func LoadEnv(app string) error {
	env := os.Getenv("DOT_ENV")
	if env == "" {
		env = ".env"
	}

	candidates := []string{env}

	userConfDir, err := UserConfigDir()
	if err != nil {
		return fmt.Errorf("get user config dir: %w", err)
	}

	candidates = append(candidates,
		filepath.Join(userConfDir, app, "config.env"))

	var envFiles []string

	for f := range slices.Values(candidates) {
		info, err := os.Stat(f)

		switch {
		case errors.Is(err, os.ErrNotExist):
			continue
		case err != nil:
			return fmt.Errorf("check if %q exists: %w", f, err)
		case info.IsDir():
			return fmt.Errorf("%q is a directory", f)
		default:
			envFiles = append(envFiles, f)
		}
	}

	if len(envFiles) == 0 {
		return nil
	}

	err = godotenv.Load(envFiles...)
	if err != nil {
		return fmt.Errorf("read files: %w", err)
	}

	return nil
}
