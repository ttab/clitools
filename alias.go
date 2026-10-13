package clitools

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/danjacques/gofslock/fslock"
)

func environmentsDir() (string, error) {
	ucDir, err := UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("get user configuration directory: %w", err)
	}

	return filepath.Join(ucDir, "elephant-clitools"), nil
}

// validateEnvironmentName rejects names that wouldn't stay inside the
// environments directory.
func validateEnvironmentName(name string) error {
	if name == "" || name == "." || name == ".." ||
		strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("invalid environment name %q", name)
	}

	return nil
}

// readEnvConfig reads the stored configuration of an environment without
// following aliases. An environment that doesn't exist reads as an empty
// configuration.
func readEnvConfig(baseDir, environment string) (EnvConfiguration, error) {
	var config EnvConfiguration

	dir := filepath.Join(baseDir, environment)

	_, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return config, nil
	} else if err != nil {
		return config, fmt.Errorf("check environment directory: %w", err)
	}

	err = fslock.With(filepath.Join(dir, "lockfile"), func() error {
		err := unmarshalFile(filepath.Join(dir, "config.json"), &config)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("load %s configuration: %w", environment, err)
		}

		return nil
	})
	if err != nil {
		return config, fmt.Errorf("read config with lock: %w", err)
	}

	return config, nil
}

// resolveEnvironment returns the name of the environment that holds the
// configuration for the given environment: the environment itself, or the
// target of an alias. Aliases are a single hop, an alias of an alias is an
// error, which also rules out cycles.
func resolveEnvironment(baseDir, environment string) (string, error) {
	err := validateEnvironmentName(environment)
	if err != nil {
		return "", err
	}

	config, err := readEnvConfig(baseDir, environment)
	if err != nil {
		return "", err
	}

	if config.Alias == "" {
		return environment, nil
	}

	err = validateEnvironmentName(config.Alias)
	if err != nil {
		return "", fmt.Errorf("alias %s: %w", environment, err)
	}

	target, err := readEnvConfig(baseDir, config.Alias)
	if err != nil {
		return "", err
	}

	if target.Alias != "" {
		return "", fmt.Errorf(
			"%s is an alias for %s, which is itself an alias for %s: aliases cannot be chained",
			environment, config.Alias, target.Alias)
	}

	return config.Alias, nil
}

// SetEnvironmentAlias makes environment a reference to target, replacing
// any configuration environment had of its own. The target must be a
// configured environment, and cannot itself be an alias, or be aliased to by
// anything once it becomes one.
func SetEnvironmentAlias(environment string, target string) error {
	err := validateEnvironmentName(environment)
	if err != nil {
		return err
	}

	err = validateEnvironmentName(target)
	if err != nil {
		return err
	}

	if environment == target {
		return errors.New("an environment cannot be an alias for itself")
	}

	baseDir, err := environmentsDir()
	if err != nil {
		return err
	}

	targetConfig, err := readEnvConfig(baseDir, target)
	if err != nil {
		return err
	}

	switch {
	case targetConfig.Alias != "":
		return fmt.Errorf(
			"%s is itself an alias for %s: aliases cannot be chained",
			target, targetConfig.Alias)
	case !targetConfig.configured():
		return fmt.Errorf("%s is not a configured environment", target)
	}

	aliases, err := aliasesOf(baseDir, environment)
	if err != nil {
		return err
	}

	if len(aliases) > 0 {
		return fmt.Errorf(
			"%s is the target of the alias %s: aliases cannot be chained",
			environment, strings.Join(aliases, ", "))
	}

	dir := filepath.Join(baseDir, environment)

	err = os.MkdirAll(dir, 0o700)
	if err != nil {
		return fmt.Errorf("ensure environment configuration directory: %w", err)
	}

	err = fslock.With(filepath.Join(dir, "lockfile"), func() error {
		return marshalFile(filepath.Join(dir, "config.json"),
			EnvConfiguration{Alias: target})
	})
	if err != nil {
		return fmt.Errorf("save alias with lock: %w", err)
	}

	return nil
}

// aliasesOf lists the environments that are aliases for target.
func aliasesOf(baseDir, target string) ([]string, error) {
	names, err := environmentNames(baseDir)
	if err != nil {
		return nil, err
	}

	var aliases []string

	for _, name := range names {
		config, err := readEnvConfig(baseDir, name)
		if err != nil {
			return nil, err
		}

		if config.Alias == target {
			aliases = append(aliases, name)
		}
	}

	return aliases, nil
}

// environmentNames lists the environment directories, sorted by name.
func environmentNames(baseDir string) ([]string, error) {
	entries, err := os.ReadDir(baseDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("read configuration directory: %w", err)
	}

	var names []string

	// ReadDir returns entries sorted by filename.
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}

	return names, nil
}
