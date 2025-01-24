# CLI tools

[![Go Reference](https://pkg.go.dev/badge/github.com/ttab/clitools.svg)](https://pkg.go.dev/github.com/ttab/clitools)

The clitools contains helpers for building TT CLI tools.

## Logging in using the ConfigurationHandler

See the [example in the Go docs](https://pkg.go.dev/github.com/ttab/clitools#example-package).

Configuration and tokens will be saved in $XDG_CONFIG_HOME or the appropriate [user configuration directory](https://pkg.go.dev/os#UserConfigDir) for your platform, for Linux this is "~/.config/[name of application]/". Configuration is stored in "config.json" and the access tokens in "tokens.json".

## Configuration directory and environment loading

`UserConfigDir()` gives preference to XDG_CONFIG_HOME, letting users in any OS specify a linux-style user config location. If XDG_CONFIG_HOME is empty it behaves just like `os.UserConfigDir()`.

`LoadEnv()` loads any ".env" (override by setting DOT_ENV) in the current path and "[user config dir]/[app]/config.env" if they exist. This will not override any variables that are set, and the .env file takes precedence over config.env.
