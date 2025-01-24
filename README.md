# CLI tools

The clitools contains helpers for building TT CLI tools. Current functionality includes configuration handling and authenticating against our OIDC provider.

## Logging in using the ConfigurationHandler

See the [example in the Go docs](https://pkg.go.dev/github.com/ttab/clitools#example-package).

Configuration and tokens will be saved in $XDG_CONFIG_HOME or the appropriate [user configuration directory](https://pkg.go.dev/os#UserConfigDir) for your platform, for Linux this is "~/.config/[name of application]/". Configuration is stored in "config.json" and the access tokens in "tokens.json".
