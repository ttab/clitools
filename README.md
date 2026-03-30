# CLI tools

[![Go Reference](https://pkg.go.dev/badge/github.com/ttab/clitools.svg)](https://pkg.go.dev/github.com/ttab/clitools)

Helpers for building Elephant CLI tools. Handles environment configuration, service endpoint resolution, and OIDC authentication so that individual CLI applications don't have to.

## Configuring an environment

Before a CLI tool can authenticate or call services, the target environment needs to be configured. The package provides a `configure` CLI command (via `ConfigureCliCommands`) that can be embedded in any application built with [urfave/cli](https://github.com/urfave/cli):

```bash
# Set the base URL for the environment. Service endpoints are derived from it.
myapp --env=prod configure --base-url=https://tt.ecms.se --oidc=https://login.tt.se/realms/elephant/.well-known/openid-configuration

# Individual endpoints can be overridden when a service doesn't follow the
# standard naming convention.
myapp --env=prod configure --endpoint=chrome=https://tt.se/elephant
```

Setting a base URL like `https://tt.ecms.se` means that service endpoints are constructed on the fly:

| Service    | Derived URL                        |
|------------|------------------------------------|
| repository | `https://repository.api.tt.ecms.se` |
| index      | `https://index.api.tt.ecms.se`      |
| chrome     | `https://tt.ecms.se/elephant`       |
| ...        | `https://{name}.api.tt.ecms.se`     |

The "chrome" endpoint is special-cased to `{base URL}/elephant`. All other endpoints follow the pattern `{scheme}://{name}.api.{host}`.

Explicit endpoints (set with `--endpoint`) always take precedence over endpoints derived from the base URL.

## Endpoint resolution

Application code retrieves endpoints through the `ConfigurationHandler`:

```go
handler, err := clitools.NewConfigurationHandler("myapp", clitools.DefaultApplicationID, "prod")

// Look up a specific endpoint.
repoURL, ok := handler.GetEndpoint("repository")

// Get all known endpoints (base URL derived + explicit overrides).
allEndpoints := handler.GetEndpoints()
```

`GetEndpoint` checks explicit endpoints first, then falls back to constructing the URL from the base URL. Any service name can be resolved this way, so new services work without reconfiguration.

## Authentication

The package supports two OIDC flows:

**Authorization code with PKCE** (interactive CLI usage): `GetAccessToken` opens a browser for the user to log in and starts a temporary local HTTP server to receive the callback. Tokens are cached and reused until they expire.

**Client credentials** (service-to-service): `GetClientAccessToken` returns an `oauth2.TokenSource` for the given client ID and secret.

See the [example in the Go docs](https://pkg.go.dev/github.com/ttab/clitools#example-package) for a complete usage example.

## Configuration storage

Configuration is stored per environment under `$XDG_CONFIG_HOME/elephant-clitools/{environment}/` (or the platform-appropriate [user configuration directory](https://pkg.go.dev/os#UserConfigDir), e.g. `~/.config/elephant-clitools/{environment}/` on Linux).

Each environment directory contains:
- `config.json` -- OIDC settings, base URL, and endpoint overrides. Shared across all applications using the same environment.
- `tokens.json` -- cached access tokens, keyed by application name.

File system locking ensures that concurrent CLI processes don't corrupt the configuration.

## Environment variable loading

`UserConfigDir()` gives preference to `XDG_CONFIG_HOME`, letting users on any OS specify a Linux-style user config location. If `XDG_CONFIG_HOME` is empty it behaves just like `os.UserConfigDir()`.

`LoadEnv()` loads any `.env` file (override the path by setting `DOT_ENV`) in the current directory and `{user config dir}/{app}/config.env` if they exist. Already-set variables are not overridden, and `.env` takes precedence over `config.env`.
