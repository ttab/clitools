# Changelog

All notable changes after v1.0.0 are documented here. Entries are derived from
the release tags; the linked commits and PRs hold the detail.

## [v1.1.1] - 2026-10-13

- `configure` takes the environment from an `--env` set on a parent command
  again, so `app --env prod configure …` works as it did before v1.1.0, where
  it failed asking for `--env`. An `--env` on `configure` itself still wins,
  and a parent flag's default doesn't count.

## [v1.1.0] - 2026-10-13

**Behaviour change (environment names):** `NewConfigurationHandler` now
rejects an empty environment name, and names containing a path separator,
instead of storing the configuration in the `elephant-clitools` directory
itself or outside it.

**Behaviour change (aliases):** an environment can now be an alias for
another, and `NewConfigurationHandler` follows it: the handler reads and
writes the target's configuration and tokens. `Environment()` returns the
name of the environment the handler actually operates on. See
[Aliases](README.md#aliases).

Changes:

- An environment without an OIDC configuration makes `GetAccessToken`,
  `GetOIDCConfig` and `GetClientAccessToken` return an error that names the
  `configure` command, rather than panicking with a nil pointer dereference.
  `IsConfigured()` reports the same thing up front.
- `configure --well-known` configures `tt-stage`, `tt-prod`, `ntb-stage` and
  `ntb-prod`, and makes `stage` and `prod` aliases for the TT environments
  unless they are already configured. See
  [Well-known environments](README.md#well-known-environments). A bare
  `configure` in a terminal offers to do the same.
- `configure --env=<name> --alias=<target>` makes an environment an alias, and
  `SetEnvironmentAlias` does the same from code.
- `configure list` shows every configured environment with its base URL, OIDC
  URL, alias target and token expiry.
- `configure` takes its own `--env` flag.

## [v1.0.3] - 2026-04-23

- `configure --reset-endpoints` clears any explicitly configured endpoints.

## [v1.0.2] - 2026-04-17

- Authorization prompts are written to stderr instead of stdout, so a tool's
  output can be piped while it logs in.

## [v1.0.1] - 2026-04-13

- `--oidc` accepts an issuer URL and appends
  `/.well-known/openid-configuration` when it is missing.
