package clitools

import (
	"context"
	"fmt"
	"io"
)

type wellKnownEnvironment struct {
	Name    string
	OIDC    string
	BaseURL string
}

type wellKnownAlias struct {
	Name   string
	Target string
}

// wellKnownEnvironments are configured by "configure --well-known".
var wellKnownEnvironments = []wellKnownEnvironment{
	{
		Name:    "tt-stage",
		OIDC:    "https://login.stage.tt.se/realms/elephant",
		BaseURL: "https://stage.tt.ecms.se",
	},
	{
		Name:    "tt-prod",
		OIDC:    "https://login.tt.se/realms/elephant",
		BaseURL: "https://tt.ecms.se",
	},
	{
		Name:    "ntb-stage",
		OIDC:    "https://login.stage.tt.se/realms/ntb",
		BaseURL: "https://stage.ntb.ecms.se",
	},
	{
		Name:    "ntb-prod",
		OIDC:    "https://login.tt.se/realms/ntb",
		BaseURL: "https://ntb.ecms.se",
	},
}

// wellKnownAliases are created by "configure --well-known" unless an
// environment with the same name is already configured.
var wellKnownAliases = []wellKnownAlias{
	{Name: "stage", Target: "tt-stage"},
	{Name: "prod", Target: "tt-prod"},
}

// configureWellKnown sets the OIDC configuration and base URL of the
// well-known environments, leaving any explicitly configured endpoints in
// place, and then creates the well-known aliases that don't exist yet.
func configureWellKnown(
	ctx context.Context,
	name, clientID string,
	envs []wellKnownEnvironment,
	aliases []wellKnownAlias,
	out io.Writer,
) error {
	for _, env := range envs {
		handler, err := NewConfigurationHandler(name, clientID, env.Name)
		if err != nil {
			return fmt.Errorf("load %s: %w", env.Name, err)
		}

		if handler.Environment() != env.Name {
			_, _ = fmt.Fprintf(out, "%s: alias for %s, left alone\n",
				env.Name, handler.Environment())

			continue
		}

		err = handler.SetOIDCConfigURL(ctx, env.OIDC)
		if err != nil {
			return fmt.Errorf("configure %s: %w", env.Name, err)
		}

		err = handler.SetBaseURL(env.BaseURL)
		if err != nil {
			return fmt.Errorf("configure %s: %w", env.Name, err)
		}

		err = handler.Save()
		if err != nil {
			return fmt.Errorf("save %s: %w", env.Name, err)
		}

		_, _ = fmt.Fprintf(out, "%s: configured\n", env.Name)
	}

	baseDir, err := environmentsDir()
	if err != nil {
		return err
	}

	for _, alias := range aliases {
		config, err := readEnvConfig(baseDir, alias.Name)
		if err != nil {
			return err
		}

		switch {
		case config.Alias != "":
			_, _ = fmt.Fprintf(out, "%s: already an alias for %s, left alone\n",
				alias.Name, config.Alias)

			continue
		case config.configured():
			_, _ = fmt.Fprintf(out, "%s: already configured, left alone\n",
				alias.Name)

			continue
		}

		err = SetEnvironmentAlias(alias.Name, alias.Target)
		if err != nil {
			return fmt.Errorf("alias %s: %w", alias.Name, err)
		}

		_, _ = fmt.Fprintf(out, "%s: alias for %s\n", alias.Name, alias.Target)
	}

	return nil
}
