package clitools

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/urfave/cli/v3"
)

func ConfigureCliCommands(name string, clientID string) *cli.Command {
	cmd := cli.Command{
		Name: "configure",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "oidc",
				Usage: "Set the OIDC discovery URL or issuer URL (the .well-known/openid-configuration path is added automatically if missing)",
			},
			&cli.StringSliceFlag{
				Name:  "endpoint",
				Usage: "-endpoint=repository=https://repository.api.demo.ecms.test",
			},
			&cli.StringFlag{
				Name:  "base-url",
				Usage: "Set the base URL for the environment, service endpoints are derived from it",
			},
			&cli.BoolFlag{
				Name:  "reset-endpoints",
				Usage: "Reset any explicitly configured endpoints",
			},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			var (
				env            = c.String("env")
				oidc           = c.String("oidc")
				endpoints      = c.StringSlice("endpoint")
				baseURL        = c.String("base-url")
				resetEndpoints = c.Bool("reset-endpoints")
			)

			if env == "" {
				return errors.New("no environment set in CLI context")
			}

			handler, err := NewConfigurationHandler(
				name, clientID, env,
			)
			if err != nil {
				return fmt.Errorf("create configuration handler: %w", err)
			}

			if oidc != "" {
				err := handler.SetOIDCConfigURL(ctx, oidc)
				if err != nil {
					return err
				}
			}

			if resetEndpoints {
				handler.ResetEndpoints()
			}

			endpointMap := map[string]string{}

			for _, spec := range endpoints {
				name, endpointURL, ok := strings.Cut(spec, "=")
				if !ok {
					return fmt.Errorf("invalid endpoint spec %q", spec)
				}

				endpointMap[name] = endpointURL
			}

			handler.AddEndpoints(endpointMap)

			if baseURL != "" {
				err := handler.SetBaseURL(baseURL)
				if err != nil {
					return err
				}
			}

			err = handler.Save()
			if err != nil {
				return fmt.Errorf("save configuration: %w", err)
			}

			return nil
		},
	}

	return &cmd
}
