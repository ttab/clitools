package clitools

import (
	"errors"
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"
)

func ConfigureCliCommands(name string, clientID string) *cli.Command {
	cmd := cli.Command{
		Name: "configure",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "oidc",
				Usage: "Set the .well-known/openid-configuration URL",
			},
			&cli.StringSliceFlag{
				Name:  "endpoint",
				Usage: "-endpoint=repository=https://repository.api.demo.ecms.test",
			},
			&cli.StringFlag{
				Name:  "standard-endpoints",
				Usage: "Set standard endpoints with base domain -standard-endpoints=demo.ecms.test",
			},
		},
		Action: func(c *cli.Context) error {
			var (
				env       = c.String("env")
				oidc      = c.String("oidc")
				endpoints = c.StringSlice("endpoint")
				standard  = c.String("standard-endpoints")
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
				err := handler.SetOIDCConfigURL(c.Context, oidc)
				if err != nil {
					return err
				}
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

			if standard != "" {
				handler.AddEndpoints(
					elephantEndpoints("https", standard))
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
