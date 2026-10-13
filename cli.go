package clitools

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v3"
)

func ConfigureCliCommands(name string, clientID string) *cli.Command {
	cmd := cli.Command{
		Name: "configure",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "env",
				Usage: "The name of the environment to configure",
			},
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
			&cli.StringFlag{
				Name:  "alias",
				Usage: "Make the environment an alias for another, replacing its own configuration",
			},
			&cli.BoolFlag{
				Name:  "well-known",
				Usage: "Configure the tt-stage, tt-prod, ntb-stage and ntb-prod environments, and alias stage and prod to the TT ones unless they are already configured",
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List configured environments",
				Action: func(ctx context.Context, c *cli.Command) error {
					return listEnvironments(name, clientID, os.Stdout)
				},
			},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			var (
				env            = c.String("env")
				oidc           = c.String("oidc")
				endpoints      = c.StringSlice("endpoint")
				baseURL        = c.String("base-url")
				resetEndpoints = c.Bool("reset-endpoints")
				alias          = c.String("alias")
				wellKnown      = c.Bool("well-known")
			)

			changes := oidc != "" || len(endpoints) > 0 ||
				baseURL != "" || resetEndpoints

			if wellKnown {
				if env != "" || alias != "" || changes {
					return errors.New("--well-known cannot be combined with other flags")
				}

				return configureWellKnown(ctx, name, clientID,
					wellKnownEnvironments, wellKnownAliases,
					os.Stdout)
			}

			if env == "" {
				if alias != "" || changes || !isTerminal(os.Stdin) {
					return errors.New("the --env flag is required")
				}

				ok, err := askYesNo(os.Stdin, os.Stderr,
					"No --env given. Set up the default environments (tt-stage, tt-prod, ntb-stage and ntb-prod, with stage and prod as aliases for the TT ones)?",
					true)
				if err != nil {
					return err
				}

				if !ok {
					return errors.New("the --env flag is required")
				}

				return configureWellKnown(ctx, name, clientID,
					wellKnownEnvironments, wellKnownAliases,
					os.Stdout)
			}

			if alias != "" {
				if changes {
					return errors.New("--alias cannot be combined with configuration changes, configure the target environment instead")
				}

				return SetEnvironmentAlias(env, alias)
			}

			handler, err := NewConfigurationHandler(
				name, clientID, env,
			)
			if err != nil {
				return fmt.Errorf("create configuration handler: %w", err)
			}

			if handler.Environment() != env {
				fmt.Fprintf(os.Stderr,
					"%s is an alias for %s, configuring %s\n",
					env, handler.Environment(), handler.Environment())
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

func listEnvironments(name, clientID string, out *os.File) error {
	text, err := buildEnvironmentList(name, clientID, isTerminal(out))
	if err != nil {
		return err
	}

	_, err = io.WriteString(out, text)
	if err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	return nil
}

func buildEnvironmentList(name, clientID string, useColor bool) (string, error) {
	baseDir, err := environmentsDir()
	if err != nil {
		return "", err
	}

	envNames, err := environmentNames(baseDir)
	if err != nil {
		return "", err
	}

	if len(envNames) == 0 {
		return "No environments configured.\n", nil
	}

	var b strings.Builder

	for i, envName := range envNames {
		if i > 0 {
			b.WriteString("\n")
		}

		config, err := readEnvConfig(baseDir, envName)
		if err != nil {
			fmt.Fprintf(&b, "%s: error: %v\n", envName, err)
			continue
		}

		if config.Alias != "" {
			fmt.Fprintln(&b, envName)
			fmt.Fprintf(&b, "  Alias for: %s\n", config.Alias)

			continue
		}

		handler, err := NewConfigurationHandler(name, clientID, envName)
		if err != nil {
			fmt.Fprintf(&b, "%s: error: %v\n", envName, err)
			continue
		}

		writeEnvironmentSummary(&b, envName, name, handler, useColor)
	}

	return b.String(), nil
}

func writeEnvironmentSummary(
	b *strings.Builder,
	envName, appName string,
	handler *ConfigurationHandler,
	useColor bool,
) {
	baseURL := handler.config.BaseURL
	if baseURL == "" {
		baseURL = "(not configured)"
	}

	oidcURL := "(not configured)"
	if handler.config.OIDC != nil && handler.config.OIDC.ConfigURL != "" {
		oidcURL = handler.config.OIDC.ConfigURL
	}

	fmt.Fprintln(b, envName)
	fmt.Fprintf(b, "  Base URL: %s\n", baseURL)
	fmt.Fprintf(b, "  OIDC URL: %s\n", oidcURL)

	token, ok := handler.tokens[appName]

	switch {
	case !ok:
		b.WriteString("  Token:    (none)\n")
	case time.Now().After(token.Expires):
		line := fmt.Sprintf("%s (expired)",
			token.Expires.Local().Format(time.RFC3339))
		if useColor {
			line = "\x1b[31m" + line + "\x1b[0m"
		}

		fmt.Fprintf(b, "  Token:    %s\n", line)
	default:
		fmt.Fprintf(b, "  Token:    %s\n",
			token.Expires.Local().Format(time.RFC3339))
	}
}

// askYesNo asks a yes or no question, returning def for an empty answer.
func askYesNo(in io.Reader, out io.Writer, question string, def bool) (bool, error) {
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}

	r := bufio.NewReader(in)

	for {
		_, _ = fmt.Fprintf(out, "%s %s ", question, hint)

		line, err := r.ReadString('\n')
		if err != nil && (!errors.Is(err, io.EOF) || line == "") {
			return false, fmt.Errorf("read answer: %w", err)
		}

		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}

		if errors.Is(err, io.EOF) {
			return false, errors.New("read answer: unrecognised answer at end of input")
		}
	}
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}

	return info.Mode()&os.ModeCharDevice != 0
}
