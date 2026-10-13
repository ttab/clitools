package clitools

import (
	"io"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
)

func TestAskYesNo(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		def     bool
		want    bool
		wantErr bool
	}{
		{name: "empty takes the default yes", input: "\n", def: true, want: true},
		{name: "empty takes the default no", input: "\n", def: false, want: false},
		{name: "yes", input: "yes\n", want: true},
		{name: "no", input: "N\n", def: true, want: false},
		{name: "asks again after nonsense", input: "maybe\ny\n", want: true},
		{name: "answer without newline", input: "y", want: true},
		{name: "end of input", input: "", def: true, wantErr: true},
		{name: "nonsense at end of input", input: "maybe", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := askYesNo(strings.NewReader(tt.input), io.Discard, "Continue?", tt.def)

			switch {
			case tt.wantErr && err == nil:
				t.Fatalf("got %v, want an error", got)
			case !tt.wantErr && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case !tt.wantErr && got != tt.want:
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfigureTakesEnvFromParent(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("ENV", "")

	root := func() *cli.Command {
		return &cli.Command{
			Name: "app",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "env",
					Value:   "stage",
					Sources: cli.EnvVars("ENV"),
				},
			},
			Commands: []*cli.Command{
				ConfigureCliCommands("test", DefaultApplicationID),
			},
		}
	}

	tests := []struct {
		name    string
		args    []string
		wantEnv string
		wantErr bool
	}{
		{
			name:    "env on the root command",
			args:    []string{"app", "--env", "from-root", "configure", "--base-url", "https://root.example.com"},
			wantEnv: "from-root",
		},
		{
			name:    "env on configure wins",
			args:    []string{"app", "--env", "from-root", "configure", "--env", "from-configure", "--base-url", "https://configure.example.com"},
			wantEnv: "from-configure",
		},
		{
			// The root default must not count, or a bare configure
			// would never offer the well-known environments.
			name:    "root default is not an env",
			args:    []string{"app", "configure", "--base-url", "https://default.example.com"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := root().Run(t.Context(), tt.args)

			switch {
			case tt.wantErr && err == nil:
				t.Fatal("want an error")
			case tt.wantErr:
				return
			case err != nil:
				t.Fatalf("run: %v", err)
			}

			h, err := NewConfigurationHandler("test", DefaultApplicationID, tt.wantEnv)
			if err != nil {
				t.Fatalf("load %s: %v", tt.wantEnv, err)
			}

			if h.config.BaseURL == "" {
				t.Fatalf("%s was not configured", tt.wantEnv)
			}
		})
	}
}
