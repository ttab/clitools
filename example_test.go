package clitools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/ttab/clitools"
)

// Example demonstrates authenticating against an Elephant environment and
// looking up service endpoints. The environment must have been configured
// beforehand using the "configure" CLI command.
func Example() {
	env := "tt-prod"

	app, err := clitools.NewConfigurationHandler(
		"clitools", clitools.DefaultApplicationID, env,
	)
	if err != nil {
		panic(fmt.Errorf("create configuration handler: %w", err))
	}

	// Look up a service endpoint. If a base URL has been configured this
	// will derive the endpoint automatically.
	repoURL, ok := app.GetEndpoint("repository")
	if !ok {
		panic("no repository endpoint configured")
	}

	fmt.Println("Repository endpoint:", repoURL)

	// Authenticate using the OIDC authorization code flow. This will open
	// a browser window for the user to log in, unless a valid cached token
	// is available.
	token, err := app.GetAccessToken(context.Background(), []string{
		"doc_read",
	})
	if err != nil {
		panic(fmt.Errorf("authenticate: %w", err))
	}

	err = app.Save()
	if err != nil {
		panic(fmt.Errorf("save configuration: %w", err))
	}

	enc := json.NewEncoder(os.Stdout)

	enc.SetIndent("", "  ")

	fmt.Println("Current token:")
	_ = enc.Encode(token)
}

func TestExample(t *testing.T) {
	if !testing.Verbose() {
		return
	}

	Example()
}
