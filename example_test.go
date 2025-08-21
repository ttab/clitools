package clitools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/ttab/clitools"
)

func Example() {
	env := "stage"

	println("Sample application that demonstrates logging in to elephant from a CLI tool\n")

	app, err := clitools.NewConfigurationHandler(
		"clitools", clitools.DefaultApplicationID, env,
	)
	if err != nil {
		panic(fmt.Errorf("create configuration handler: %w", err))
	}

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

	println("Current token:")
	_ = enc.Encode(token)
}

func TestExample(t *testing.T) {
	if !testing.Verbose() {
		return
	}

	Example()
}
