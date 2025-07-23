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
	// SampleConf - any addional configuration you want to store.
	type SampleConf struct {
		SomeSetting string `json:"some_setting"`
	}

	env := "stage"

	oidcURL, err := clitools.OIDCConfigURL(clitools.StageOIDCServer, "elephant")
	if err != nil {
		panic(fmt.Errorf("get realm OIDC config URL: %w", err))
	}

	println("Sample application that demonstrates logging in to elephant from a CLI tool\n")

	app, err := clitools.NewConfigurationHandler[SampleConf](
		"clitools", clitools.DefaultApplicationID,
		env, oidcURL,
	)
	if err != nil {
		panic(fmt.Errorf("create configuration handler: %w", err))
	}

	token, err := app.GetAccessToken(context.Background(), env, []string{
		"doc_read",
	})
	if err != nil {
		panic(fmt.Errorf("authenticate: %w", err))
	}

	app.SetConfiguration(SampleConf{
		SomeSetting: "that we want to track",
	})

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
