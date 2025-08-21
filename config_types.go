package clitools

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type EnvConfiguration struct {
	OIDC      *OIDCEnvironment `json:"oidc"`
	Endpoints map[string]string
}

func (ec *EnvConfiguration) SetDefaults(env string) {
	defaults, ok := known[env]
	if !ok {
		return
	}

	for name, endpoint := range defaults.Endpoints {
		_, isSet := ec.Endpoints[name]
		if isSet {
			continue
		}

		ec.Endpoints[name] = endpoint
	}

	if ec.OIDC == nil {
		ec.OIDC = &OIDCEnvironment{
			ConfigURL: defaults.OIDCConfig,
		}
	}
}

type OIDCEnvironment struct {
	Refreshed time.Time   `json:"refreshed,omitempty,omitzero"`
	ConfigURL string      `json:"oidc_config_url,omitempty"`
	Config    *OIDCConfig `json:"oidc_config"`
}

func (ce *OIDCEnvironment) EnsureOIDCConfig(
	ctx context.Context, client *http.Client, maxAge time.Duration,
) (outErr error) {
	if ce.Config != nil && (ce.ConfigURL == "" || time.Since(ce.Refreshed) < maxAge) {
		return nil
	}

	if ce.ConfigURL == "" {
		return errors.New("no OIDC config or URL has been set")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ce.ConfigURL, nil)
	if err != nil {
		return fmt.Errorf("create OIDC config request: %w", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch OIDC config: %w", err)
	}

	defer safeClose(res.Body, "OIDC config response", &outErr)

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("error response: %s", res.Status)
	}

	var conf OIDCConfig

	err = unmarshalReader(res.Body, &conf)
	if err != nil {
		return fmt.Errorf("parse OIDC config: %w", err)
	}

	ce.Refreshed = time.Now()
	ce.Config = &conf

	return nil
}

type OIDCConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

type knownEnv struct {
	OIDCConfig string
	Endpoints  map[string]string
}

var known = map[string]knownEnv{
	"local-demo": {
		OIDCConfig: "http://elsinod.demo.ecms.test/.well-known/openid-configuration",
		Endpoints:  elephantEndpoints("https", "demo.ecms.test"),
	},
	"prod": {
		OIDCConfig: "https://login.tt.se/realms/elephant/.well-known/openid-configuration",
		Endpoints:  elephantEndpoints("https", "tt.ecms.se"),
	},
	"stage": {
		OIDCConfig: "https://login.stage.tt.se/realms/elephant/.well-known/openid-configuration",
		Endpoints: map[string]string{
			// Not a fully standardised environment.
			"chrome":     "https://stage.tt.se/elephant",
			"repository": "https://repository.stage.tt.se",
			"index":      "https://elephant-index.stage.tt.se",
			"spell":      "https://spell.api.stage.tt.se",
			"user":       "https://user.api.stage.tt.se",
			"baboon":     "https://baboon.api.stage.tt.se",
			"wires":      "https://wires.api.stage.tt.se",
		},
	},
}

func elephantEndpoints(proto string, base string) map[string]string {
	return map[string]string{
		"chrome":     fmt.Sprintf("%s://%s/elephant", proto, base),
		"repository": ElephantAPIEndpoint(proto, base, "respository"),
		"index":      ElephantAPIEndpoint(proto, base, "index"),
		"spell":      ElephantAPIEndpoint(proto, base, "spell"),
		"user":       ElephantAPIEndpoint(proto, base, "user"),
		"baboon":     ElephantAPIEndpoint(proto, base, "baboon"),
		"wires":      ElephantAPIEndpoint(proto, base, "wires"),
	}
}

func ElephantAPIEndpoint(proto, base, name string) string {
	return fmt.Sprintf("%s://%s.api.%s", proto, name, base)
}
