package clitools

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

type appConfiguration[T any] struct {
	Environments  map[string]*configuredEnvironment `json:"environments"`
	Configuration T                                 `json:"configuration"`
	Tokens        map[string]AccessToken            `json:"tokens"`
}

type configuredEnvironment struct {
	Refreshed     time.Time   `json:"refreshed"`
	OIDCConfigURL string      `json:"oidc_config_url"`
	OIDCConfig    *oidcConfig `json:"oidc_config"`
}

func (ce *configuredEnvironment) EnsureOIDCConfig(
	ctx context.Context, client *http.Client, maxAge time.Duration,
) (outErr error) {
	if ce.OIDCConfig != nil && time.Since(ce.Refreshed) < maxAge {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ce.OIDCConfigURL, nil)
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

	var conf oidcConfig

	err = unmarshalReader(res.Body, &conf, false)
	if err != nil {
		return fmt.Errorf("parse OIDC config: %w", err)
	}

	ce.Refreshed = time.Now()
	ce.OIDCConfig = &conf

	return nil
}

type oidcConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

type AccessToken struct {
	Token         string    `json:"token"`
	Expires       time.Time `json:"expires"`
	Scopes        []string  `json:"scopes"`
	GrantedScopes []string  `json:"granted_scopes"`
}
