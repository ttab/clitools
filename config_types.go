package clitools

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type appConfiguration[T any] struct {
	Environments  map[string]*OIDCEnvironment `json:"environments"`
	Configuration T                           `json:"configuration"`
}

type OIDCEnvironment struct {
	Refreshed     time.Time   `json:"refreshed,omitempty,omitzero"`
	OIDCConfigURL string      `json:"oidc_config_url,omitempty"`
	OIDCConfig    *OIDCConfig `json:"oidc_config"`
}

func (ce *OIDCEnvironment) EnsureOIDCConfig(
	ctx context.Context, client *http.Client, maxAge time.Duration,
) (outErr error) {
	if ce.OIDCConfig != nil && (ce.OIDCConfigURL == "" || time.Since(ce.Refreshed) < maxAge) {
		return nil
	}

	if ce.OIDCConfigURL == "" {
		return errors.New("no OIDC config or URL has been set")
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

	var conf OIDCConfig

	err = unmarshalReader(res.Body, &conf)
	if err != nil {
		return fmt.Errorf("parse OIDC config: %w", err)
	}

	ce.Refreshed = time.Now()
	ce.OIDCConfig = &conf

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
