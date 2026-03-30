package clitools

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type EnvConfiguration struct {
	OIDC      *OIDCEnvironment `json:"oidc"`
	BaseURL   string           `json:"base_url,omitempty"`
	Endpoints map[string]string
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

func elephantEndpoints(proto string, base string) map[string]string {
	return map[string]string{
		"chrome":     fmt.Sprintf("%s://%s/elephant", proto, base),
		"repository": ElephantAPIEndpoint(proto, base, "repository"),
		"index":      ElephantAPIEndpoint(proto, base, "index"),
		"spell":      ElephantAPIEndpoint(proto, base, "spell"),
		"user":       ElephantAPIEndpoint(proto, base, "user"),
		"baboon":     ElephantAPIEndpoint(proto, base, "baboon"),
		"wires":      ElephantAPIEndpoint(proto, base, "wires"),
	}
}

// ElephantAPIEndpoint constructs a standard API endpoint URL.
func ElephantAPIEndpoint(proto, base, name string) string {
	return fmt.Sprintf("%s://%s.api.%s", proto, name, base)
}

// EndpointFromBaseURL constructs an endpoint URL from the configured base URL.
// Explicit endpoints take precedence and should be checked first.
func (ec *EnvConfiguration) EndpointFromBaseURL(name string) (string, bool) {
	if ec.BaseURL == "" {
		return "", false
	}

	u, err := url.Parse(ec.BaseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}

	if name == "chrome" {
		return ec.BaseURL + "/elephant", true
	}

	return ElephantAPIEndpoint(u.Scheme, u.Host, name), true
}

// BaseURLEndpoints returns the standard set of elephant endpoints derived from
// the base URL. Returns an empty map if no base URL is configured.
func (ec *EnvConfiguration) BaseURLEndpoints() map[string]string {
	if ec.BaseURL == "" {
		return make(map[string]string)
	}

	u, err := url.Parse(ec.BaseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return make(map[string]string)
	}

	return elephantEndpoints(u.Scheme, u.Host)
}
