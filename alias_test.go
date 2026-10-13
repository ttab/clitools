package clitools

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestOIDCServer(t *testing.T) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		_ = json.NewEncoder(w).Encode(OIDCConfig{
			Issuer:                "http://" + r.Host + strings.TrimSuffix(r.URL.Path, oidcWellKnownPath),
			AuthorizationEndpoint: "http://" + r.Host + "/auth",
			TokenEndpoint:         "http://" + r.Host + "/token",
		})
	}))

	t.Cleanup(srv.Close)

	return srv
}

func configureTestEnv(t *testing.T, srv *httptest.Server, env string) {
	t.Helper()

	h, err := NewConfigurationHandler("test", DefaultApplicationID, env)
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}

	err = h.SetOIDCConfigURL(t.Context(), srv.URL+"/realms/"+env)
	if err != nil {
		t.Fatalf("set OIDC: %v", err)
	}

	err = h.SetBaseURL("https://" + env + ".example.com")
	if err != nil {
		t.Fatalf("set base URL: %v", err)
	}

	err = h.Save()
	if err != nil {
		t.Fatalf("save: %v", err)
	}
}

func TestUnconfiguredEnvironmentIsAnError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	h, err := NewConfigurationHandler("test", DefaultApplicationID, "stage")
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}

	if h.IsConfigured() {
		t.Fatal("a new environment should not be configured")
	}

	_, err = h.GetAccessToken(t.Context(), []string{"doc_read"})
	if err == nil || !strings.Contains(err.Error(), "no OIDC configuration") {
		t.Fatalf("GetAccessToken: got %v, want a not configured error", err)
	}

	_, err = h.GetClientAccessToken(t.Context(), "id", "secret", nil)
	if err == nil || !strings.Contains(err.Error(), "no OIDC configuration") {
		t.Fatalf("GetClientAccessToken: got %v, want a not configured error", err)
	}
}

func TestAliasSharesConfigurationAndTokens(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	srv := newTestOIDCServer(t)

	configureTestEnv(t, srv, "tt-stage")

	err := SetEnvironmentAlias("stage", "tt-stage")
	if err != nil {
		t.Fatalf("set alias: %v", err)
	}

	h, err := NewConfigurationHandler("test", DefaultApplicationID, "stage")
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}

	if h.Environment() != "tt-stage" {
		t.Fatalf("Environment() = %q, want tt-stage", h.Environment())
	}

	repo, _ := h.GetEndpoint("repository")
	if repo != "https://repository.api.tt-stage.example.com" {
		t.Fatalf("unexpected repository endpoint %q", repo)
	}

	h.tokens["test"] = AccessToken{
		Token:         "shared",
		Expires:       time.Now().Add(time.Hour),
		GrantedScopes: []string{"doc_read"},
	}

	err = h.Save()
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	target, err := NewConfigurationHandler("test", DefaultApplicationID, "tt-stage")
	if err != nil {
		t.Fatalf("create target handler: %v", err)
	}

	tok, err := target.GetAccessToken(t.Context(), []string{"doc_read"})
	if err != nil {
		t.Fatalf("get token through target: %v", err)
	}

	if tok.Token != "shared" {
		t.Fatalf("token saved through the alias didn't land in the target")
	}

	baseDir, _ := environmentsDir()

	_, err = os.Stat(filepath.Join(baseDir, "stage", "tokens.json"))
	if !os.IsNotExist(err) {
		t.Fatalf("the alias should hold no tokens of its own: %v", err)
	}
}

func TestAliasesCannotBeChained(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	srv := newTestOIDCServer(t)

	configureTestEnv(t, srv, "tt-stage")

	err := SetEnvironmentAlias("stage", "tt-stage")
	if err != nil {
		t.Fatalf("set alias: %v", err)
	}

	err = SetEnvironmentAlias("s", "stage")
	if err == nil {
		t.Fatal("aliasing an alias should fail")
	}

	configureTestEnv(t, srv, "other")

	err = SetEnvironmentAlias("tt-stage", "other")
	if err == nil {
		t.Fatal("turning an alias target into an alias should fail")
	}

	err = SetEnvironmentAlias("x", "missing")
	if err == nil {
		t.Fatal("aliasing an unconfigured environment should fail")
	}

	err = SetEnvironmentAlias("x", "../tt-stage")
	if err == nil {
		t.Fatal("an environment name with a path separator should fail")
	}
}

func TestConfigureWellKnown(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	srv := newTestOIDCServer(t)

	// A real environment that predates --well-known, and a directory
	// left behind by a tool that looked up an unconfigured environment.
	configureTestEnv(t, srv, "prod")

	_, err := NewConfigurationHandler("test", DefaultApplicationID, "stage")
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}

	envs := []wellKnownEnvironment{
		{Name: "tt-stage", OIDC: srv.URL + "/realms/elephant", BaseURL: "https://stage.tt.example.com"},
		{Name: "tt-prod", OIDC: srv.URL + "/realms/elephant", BaseURL: "https://tt.example.com"},
	}

	var out bytes.Buffer

	err = configureWellKnown(t.Context(), "test", DefaultApplicationID,
		envs, wellKnownAliases, &out)
	if err != nil {
		t.Fatalf("configure well-known: %v", err)
	}

	stage, err := NewConfigurationHandler("test", DefaultApplicationID, "stage")
	if err != nil {
		t.Fatalf("load stage: %v", err)
	}

	if stage.Environment() != "tt-stage" || !stage.IsConfigured() {
		t.Fatalf("stage should be an alias for a configured tt-stage, got %q", stage.Environment())
	}

	prod, err := NewConfigurationHandler("test", DefaultApplicationID, "prod")
	if err != nil {
		t.Fatalf("load prod: %v", err)
	}

	if prod.Environment() != "prod" || prod.config.BaseURL != "https://prod.example.com" {
		t.Fatalf("an existing prod should be left alone, got %q at %q",
			prod.Environment(), prod.config.BaseURL)
	}

	if !strings.Contains(out.String(), "prod: already configured, left alone") {
		t.Fatalf("unexpected output:\n%s", out.String())
	}

	// Running it again is a no-op for the aliases.
	out.Reset()

	err = configureWellKnown(context.Background(), "test", DefaultApplicationID,
		envs, wellKnownAliases, &out)
	if err != nil {
		t.Fatalf("configure well-known again: %v", err)
	}

	if !strings.Contains(out.String(), "stage: already an alias for tt-stage") {
		t.Fatalf("unexpected output:\n%s", out.String())
	}
}
