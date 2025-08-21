package clitools

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/danjacques/gofslock/fslock"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// DefaultApplicationID when authorising CLI applications.
const DefaultApplicationID = "elephant-cli"

// AccessToken that can be used to communicate with our APIs.
type AccessToken struct {
	Token         string    `json:"token"`
	Expires       time.Time `json:"expires"`
	Scopes        []string  `json:"scopes"`
	GrantedScopes []string  `json:"granted_scopes"`
}

// NewConfigurationHandler crates a configuration handler and loads the current
// configuration from disk if it's available.
func NewConfigurationHandler(
	name string,
	clientID string,
	environment string,
) (*ConfigurationHandler, error) {
	ucDir, err := UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("get user configuration directory: %w", err)
	}

	configDir := filepath.Join(ucDir, "elephant-clitools", environment)

	err = os.MkdirAll(configDir, 0o700)
	if err != nil {
		return nil, fmt.Errorf("ensure environment configuration directory: %w", err)
	}

	ac := ConfigurationHandler{
		env:             environment,
		name:            name,
		clientID:        clientID,
		configDirectory: configDir,
		lockFile:        filepath.Join(configDir, "lockfile"),
		configFile:      filepath.Join(configDir, "config.json"),
		tokenFile:       filepath.Join(configDir, "tokens.json"),
		tokens:          map[string]AccessToken{},
	}

	err = ac.Load()
	if err != nil {
		return nil, err
	}

	return &ac, nil
}

type ConfigurationHandler struct {
	env             string
	name            string
	clientID        string
	configDirectory string
	lockFile        string
	configFile      string
	tokenFile       string
	config          EnvConfiguration
	tokens          map[string]AccessToken
}

// Load configuration and tokens from disk.
func (ac *ConfigurationHandler) Load() (outErr error) {
	err := fslock.With(ac.lockFile, func() error {
		var (
			config EnvConfiguration
			tokens map[string]AccessToken
		)

		err := unmarshalFile(ac.configFile, &config)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("load configuration: %w", err)
		}

		if config.Endpoints == nil {
			config.Endpoints = make(map[string]string)
		}

		config.SetDefaults(ac.env)

		err = unmarshalFile(ac.tokenFile, &tokens)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("load access tokens: %w", err)
		}

		if tokens == nil {
			tokens = make(map[string]AccessToken)
		}

		ac.config = config
		ac.tokens = tokens

		return nil
	})
	if err != nil {
		return fmt.Errorf("load config with lock: %w", err)
	}

	return nil
}

// Save configuration and tokens to disk.
func (ac *ConfigurationHandler) Save() error {
	err := fslock.With(ac.lockFile, func() error {
		err := marshalFile(ac.configFile, ac.config)
		if err != nil {
			return fmt.Errorf("save configuration: %w", err)
		}

		err = marshalFile(ac.tokenFile, ac.tokens)
		if err != nil {
			return fmt.Errorf("save token: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("save config with lock: %w", err)
	}

	return nil
}

func (ac *ConfigurationHandler) SetOIDCConfigURL(
	ctx context.Context,
	configURL string,
) error {
	env := &OIDCEnvironment{
		ConfigURL: configURL,
	}

	err := env.EnsureOIDCConfig(ctx, http.DefaultClient, 1*time.Second)
	if err != nil {
		return fmt.Errorf("invalid OIDC configuration URL: %w", err)
	}

	ac.config.OIDC = env

	return nil
}

// AddEndpoints for the environment.
func (ac *ConfigurationHandler) AddEndpoints(endpoints map[string]string) {
	maps.Copy(ac.config.Endpoints, endpoints)
}

// GetEndpoints returns all available endpoints.
func (ac *ConfigurationHandler) GetEndpoints() map[string]string {
	return maps.Clone(ac.config.Endpoints)
}

// GetEndpoints returns the specified endpoint.
func (ac *ConfigurationHandler) GetEndpoint(name string) (string, bool) {
	v, ok := ac.config.Endpoints[name]

	return v, ok
}

// Convenience function for using the OIDC configuration to get a client
// credentials token source.
func (ac *ConfigurationHandler) GetClientAccessToken(
	ctx context.Context,
	clientID string, clientSecret string,
	scopes []string,
) (oauth2.TokenSource, error) {
	err := ac.config.OIDC.EnsureOIDCConfig(ctx, http.DefaultClient, 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("ensure OIDC config: %w", err)
	}

	conf := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     ac.config.OIDC.Config.TokenEndpoint,
		Scopes:       scopes,
	}

	return conf.TokenSource(ctx), nil
}

// GetAccessToken either returns an existing non-expired token for the
// environment that matches the requested scope, or starts the authorization
// flow to get a new token.
//
// During the authorisation flow we will attempt to automatically open a URL in
// the users browser.
func (ac *ConfigurationHandler) GetAccessToken(
	ctx context.Context, scopes []string,
) (_ AccessToken, outErr error) {
	currentToken, ok := ac.tokens[ac.name]
	if ok && time.Until(currentToken.Expires) > 5*time.Minute && subsetOf(scopes, currentToken.GrantedScopes) {
		return currentToken, nil
	}

	var _z AccessToken

	oc, err := ac.GetOIDCConfig(ctx)
	if err != nil {
		return _z, fmt.Errorf("get OIDC config: %w", err)
	}

	state := make([]byte, 32)
	verifier := make([]byte, 64)

	// Generate random state and verifier.
	_, err = rand.Read(state)
	if err != nil {
		return _z, fmt.Errorf("generate random state: %w", err)
	}

	_, err = rand.Read(verifier)
	if err != nil {
		return _z, fmt.Errorf("generate random verifier: %w", err)
	}

	verifierString := base64.RawURLEncoding.EncodeToString(verifier)
	stateString := base64.RawURLEncoding.EncodeToString(state)

	// The PKCE challenge string is hashed with SHA256 and encoded as Base64-URL
	challengeHash := sha256.Sum256([]byte(verifierString))
	challengeHashString := base64.RawURLEncoding.EncodeToString(
		challengeHash[:],
	)

	authURL, err := url.Parse(oc.AuthorizationEndpoint)
	if err != nil {
		return _z, fmt.Errorf("invalid authorization endpoint: %w", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return _z, fmt.Errorf("open callback server port: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port

	redirectURL := fmt.Sprintf("http://localhost:%d", port)

	q := make(url.Values)

	q.Set("response_type", "code")
	q.Set("client_id", ac.clientID)
	q.Set("state", stateString)
	q.Set("code_challenge", challengeHashString)
	q.Set("code_challenge_method", "S256")
	q.Set("redirect_uri", redirectURL)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("kc_idp_hint", "saml")

	authURL.RawQuery = q.Encode()

	fmt.Println("Requesting a new access token")
	fmt.Printf("If a web browser doesn't automatically open, go to the following URL to log in:\n\t%s\n\n", authURL.String())

	_ = browser.OpenURL(authURL.String())

	var server http.Server

	var (
		token       AccessToken
		callbackErr error
	)

	server.Handler = handlerFunc(&callbackErr, func(w http.ResponseWriter, r *http.Request) (outErr error) {
		// Close when we're done, but spin out, as close waits for
		// handlers to finish.
		defer func() {
			go server.Close() //nolint: errcheck
		}()

		q := r.URL.Query()

		if q.Get("error") != "" {
			return fmt.Errorf("error response: %s: %s",
				q.Get("error"), q.Get("error_description"))
		}

		if q.Get("state") != stateString {
			return errors.New("invalid login state")
		}

		if q.Get("code") == "" {
			return errors.New("missing authorisation code")
		}

		data := make(url.Values)

		data.Set("client_id", ac.clientID)
		data.Set("grant_type", "authorization_code")
		data.Set("code", q.Get("code"))
		data.Set("code_verifier", verifierString)
		data.Set("redirect_uri", redirectURL)

		body := strings.NewReader(data.Encode())

		req, err := http.NewRequestWithContext(
			r.Context(), http.MethodPost, oc.TokenEndpoint, body)
		if err != nil {
			return fmt.Errorf("create token request: %w", err)
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("perform token request: %w", err)
		}

		defer safeClose(res.Body, "token response", &outErr)

		var respData grantResponse

		err = unmarshalReader(res.Body, &respData)
		if err != nil {
			return fmt.Errorf("parse grant response: %w", err)
		}

		if respData.Error != "" {
			return fmt.Errorf("grant request error response: %s: %s",
				respData.Error, respData.ErrorDescription)
		}

		if respData.AccessToken == "" {
			return errors.New("no access token in grant response")
		}

		expires := time.Now().Add(time.Duration(respData.ExpiresInSeconds) * time.Second)

		token.Token = respData.AccessToken
		token.Expires = expires
		token.Scopes = scopes
		token.GrantedScopes = strings.Split(respData.Scope, " ")

		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("You are now logged in and can close this window."))

		return nil
	})

	err = server.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return _z, fmt.Errorf("start local callback server: %w", err)
	}

	if callbackErr != nil {
		return _z, callbackErr
	}

	ac.tokens[ac.name] = token

	return token, nil
}

func subsetOf(a []string, b []string) bool {
	for _, v := range a {
		if !slices.Contains(b, v) {
			return false
		}
	}

	return true
}

func (ac *ConfigurationHandler) GetOIDCConfig(
	ctx context.Context,
) (*OIDCConfig, error) {
	ce := ac.config.OIDC

	err := ce.EnsureOIDCConfig(ctx, http.DefaultClient, 12*time.Hour)
	if err != nil {
		return nil, err
	}

	return ce.Config, nil
}

type grantResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	AccessToken      string `json:"access_token"`
	ExpiresInSeconds int    `json:"expires_in"`
	Scope            string `json:"scope"`
}

func handlerFunc(
	outErr *error,
	fn func(w http.ResponseWriter, r *http.Request) error,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := fn(w, r)
		if err != nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusBadRequest)

			_, _ = w.Write([]byte(err.Error()))
		}

		*outErr = err
	}
}

func unmarshalFile(name string, o any) (outErr error) {
	f, err := os.Open(name)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}

	defer safeClose(f, "file", &outErr)

	return unmarshalReader(f, o)
}

func safeClose(c io.Closer, name string, outErr *error) {
	err := c.Close()
	if err != nil {
		*outErr = errors.Join(*outErr, fmt.Errorf(
			"close %s: %w", name, err))
	}
}

func unmarshalReader(r io.Reader, o any) (outErr error) {
	dec := json.NewDecoder(r)

	err := dec.Decode(o)
	if err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}

	return nil
}

func marshalFile(name string, o any) (outErr error) {
	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}

	defer safeClose(f, "file", &outErr)

	enc := json.NewEncoder(f)

	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")

	err = enc.Encode(o)
	if err != nil {
		return fmt.Errorf("write JSON to file: %w", err)
	}

	return nil
}
