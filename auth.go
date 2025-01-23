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
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pkg/browser"
)

const (
	EnvLocal           = "local"
	EnvStage           = "stage"
	EnvProd            = "prod"
	StageOIDCConfigURL = "https://login.stage.tt.se/realms/elephant/.well-known/openid-configuration"
	ProdOIDCConfigURL  = "https://login.tt.se/realms/elephant/.well-known/openid-configuration"
)

var defaultEnvs = map[string]string{
	EnvLocal: StageOIDCConfigURL,
	EnvStage: StageOIDCConfigURL,
	EnvProd:  ProdOIDCConfigURL,
}

func NewConfigurationHandler[T any](name string, clientID string) (*ConfigurationHandler[T], error) {
	ucDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("get user configuration directory: %w", err)
	}

	configDir := filepath.Join(ucDir, name)

	err = os.MkdirAll(configDir, 0o700)
	if err != nil {
		return nil, fmt.Errorf("ensure application configuration directory: %w", err)
	}

	ac := ConfigurationHandler[T]{
		name:            name,
		clientID:        clientID,
		configDirectory: configDir,
		configFile:      filepath.Join(configDir, "config.json"),
	}

	err = unmarshalFile(ac.configFile, &ac.config)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("load current configuration: %w", err)
	}

	if ac.config.Environments == nil {
		ac.config.Environments = make(map[string]*configuredEnvironment)
	}

	if ac.config.Tokens == nil {
		ac.config.Tokens = make(map[string]AccessToken)
	}

	for name, confURL := range defaultEnvs {
		_, isSet := ac.config.Environments[name]
		if isSet {
			continue
		}

		ac.config.Environments[name] = &configuredEnvironment{
			OIDCConfigURL: confURL,
		}
	}

	return &ac, nil
}

type ConfigurationHandler[T any] struct {
	name            string
	clientID        string
	configDirectory string
	configFile      string
	config          appConfiguration[T]
}

func (ac *ConfigurationHandler[T]) RegisterEnvironment(
	ctx context.Context,
	name string, configURL string,
) error {
	ce := ac.config.Environments[name]

	if ce.OIDCConfigURL != configURL {
		ce.OIDCConfigURL = configURL
		ce.OIDCConfig = nil
	}

	err := ce.EnsureOIDCConfig(ctx, http.DefaultClient, 12*time.Hour)
	if err != nil {
		return err
	}

	return nil
}

func (ac *ConfigurationHandler[T]) Save() error {
	return marshalFile(ac.configFile, ac.config)
}

func (ac *ConfigurationHandler[T]) GetConfiguration() T {
	return ac.config.Configuration
}

func (ac *ConfigurationHandler[T]) SetConfiguration(conf T) {
	ac.config.Configuration = conf
}

func (ac *ConfigurationHandler[T]) GetAccessToken(
	ctx context.Context, environment string, scopes []string,
) (_ AccessToken, outErr error) {
	currentToken, ok := ac.config.Tokens[environment]
	if ok && time.Until(currentToken.Expires) > 5*time.Minute && slices.Equal(currentToken.Scopes, scopes) {
		return currentToken, nil
	}

	var _z AccessToken

	oc, err := ac.getOIDCConfig(ctx, environment)
	if err != nil {
		return _z, fmt.Errorf(
			"get %q OIDC config: %w", environment, err)
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

	server := http.Server{
		Addr: "127.0.0.1:4000",
	}

	var (
		token       AccessToken
		callbackErr error
	)

	server.Handler = handlerFunc(&callbackErr, func(w http.ResponseWriter, r *http.Request) (outErr error) {
		// Close when we're done, but spin out, as close waits for
		// handlers to finish.
		defer func() {
			go server.Close()
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

		err = unmarshalReader(res.Body, &respData, false)
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

		return nil
	})

	err = server.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return _z, fmt.Errorf("start local callback server: %w", err)
	}

	if callbackErr != nil {
		return _z, callbackErr
	}

	ac.config.Tokens[environment] = token

	return token, nil
}

func (ac *ConfigurationHandler[T]) getOIDCConfig(
	ctx context.Context, environment string,
) (*oidcConfig, error) {
	ce, ok := ac.config.Environments[environment]
	if !ok {
		return nil, fmt.Errorf("unknown environment %q", environment)
	}

	err := ce.EnsureOIDCConfig(ctx, http.DefaultClient, 12*time.Hour)
	if err != nil {
		return nil, err
	}

	return ce.OIDCConfig, nil
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

	return unmarshalReader(f, o, true)
}

func safeClose(c io.Closer, name string, outErr *error) {
	err := c.Close()
	if err != nil {
		*outErr = errors.Join(*outErr, fmt.Errorf(
			"close %s: %w", name, err))
	}
}

func unmarshalReader(r io.Reader, o any, disallowUnknown bool) (outErr error) {
	dec := json.NewDecoder(r)

	if disallowUnknown {
		dec.DisallowUnknownFields()
	}

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