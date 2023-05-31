package linefido2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const defaultBaseUrl = "http://localhost:8081"

// Client is an interface for calling APIs of FIDO2 server.
type Client interface {
	// GetRegistrationOptions calls Get Reg Challenge API.
	GetRegistrationOptions(ctx context.Context, req *RegistrationOptionsRequest) (*RegistrationOptions, error)
	// RegisterCredential calls Send Reg Response API.
	RegisterCredential(ctx context.Context, req *RegisterCredentialRequest) (*RegisterCredentialResult, error)
	// GetAuthenticationOptions calls Get Auth Challenge API.
	GetAuthenticationOptions(ctx context.Context, req *AuthenticationOptionsRequest) (*AuthenticationOptions, error)
	// VerifyCredential calls Send Auth Response API.
	VerifyCredential(ctx context.Context, req *VerifyCredentialRequest) (*VerifyCredentialResult, error)
	// CheckHealth calls Get Health Check Status.
	CheckHealth(ctx context.Context) error
}

type apiUrls struct {
	registrationOptions   string
	registerCredential    string
	authenticationOptions string
	verifyCredential      string
	checkHealth           string
}

func newApiUrls(baseUrl string) apiUrls {
	return apiUrls{
		registrationOptions:   mustApiUri(baseUrl, "fido2/reg/challenge"),
		registerCredential:    mustApiUri(baseUrl, "fido2/reg/response"),
		authenticationOptions: mustApiUri(baseUrl, "fido2/auth/challenge"),
		verifyCredential:      mustApiUri(baseUrl, "fido2/auth/response"),
		checkHealth:           mustApiUri(baseUrl, "health"),
	}
}

func mustApiUri(baseUrl, path string) string {
	u, err := url.JoinPath(baseUrl, path)
	if err != nil {
		panic(err)
	}

	return u
}

type client struct {
	client  *http.Client
	baseUrl string
	urls    apiUrls
}

// NewClient creates new Client instance.
func NewClient(opts ...ClientOption) Client {
	c := &client{}

	for _, opt := range opts {
		opt(c)
	}

	if c.client == nil {
		c.client = http.DefaultClient
	}

	if c.baseUrl == "" {
		c.baseUrl = defaultBaseUrl
		c.urls = newApiUrls(defaultBaseUrl)
	}

	return c
}

// ClientOption is function for setting option to Client.
type ClientOption func(Client)

// WithHttpClient returns ClientOption for setting other http.Client to Client.
func WithHttpClient(hc *http.Client) ClientOption {
	return func(c Client) {
		cl := c.(*client)
		cl.client = hc
	}
}

// WithBaseUrl returns ClientOption for setting other base url to Client.
func WithBaseUrl(baseUrl string) ClientOption {
	return func(c Client) {
		cl := c.(*client)
		cl.baseUrl = baseUrl
		cl.urls = newApiUrls(baseUrl)
	}
}

func (c *client) GetRegistrationOptions(ctx context.Context, req *RegistrationOptionsRequest) (*RegistrationOptions, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, wrapErr(err)
	}

	body, err := c.postJSON(ctx, c.urls.registrationOptions, payload)
	if err != nil {
		return nil, wrapErr(err)
	}

	var res RegistrationOptionsResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, wrapErr(err)
	}

	return res.publish()
}

func (c *client) RegisterCredential(ctx context.Context, req *RegisterCredentialRequest) (*RegisterCredentialResult, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, wrapErr(err)
	}

	body, err := c.postJSON(ctx, c.urls.registerCredential, payload)
	if err != nil {
		return nil, wrapErr(err)
	}

	var res RegisterCredentialResultResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, wrapErr(err)
	}

	return res.publish()
}

func (c *client) GetAuthenticationOptions(ctx context.Context, req *AuthenticationOptionsRequest) (*AuthenticationOptions, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, wrapErr(err)
	}

	body, err := c.postJSON(ctx, c.urls.authenticationOptions, payload)
	if err != nil {
		return nil, wrapErr(err)
	}

	var res AuthenticationOptionsResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, wrapErr(err)
	}

	return res.publish()
}

func (c *client) VerifyCredential(ctx context.Context, req *VerifyCredentialRequest) (*VerifyCredentialResult, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, wrapErr(err)
	}

	body, err := c.postJSON(ctx, c.urls.verifyCredential, payload)
	if err != nil {
		return nil, wrapErr(err)
	}

	var res VerifyCredentialResultResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, wrapErr(err)
	}

	return res.publish()
}

func (c *client) CheckHealth(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.urls.checkHealth, nil)
	if err != nil {
		return wrapErr(err)
	}

	res, err := c.client.Do(req)
	if err != nil {
		return wrapErr(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return wrapErr(err)
		}

		return wrapErr(errors.New(string(body)))
	}

	return nil
}

func (c *client) postJSON(ctx context.Context, url string, payload []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-type", "application/json")
	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func wrapErr(err error) error {
	if _, ok := err.(ServerError); ok {
		return err
	}

	return fmt.Errorf("fido2 client error: %w", err)
}
