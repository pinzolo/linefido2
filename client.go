package linefido2

import (
	"bytes"
	"context"
	"encoding/json"
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
	// GetCredentialById calls Get Credential by CredentialId API.
	GetCredentialById(ctx context.Context, credentialId, rpId string) (*UserKey, error)
	// GetCredentialsByUserId calls Get Credential by UserId API.
	GetCredentialsByUserId(ctx context.Context, rpId, userId string) ([]*UserKey, error)
	// DeleteCredentialById calls Delete Credential by CredentialId API.
	DeleteCredentialById(ctx context.Context, credentialId, rpId string) error
	// DeleteCredentialsByUserId calls Delete Credential by UserId API.
	DeleteCredentialsByUserId(ctx context.Context, rpId, userId string) error
	// CheckHealth calls Get Health Check Status.
	CheckHealth(ctx context.Context) error
}

type apiUrls struct {
	registrationOptions   string
	registerCredential    string
	authenticationOptions string
	verifyCredential      string
	credentialsBase       string
	checkHealth           string
}

func newApiUrls(baseUrl string) apiUrls {
	return apiUrls{
		registrationOptions:   mustApiUri(baseUrl, "fido2/reg/challenge"),
		registerCredential:    mustApiUri(baseUrl, "fido2/reg/response"),
		authenticationOptions: mustApiUri(baseUrl, "fido2/auth/challenge"),
		verifyCredential:      mustApiUri(baseUrl, "fido2/auth/response"),
		credentialsBase:       mustApiUri(baseUrl, "fido2/credentials"),
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

func (c *client) GetCredentialById(ctx context.Context, credentialId, rpId string) (*UserKey, error) {
	apiUrl := mustApiUri(c.urls.credentialsBase, credentialId)
	body, err := c.doGet(ctx, apiUrl, map[string]string{
		"rpId": rpId,
	})
	if err != nil {
		return nil, wrapErr(err)
	}

	var res CredentialResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, wrapErr(err)
	}

	return res.publish()
}

func (c *client) GetCredentialsByUserId(ctx context.Context, rpId, userId string) ([]*UserKey, error) {
	body, err := c.doGet(ctx, c.urls.credentialsBase, map[string]string{
		"rpId":   rpId,
		"userId": userId,
	})
	if err != nil {
		return nil, wrapErr(err)
	}

	var res CredentialsResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, wrapErr(err)
	}

	return res.publish()
}

func (c *client) DeleteCredentialById(ctx context.Context, credentialId, rpId string) error {
	apiUrl := mustApiUri(c.urls.credentialsBase, credentialId)
	_, err := c.doDelete(ctx, apiUrl, map[string]string{
		"rpId": rpId,
	})
	if err != nil {
		return wrapErr(err)
	}

	return nil
}

func (c *client) DeleteCredentialsByUserId(ctx context.Context, rpId, userId string) error {
	_, err := c.doDelete(ctx, c.urls.credentialsBase, map[string]string{
		"rpId":   rpId,
		"userId": userId,
	})
	if err != nil {
		return wrapErr(err)
	}

	return nil
}

func (c *client) CheckHealth(ctx context.Context) error {
	_, err := c.doGet(ctx, c.urls.checkHealth, nil)
	if err != nil {
		return wrapErr(err)
	}

	return nil
}

func (c *client) postJSON(ctx context.Context, apiUrl string, payload []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiUrl, bytes.NewBuffer(payload))
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

	if res.StatusCode >= http.StatusBadRequest {
		return nil, convertBodyToError(body)
	}

	return body, nil
}

func (c *client) doGet(ctx context.Context, apiUrl string, params map[string]string) ([]byte, error) {
	return c.handleNoResult(ctx, http.MethodGet, apiUrl, params)
}

func (c *client) doDelete(ctx context.Context, apiUrl string, params map[string]string) ([]byte, error) {
	return c.handleNoResult(ctx, http.MethodDelete, apiUrl, params)
}

func (c *client) handleNoResult(ctx context.Context, method string, apiUrl string, params map[string]string) ([]byte, error) {
	u, err := url.Parse(apiUrl)
	if err != nil {
		return nil, err
	}

	if params != nil {
		q := u.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, err
	}

	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	err = convertBodyToError(body)
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

func convertBodyToError(body []byte) error {
	res := new(BaseResponse)
	err := json.Unmarshal(body, res)
	if err != nil {
		return err
	}

	if res.hasError() {
		return ServerError{ServerResponse: res.ServerResponse}
	}

	return nil
}
