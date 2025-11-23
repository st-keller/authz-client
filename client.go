// Package authzclient provides a client for requesting JWT tokens from service-authz.
//
// This library implements the token-request side of ADR-036 Service Authorization.
// Services use this client to obtain JWTs for calling other platform services.
//
// Example usage:
//
//	client, err := authzclient.New(authzclient.Config{
//	    ServiceName:     "deployment-agent",
//	    ServiceAuthzURL: "https://localhost:8400",
//	    CertDir:         "/opt/deployment-agent-certs",
//	    Environment:     "staging",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	token, err := client.GetToken("ca-manager", []string{"certificates:request"})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	req.Header.Set("Authorization", "Bearer " + token)
package authzclient

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// Client handles JWT token requests to service-authz.
// Implements lazy renewal: caches token until near expiry.
// Thread-safe for concurrent use.
type Client struct {
	config     Config
	httpClient *http.Client

	// Token cache (thread-safe)
	mu          sync.RWMutex
	cachedToken string
	tokenExpiry time.Time
}

// New creates a new authz-client for service-authz.
// Returns an error if config is invalid or certificates cannot be loaded.
func New(config Config) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Load mTLS certificates
	cert, err := tls.LoadX509KeyPair(config.CertFile(), config.KeyFile())
	if err != nil {
		return nil, fmt.Errorf("authz-client: failed to load client certificate: %w", err)
	}

	caCert, err := os.ReadFile(config.CAFile())
	if err != nil {
		return nil, fmt.Errorf("authz-client: failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("authz-client: failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS13,
	}

	return &Client{
		config: config,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}, nil
}

// GetToken returns a cached token or requests a new one from service-authz.
// Implements lazy renewal: only requests new token when current token is near expiry.
//
// Parameters:
//   - targetService: the service you want to call (e.g., "ca-manager")
//   - scopes: the scopes you need (e.g., []string{"certificates:request"})
//
// Returns the JWT token string or an error.
func (c *Client) GetToken(targetService string, scopes []string) (string, error) {
	return c.GetTokenWithContext(targetService, scopes, nil)
}

// GetTokenWithContext is like GetToken but allows passing call context (ADR-036).
// Use this when you need to propagate request context through the call chain.
func (c *Client) GetTokenWithContext(targetService string, scopes []string, callContext map[string]interface{}) (string, error) {
	renewalBuffer := time.Duration(c.config.GetRenewalBufferSeconds()) * time.Second

	// Check if cached token is still valid (with renewal buffer)
	c.mu.RLock()
	if c.cachedToken != "" && time.Now().Before(c.tokenExpiry.Add(-renewalBuffer)) {
		token := c.cachedToken
		c.mu.RUnlock()
		return token, nil
	}
	c.mu.RUnlock()

	// Request new token
	if callContext == nil {
		callContext = map[string]interface{}{}
	}

	reqBody := TokenRequest{
		InstanceID:    c.config.GetInstanceID(),
		TargetService: targetService,
		Scopes:        scopes,
		Environment:   c.config.Environment,
		CallContext:   callContext,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("authz-client: failed to marshal token request: %w", err)
	}

	tokenURL := c.config.ServiceAuthzURL + c.config.GetTokenEndpoint()
	resp, err := c.httpClient.Post(tokenURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("authz-client: failed to request token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errResp)
		return "", fmt.Errorf("authz-client: token request failed (HTTP %d): %v", resp.StatusCode, errResp)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("authz-client: failed to decode token response: %w", err)
	}

	// Cache token
	c.mu.Lock()
	c.cachedToken = tokenResp.Token
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	c.mu.Unlock()

	return tokenResp.Token, nil
}

// InvalidateToken clears the cached token.
// Call this after receiving a 401 Unauthorized response to force a token refresh.
func (c *Client) InvalidateToken() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cachedToken = ""
	c.tokenExpiry = time.Time{}
}

// TokenExpiry returns the expiry time of the cached token.
// Returns zero time if no token is cached.
func (c *Client) TokenExpiry() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tokenExpiry
}

// HasValidToken returns true if a valid (non-expired) token is cached.
func (c *Client) HasValidToken() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cachedToken != "" && time.Now().Before(c.tokenExpiry)
}
