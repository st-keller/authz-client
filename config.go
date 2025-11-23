package authzclient

import (
	"fmt"
	"os"
)

// Config for authz-client
type Config struct {
	// ServiceName is the name of this service (e.g., "deployment-agent")
	// Used to construct certificate filenames: {ServiceName}-to-service-authz.cert.pem
	ServiceName string

	// InstanceID is the unique identity of this service instance (e.g., "deployment-agent-staging-001")
	// This is validated by service-authz against the mTLS cert CN (must start with ServiceName)
	// See ADR-036: Identity Validation Architecture (Wege und Schlagbäume)
	// If empty, reads from SERVICE_INSTANCE_ID environment variable
	InstanceID string

	// ServiceAuthzURL is the full URL to service-authz (e.g., "https://localhost:8400")
	// No defaults - must be explicitly configured!
	ServiceAuthzURL string

	// CertDir is the directory containing mTLS certificates
	// Expected files:
	//   - {ServiceName}-to-service-authz.cert.pem
	//   - {ServiceName}-to-service-authz.key.pem
	//   - ca.cert.pem OR ca-chain.cert.pem
	CertDir string

	// Environment is passed to service-authz in token requests (e.g., "staging", "production")
	Environment string

	// TokenEndpoint is the path to the token endpoint (default: "/api/v1/token")
	TokenEndpoint string

	// RenewalBuffer is how long before expiry to renew token (default: 5 minutes worth of seconds)
	RenewalBufferSeconds int
}

// Validate checks that all required config fields are set
func (c *Config) Validate() error {
	if c.ServiceName == "" {
		return fmt.Errorf("authz-client: ServiceName is required")
	}
	if c.ServiceAuthzURL == "" {
		return fmt.Errorf("authz-client: ServiceAuthzURL is required")
	}
	if c.CertDir == "" {
		return fmt.Errorf("authz-client: CertDir is required")
	}
	if c.Environment == "" {
		return fmt.Errorf("authz-client: Environment is required")
	}
	// InstanceID must be set either in config or via SERVICE_INSTANCE_ID env var
	if c.GetInstanceID() == "" {
		return fmt.Errorf("authz-client: InstanceID is required (set in config or SERVICE_INSTANCE_ID env var)")
	}
	return nil
}

// GetInstanceID returns the instance ID (from config or SERVICE_INSTANCE_ID env var)
// This is the unique identity used in JWT subject claims
func (c *Config) GetInstanceID() string {
	if c.InstanceID != "" {
		return c.InstanceID
	}
	return os.Getenv("SERVICE_INSTANCE_ID")
}

// CertFile returns the path to the client certificate
func (c *Config) CertFile() string {
	return c.CertDir + "/" + c.ServiceName + "-to-service-authz.cert.pem"
}

// KeyFile returns the path to the client private key
func (c *Config) KeyFile() string {
	return c.CertDir + "/" + c.ServiceName + "-to-service-authz.key.pem"
}

// CAFile returns the path to the CA certificate (auto-detects ca-chain.cert.pem vs ca.cert.pem)
func (c *Config) CAFile() string {
	chainFile := c.CertDir + "/ca-chain.cert.pem"
	if _, err := os.Stat(chainFile); err == nil {
		return chainFile
	}
	return c.CertDir + "/ca.cert.pem"
}

// GetTokenEndpoint returns the token endpoint path (with default)
func (c *Config) GetTokenEndpoint() string {
	if c.TokenEndpoint == "" {
		return "/api/v1/token"
	}
	return c.TokenEndpoint
}

// GetRenewalBufferSeconds returns the renewal buffer (with default of 300 = 5 minutes)
func (c *Config) GetRenewalBufferSeconds() int {
	if c.RenewalBufferSeconds == 0 {
		return 300 // 5 minutes
	}
	return c.RenewalBufferSeconds
}
