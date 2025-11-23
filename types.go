package authzclient

// TokenRequest represents a JWT token request to service-authz
type TokenRequest struct {
	// InstanceID is the unique identity of this service instance (e.g., "app-manager-staging-001")
	// service-authz validates that this starts with the source service type from the mTLS cert CN
	// See ADR-036: Identity Validation Architecture (Wege und Schlagbäume)
	InstanceID    string                 `json:"instance_id"`
	TargetService string                 `json:"target_service"`
	Scopes        []string               `json:"scopes"`
	Environment   string                 `json:"environment"`
	CallContext   map[string]interface{} `json:"call_context"`
}

// TokenResponse represents a JWT token response from service-authz
type TokenResponse struct {
	Token         string   `json:"token"`
	TokenType     string   `json:"token_type"`
	ExpiresIn     int      `json:"expires_in"`
	GrantedScopes []string `json:"granted_scopes"`
}
