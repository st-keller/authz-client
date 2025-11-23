package authzclient

// TokenRequest represents a JWT token request to service-authz
type TokenRequest struct {
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
