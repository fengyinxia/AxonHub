package xai

import "github.com/looplj/axonhub/llm/oauth"

const (
	// DiscoveryURL is the OIDC discovery endpoint used to resolve xAI OAuth endpoints dynamically.
	DiscoveryURL = "https://auth.x.ai/.well-known/openid-configuration"

	// ClientID is the public xAI Grok CLI OAuth client ID.
	ClientID = "b1a00492-073a-47ea-816f-4c329264a828"

	// RedirectURI is the loopback callback URI registered for the xAI OAuth client.
	RedirectURI = "http://127.0.0.1:56121/callback"

	// Scopes is the OAuth scope set required for xAI API access.
	Scopes = "openid profile email offline_access grok-cli:access api:access"

	// FallbackAuthorizeURL is used if OIDC discovery is unavailable.
	FallbackAuthorizeURL = "https://auth.x.ai/oauth/authorize"

	// FallbackTokenURL is used if OIDC discovery is unavailable.
	FallbackTokenURL = "https://auth.x.ai/oauth/token"
)

// FallbackOAuthUrls holds the hardcoded xAI OAuth endpoints as a fallback.
// In production, endpoints are resolved dynamically via OIDC discovery.
var FallbackOAuthUrls = oauth.OAuthUrls{
	AuthorizeUrl: FallbackAuthorizeURL,
	TokenUrl:     FallbackTokenURL,
}

// DefaultOAuthModels returns the static model list for xai_oauth channels.
// xAI's Responses API does not expose a stable /models endpoint for OAuth sessions,
// so we maintain a local catalog (mirroring the xAI Grok model registry).
func DefaultOAuthModels() []string {
	return []string{
		"grok-4.3",
		"grok-4.20-0309-reasoning",
		"grok-4.20-0309-non-reasoning",
		"grok-4.20-multi-agent-0309",
		"grok-3",
		"grok-3-mini",
		"grok-3-mini-fast",
	}
}
