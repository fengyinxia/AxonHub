package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/fx"

	"github.com/looplj/axonhub/internal/log"
	"github.com/looplj/axonhub/internal/pkg/xcache"
	"github.com/looplj/axonhub/llm/httpclient"
	"github.com/looplj/axonhub/llm/oauth"
	xaiconstants "github.com/looplj/axonhub/llm/transformer/xai"
)

type XaiHandlersParams struct {
	fx.In

	CacheConfig xcache.Config
	HttpClient  *httpclient.HttpClient
}

type XaiHandlers struct {
	// stateCache 存储 PKCE code_verifier 和动态 token_url（10 分钟 TTL）
	stateCache xcache.Cache[xaiOAuthState]
	httpClient *httpclient.HttpClient
}

func NewXaiHandlers(params XaiHandlersParams) *XaiHandlers {
	return &XaiHandlers{
		stateCache: xcache.NewFromConfig[xaiOAuthState](params.CacheConfig),
		httpClient: params.HttpClient,
	}
}

type StartXaiOAuthRequest struct{}

type StartXaiOAuthResponse struct {
	SessionID string `json:"session_id"`
	AuthURL   string `json:"auth_url"`
}

// xaiOAuthState 同时保存 PKCE verifier 和 OIDC 动态发现得到的 token_url。
type xaiOAuthState struct {
	CodeVerifier string `json:"code_verifier"`
	TokenURL     string `json:"token_url"`
	AuthorizeURL string `json:"authorize_url"`
	CreatedAt    int64  `json:"created_at"`
}

func generateXaiCodeVerifier() (string, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}

func generateXaiCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}

func generateXaiState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}

func xaiOAuthCacheKey(sessionID string) string {
	return fmt.Sprintf("xai:oauth:%s", sessionID)
}

// xaiOIDCEndpoints 是 OIDC discovery 响应的最小子集。
type xaiOIDCEndpoints struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// discoverXaiOIDCEndpoints 通过 OIDC discovery 获取 authorize/token endpoint，
// 任意失败均回退到硬编码的 Fallback 值。
func discoverXaiOIDCEndpoints(ctx context.Context, httpClient *httpclient.HttpClient) xaiOIDCEndpoints {
	fallback := xaiOIDCEndpoints{
		AuthorizationEndpoint: xaiconstants.FallbackAuthorizeURL,
		TokenEndpoint:         xaiconstants.FallbackTokenURL,
	}

	req := &httpclient.Request{
		Method:  http.MethodGet,
		URL:     xaiconstants.DiscoveryURL,
		Headers: http.Header{"Accept": []string{"application/json"}},
	}

	resp, err := httpClient.Do(ctx, req)
	if err != nil {
		log.Warn(ctx, "xai oidc discovery failed, using fallback endpoints", log.Cause(err))
		return fallback
	}

	var endpoints xaiOIDCEndpoints
	if err := json.Unmarshal(resp.Body, &endpoints); err != nil {
		log.Warn(ctx, "xai oidc discovery response invalid, using fallback endpoints", log.Cause(err))
		return fallback
	}

	if endpoints.AuthorizationEndpoint == "" {
		endpoints.AuthorizationEndpoint = xaiconstants.FallbackAuthorizeURL
	}

	if endpoints.TokenEndpoint == "" {
		endpoints.TokenEndpoint = xaiconstants.FallbackTokenURL
	}

	return endpoints
}

// StartOAuth 生成 PKCE 会话并通过 OIDC discovery 构建授权 URL。
// POST /admin/xai/oauth/start
func (h *XaiHandlers) StartOAuth(c *gin.Context) {
	ctx := c.Request.Context()

	var req StartXaiOAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		JSONError(c, http.StatusBadRequest, errors.New("invalid request format"))
		return
	}

	state, err := generateXaiState()
	if err != nil {
		JSONError(c, http.StatusInternalServerError, fmt.Errorf("failed to generate oauth state: %w", err))
		return
	}

	codeVerifier, err := generateXaiCodeVerifier()
	if err != nil {
		JSONError(c, http.StatusInternalServerError, fmt.Errorf("failed to generate code verifier: %w", err))
		return
	}

	codeChallenge := generateXaiCodeChallenge(codeVerifier)

	// 单次 OIDC discovery，同时拿到 authorize_url 和 token_url
	oidcEndpoints := discoverXaiOIDCEndpoints(ctx, h.httpClient)

	cacheKey := xaiOAuthCacheKey(state)
	if err := h.stateCache.Set(ctx, cacheKey, xaiOAuthState{
		CodeVerifier: codeVerifier,
		TokenURL:     oidcEndpoints.TokenEndpoint,
		AuthorizeURL: oidcEndpoints.AuthorizationEndpoint,
		CreatedAt:    time.Now().Unix(),
	}, xcache.WithExpiration(10*time.Minute)); err != nil {
		JSONError(c, http.StatusInternalServerError, fmt.Errorf("failed to save oauth state: %w", err))
		return
	}

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", xaiconstants.ClientID)
	params.Set("redirect_uri", xaiconstants.RedirectURI)
	params.Set("scope", xaiconstants.Scopes)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	params.Set("state", state)

	authURL := fmt.Sprintf("%s?%s", oidcEndpoints.AuthorizationEndpoint, params.Encode())

	c.JSON(http.StatusOK, StartXaiOAuthResponse{SessionID: state, AuthURL: authURL})
}

type ExchangeXaiOAuthRequest struct {
	SessionID   string                  `json:"session_id" binding:"required"`
	CallbackURL string                  `json:"callback_url" binding:"required"`
	Proxy       *httpclient.ProxyConfig `json:"proxy,omitempty"`
}

type ExchangeXaiOAuthResponse struct {
	Credentials string `json:"credentials"`
}

func parseXaiCallbackURL(callbackURL string) (string, string, error) {
	trimmed := strings.TrimSpace(callbackURL)
	if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
		return "", "", fmt.Errorf("callback_url must be a full URL")
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return "", "", fmt.Errorf("invalid callback_url: %w", err)
	}

	q := u.Query()

	code := q.Get("code")
	if code == "" {
		return "", "", fmt.Errorf("code parameter not found in callback_url")
	}

	state := q.Get("state")
	if state == "" {
		return "", "", fmt.Errorf("state parameter not found in callback_url")
	}

	return code, state, nil
}

// Exchange 使用 callback URL 换取 OAuth credentials JSON。
// POST /admin/xai/oauth/exchange
func (h *XaiHandlers) Exchange(c *gin.Context) {
	ctx := c.Request.Context()

	var req ExchangeXaiOAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		JSONError(c, http.StatusBadRequest, errors.New("invalid request format"))
		return
	}

	cacheKey := xaiOAuthCacheKey(req.SessionID)

	oauthState, err := h.stateCache.Get(ctx, cacheKey)
	if err != nil {
		JSONError(c, http.StatusBadRequest, errors.New("invalid or expired oauth session"))
		return
	}

	if err := h.stateCache.Delete(ctx, cacheKey); err != nil {
		log.Warn(ctx, "failed to delete used xai oauth state from cache",
			log.String("session_id", req.SessionID), log.Cause(err))
	}

	code, callbackState, err := parseXaiCallbackURL(req.CallbackURL)
	if err != nil {
		JSONError(c, http.StatusBadRequest, err)
		return
	}

	if callbackState != req.SessionID {
		JSONError(c, http.StatusBadRequest, errors.New("oauth state mismatch"))
		return
	}

	// 支持可选代理
	httpClient := h.httpClient
	if req.Proxy != nil && req.Proxy.Type == httpclient.ProxyTypeURL && req.Proxy.URL != "" {
		httpClient = h.httpClient.WithProxy(req.Proxy)
	}

	// 使用 StartOAuth 时缓存的动态 token_url；为空则回退到硬编码
	tokenURL := oauthState.TokenURL
	if tokenURL == "" {
		tokenURL = xaiconstants.FallbackTokenURL
	}

	// xAI token endpoint 使用 Form-encoded 策略（与 Codex 一致）
	tokenProvider := oauth.NewTokenProvider(oauth.TokenProviderParams{
		HTTPClient: httpClient,
		OAuthUrls: oauth.OAuthUrls{
			TokenUrl: tokenURL,
		},
		ExchangeStrategy: &oauth.FormEncodedStrategy{},
	})

	creds, err := tokenProvider.Exchange(ctx, oauth.ExchangeParams{
		Code:         code,
		CodeVerifier: oauthState.CodeVerifier,
		ClientID:     xaiconstants.ClientID,
		RedirectURI:  xaiconstants.RedirectURI,
	})
	if err != nil {
		JSONError(c, http.StatusBadGateway, fmt.Errorf("token exchange failed: %w", err))
		return
	}

	output, err := creds.ToJSON()
	if err != nil {
		JSONError(c, http.StatusInternalServerError, fmt.Errorf("failed to encode credentials: %w", err))
		return
	}

	c.JSON(http.StatusOK, ExchangeXaiOAuthResponse{Credentials: output})
}
