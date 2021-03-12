package iam

import (
	"context"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type Client struct {
	AuthorizationServer string
	ClientId            string
	ClientSecret        string
	RedirectUrl         string
	RedirectLogoutUrl   string
	Scopes              []string
	State               string
	AutoRefresh         bool
	TokenStore          TokenStore
	AuthCodeOption      []oauth2.AuthCodeOption
	context             context.Context
	Provider            *oidc.Provider
	OAuth2Config        *oauth2.Config
	OidcConfig          *oidc.Config
	Verifier            *oidc.IDTokenVerifier
	// 开启后，不论令牌是否过期都会进行自动刷新，此时 AutoRefresh 无效
	Dev bool
}

type ProviderClaim struct {
	Issuer                     string `json:"issuer"`
	AuthorizationEndpoint      string `json:"authorization_endpoint"`
	TokenEndpoint              string `json:"token_endpoint"`
	TokenIntrospectionEndpoint string `json:"token_introspection_endpoint"`
	UserinfoEndpoint           string `json:"userinfo_endpoint"`
	EndSessionEndpoint         string `json:"end_session_endpoint"`
	CheckSessionIframe         string `json:"check_session_iframe"`
	IntrospectionEndpoint      string `json:"introspection_endpoint"`
}

// 从令牌中解析出来的用户信息
type UserAuthorization struct {
	Sub               string `json:"sub"`                // 33333333-3333-3333-3333-333333333333
	EmailVerified     bool   `json:"email_verified"`     // false
	Name              string `json:"name"`               // zhongyue.li 李中月
	PreferredUsername string `json:"preferred_username"` // zhongyue.li
	GivenName         string `json:"given_name"`         // zhongyue.li
	FamilyName        string `json:"family_name"`        // 李中月
	Email             string `json:"email"`              // zhongyue.li@baishan.com
	// 传递给前端的
	AccessToken string `json:"access_token"`
}
