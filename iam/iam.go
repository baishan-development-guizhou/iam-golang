package iam

import (
	"context"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"time"
)

type TokenInfo struct {
	AccessToken     string
	RefreshToken    string
	AccessExpireAt  time.Time
	RefreshExpireAt time.Time
}

type Iam struct {
	AuthorizationServer string
	ClientId            string
	ClientSecret        string
	RedirectUrl         string
	RedirectLogoutUrl   string
	Scopes              []string
	State               string
	AutoRefresh         bool
	RefreshKey          string
	TokenStore          TokenStore
	AuthCodeOption      []oauth2.AuthCodeOption
	context             context.Context
	Provider            *oidc.Provider
	OAuth2Config        *oauth2.Config
	OidcConfig          *oidc.Config
	Verifier            *oidc.IDTokenVerifier
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
type UserInfo struct {
	Sub               string `json:"sub"`                // 33333333-3333-3333-3333-333333333333
	EmailVerified     bool   `json:"email_verified"`     // false
	Name              string `json:"name"`               // zhongyue.li 李中月
	PreferredUsername string `json:"preferred_username"` // zhongyue.li
	GivenName         string `json:"given_name"`         // zhongyue.li
	FamilyName        string `json:"family_name"`        // 李中月
	Email             string `json:"email"`              // zhongyue.li@baishan.com
}

// 传递给前端的用户信息
type UserAuthorization struct {
	*UserInfo
	AccessToken string `json:"access_token"`
}

func (iam *Iam) initConfig() error {
	iam.context = context.Background()
	provider, err := oidc.NewProvider(iam.context, iam.AuthorizationServer)
	if err != nil {
		return err
	}
	if provider == nil {
		return fmt.Errorf("IAM 初始化错误")
	}
	iam.Provider = provider
	iam.OAuth2Config = &oauth2.Config{
		ClientID:     iam.ClientId,
		ClientSecret: iam.ClientSecret,
		RedirectURL:  iam.RedirectUrl,
		Endpoint:     provider.Endpoint(),
		Scopes:       iam.Scopes,
	}
	iam.OidcConfig = &oidc.Config{
		ClientID: iam.ClientId,
	}
	iam.Verifier = provider.Verifier(iam.OidcConfig)
	return nil
}

func (iam *Iam) checkParam() error {
	if iam.ClientId == "" {
		return errors.New("Client Id 必填项. ")
	}
	if iam.ClientSecret == "" {
		return errors.New("Client Secret 必填项. ")
	}
	if iam.AuthorizationServer == "" {
		return errors.New("Authorization Server 必填项. ")
	}
	if iam.RedirectUrl == "" {
		return errors.New("Redirect Url 必填项. ")
	}
	if iam.RedirectLogoutUrl == "" {
		return errors.New("Redirect Logout Url 必填项. ")
	}
	if !contains(iam.Scopes, oidc.ScopeOpenID) {
		iam.Scopes = append(iam.Scopes, oidc.ScopeOpenID)
	}
	if iam.State == "" {
		iam.State = randomBase64String(24)
	}
	if iam.AutoRefresh {
		// 默认值
		if iam.TokenStore == nil {
			iam.TokenStore = &MemoryTokenStore{}
		}
		if iam.RefreshKey == "" {
			iam.RefreshKey = "Set-Cookie"
		}
	}
	return nil
}

func (iam Iam) ProviderClaim() (claim *ProviderClaim, err error) {
	err = iam.Provider.Claims(&claim)
	if err != nil {
		return nil, err
	}
	return claim, nil
}

func (iam *Iam) AuthorizationServerUrl() string {
	return iam.OAuth2Config.AuthCodeURL(iam.State)
}

func (iam *Iam) LogoutUrl() (*string, error) {
	claim, err := iam.ProviderClaim()
	if err != nil {
		return nil, err
	}
	claim.EndSessionEndpoint = claim.EndSessionEndpoint + "?redirect_uri=" + iam.RedirectLogoutUrl
	return &claim.EndSessionEndpoint, nil
}

// 授权码模式用户登录
// code 授权码
func (iam *Iam) Authorization(state, code string) (*UserAuthorization, error) {
	if iam.State != state {
		return nil, errors.New("State 不匹配. ")
	}
	token, err := iam.OAuth2Config.Exchange(iam.context, code)
	if err != nil {
		return nil, err
	}
	info, err := iam.UserInfo(token.AccessToken)
	if err != nil {
		return nil, errors.New("解析令牌信息失败. ")
	}
	if iam.AutoRefresh {
		iam.TokenStore.Store(info.Sub, buildTokenInfo(token))
	}
	return &UserAuthorization{
		UserInfo:    info,
		AccessToken: token.AccessToken,
	}, err
}

// 验证并简单解析 token
func (iam *Iam) VerifyToken(token string) (idToken *oidc.IDToken, err error) {
	idToken, err = iam.Verifier.Verify(iam.context, token)
	if err != nil {
		if iam.AutoRefresh {
			return iam.checkExpiryAndRefresh(idToken, err)
		}
		return nil, err
	}
	return idToken, nil
}

// 验证并解析 token 中的用户信息
func (iam Iam) UserInfo(token string) (user *UserInfo, err error) {
	idToken, err := iam.VerifyToken(token)
	if err != nil {
		return nil, err
	}
	if err = idToken.Claims(&user); err != nil {
		return nil, err
	}
	return user, err
}

// 检查是否是因为过期造成的令牌失效，如果是且刷新令牌在有效期内，就自动刷新
func (iam Iam) checkExpiryAndRefresh(token *oidc.IDToken, err error) (*oidc.IDToken, error) {
	now := time.Now()
	// 无法解析令牌，此时令牌不合法
	if token == nil {
		return nil, err
	}
	// 如果失败的原因并不是令牌过期就不处理
	if token.Expiry.After(now) {
		return token, err
	}
	// 从存储中加载出登录时的令牌
	tokenInfo := iam.TokenStore.Load(token.Subject)
	if tokenInfo == nil {
		return token, err
	}
	// 如果刷新令牌也已经过期了就不处理
	if tokenInfo.RefreshExpireAt.Before(now) {
		return token, err
	}
	// 刷新令牌
	newToken, err := iam.RefreshToken(tokenInfo.RefreshToken)
	if err != nil {
		return token, err
	}
	// 构建并存储新的令牌信息
	iam.TokenStore.Store(token.Subject, buildTokenInfo(newToken))
	// 再次验证一下
	idToken, err := iam.Verifier.Verify(iam.context, newToken.AccessToken)
	if err != nil {
		return token, err
	}
	return idToken, nil
}

// 刷新 token
func (iam *Iam) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	source := iam.OAuth2Config.TokenSource(iam.context, &oauth2.Token{RefreshToken: refreshToken})
	token, err := source.Token()
	if err != nil {
		return nil, err
	}
	return token, nil
}
