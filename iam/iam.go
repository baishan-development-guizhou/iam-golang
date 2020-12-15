package iam

import (
	"context"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"time"
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
	// 只有开启自动刷新的时候才能够使用 dev 模式
	// 开启后，不论令牌是否过期都会进行自动刷新
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

// 初始化配置
func (client *Client) initConfig() error {
	client.context = context.Background()
	provider, err := oidc.NewProvider(client.context, client.AuthorizationServer)
	if err != nil {
		return err
	}
	if provider == nil {
		return fmt.Errorf("IAM 初始化错误")
	}
	client.Provider = provider
	client.OAuth2Config = &oauth2.Config{
		ClientID:     client.ClientId,
		ClientSecret: client.ClientSecret,
		RedirectURL:  client.RedirectUrl,
		Endpoint:     provider.Endpoint(),
		Scopes:       client.Scopes,
	}
	client.OidcConfig = &oidc.Config{
		ClientID: client.ClientId,
	}
	client.Verifier = provider.Verifier(client.OidcConfig)
	return nil
}

func (client *Client) checkParam() error {
	if client.ClientId == "" {
		return errors.New("Client Id 必填项. ")
	}
	if client.ClientSecret == "" {
		return errors.New("Client Secret 必填项. ")
	}
	if client.AuthorizationServer == "" {
		return errors.New("Authorization Server 必填项. ")
	}
	if client.RedirectUrl == "" {
		return errors.New("Redirect Url 必填项. ")
	}
	if client.RedirectLogoutUrl == "" {
		return errors.New("Redirect Logout Url 必填项. ")
	}
	if !contains(client.Scopes, oidc.ScopeOpenID) {
		client.Scopes = append(client.Scopes, oidc.ScopeOpenID)
	}
	if client.State == "" {
		client.State = randomBase64String(24)
	}
	if client.AutoRefresh {
		// 默认值
		if client.TokenStore == nil {
			client.TokenStore = &MemoryTokenStore{}
		}
	}
	if client.AuthCodeOption == nil {
		client.AuthCodeOption = []oauth2.AuthCodeOption{}
	}
	return nil
}

func (client *Client) Init() (err error) {
	if err = client.checkParam(); err != nil {
		return err
	}
	if err = client.initConfig(); err != nil {
		return err
	}
	return nil
}

func (client *Client) ProviderClaim() (claim *ProviderClaim, err error) {
	err = client.Provider.Claims(&claim)
	if err != nil {
		return nil, err
	}
	return claim, nil
}

func (client *Client) AuthorizationServerUrl() string {
	return client.OAuth2Config.AuthCodeURL(client.State, client.AuthCodeOption...)
}

func (client *Client) LogoutUrl() (*string, error) {
	claim, err := client.ProviderClaim()
	if err != nil {
		return nil, err
	}
	claim.EndSessionEndpoint = claim.EndSessionEndpoint + "?redirect_uri=" + client.RedirectLogoutUrl
	return &claim.EndSessionEndpoint, nil
}

// 授权码模式用户登录
// code 授权码
func (client *Client) Authorization(state, code string) (*UserAuthorization, error) {
	if client.State != state {
		return nil, errors.New("State 不匹配. ")
	}
	token, err := client.OAuth2Config.Exchange(client.context, code, client.AuthCodeOption...)
	if err != nil {
		return nil, err
	}
	info, err := client.UserInfo(token.AccessToken)
	if err != nil {
		return nil, errors.New("解析令牌信息失败. ")
	}
	if client.AutoRefresh {
		client.TokenStore.Store(info.Sub, buildTokenInfo(token))
	}
	return info, err
}

// 验证并解析 token 中的用户信息
func (client *Client) UserInfo(token string) (user *UserAuthorization, err error) {
	var (
		idToken  *oidc.IDToken
		newToken *oauth2.Token
	)
	idToken, err = client.Verifier.Verify(client.context, token)
	// 尝试刷新
	idToken, newToken, err = client.checkExpiryAndRefresh(idToken, err)
	if err != nil {
		return nil, err
	}
	if err = idToken.Claims(&user); err != nil {
		return nil, err
	}
	if newToken != nil {
		user.AccessToken = newToken.AccessToken
	} else {
		user.AccessToken = token
	}
	return user, nil
}

// 检查是否是因为过期造成的令牌失效，如果是且刷新令牌在有效期内，就自动刷新
func (client *Client) checkExpiryAndRefresh(token *oidc.IDToken, err error) (*oidc.IDToken, *oauth2.Token, error) {
	// 验证并没有出错，不刷新
	if !client.Dev && err == nil {
		return token, nil, err
	}
	// 并没有开启自动刷新，不处理
	if !client.AutoRefresh {
		return nil, nil, err
	}
	now := time.Now()
	// 无法解析令牌，此时令牌不合法
	if token == nil {
		return nil, nil, err
	}
	// 不是 Dev 模式下再判断
	// 如果失败的原因并不是令牌过期就不处理
	if !client.Dev && token.Expiry.After(now) {
		return token, nil, err
	}
	// 从存储中加载出登录时的令牌
	tokenInfo := client.TokenStore.Load(token.Subject)
	if tokenInfo == nil {
		return token, nil, err
	}
	// 如果刷新令牌也已经过期了就不处理
	if tokenInfo.RefreshExpireAt.Before(now) {
		return token, nil, err
	}
	// 刷新令牌
	newToken, err := client.RefreshToken(tokenInfo.RefreshToken)
	if err != nil {
		return token, nil, err
	}
	// 构建并存储新的令牌信息
	client.TokenStore.Store(token.Subject, buildTokenInfo(newToken))
	// 转化为 id token
	verify, err := client.Verifier.Verify(client.context, newToken.AccessToken)
	return verify, newToken, err
}

// 刷新 token
func (client *Client) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	source := client.OAuth2Config.TokenSource(client.context, &oauth2.Token{RefreshToken: refreshToken})
	token, err := source.Token()
	if err != nil {
		return nil, err
	}
	return token, nil
}
