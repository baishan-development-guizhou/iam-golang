package iam

import (
	"context"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"time"
)

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
		// 我们自己做过期校验
		SkipExpiryCheck: true,
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
		go func() {
			timeTickerChan := time.Tick(time.Hour * 24)
			for {
				client.TokenStore.AutoClear()
				<-timeTickerChan
			}
		}()
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
		client.TokenStore.Store(buildTokenKey(info), buildTokenInfo(token))
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
	idToken, newToken, err = client.checkExpiryAndRefresh(idToken, token, err)
	if err != nil {
		return nil, err
	}
	if err = idToken.Claims(&user); err != nil {
		return nil, err
	}
	if newToken != nil {
		user.AccessToken = newToken.AccessToken
		// 构建并存储新的令牌信息
		client.TokenStore.Store(buildTokenKey(user), buildTokenInfo(newToken))
	} else {
		user.AccessToken = token
	}
	return user, nil
}

// 检查是否是因为过期造成的令牌失效，如果是且刷新令牌在有效期内，就自动刷新
func (client *Client) checkExpiryAndRefresh(idToken *oidc.IDToken, token string, err error) (*oidc.IDToken, *oauth2.Token, error) {
	// 无法解析令牌，此时令牌不合法
	if idToken == nil || err != nil {
		return idToken, nil, err
	}
	now := time.Now()
	// 如果失败的原因并不是令牌过期就不处理
	if idToken.Expiry.After(now) && !client.Dev {
		return idToken, nil, err
	}
	expiryError := fmt.Errorf("oidc: token is expired (Token Expiry: %v)", idToken.Expiry)
	// 非开发模式或者并没有开启自动刷新，不处理
	if !client.AutoRefresh {
		return idToken, nil, expiryError
	}
	// 从存储中加载出登录时的令牌
	tokenInfo := client.TokenStore.Load(idToken.Subject)
	if tokenInfo == nil || token != tokenInfo.AccessToken {
		return idToken, nil, expiryError
	}
	// 如果刷新令牌也已经过期了就不处理
	if tokenInfo.RefreshExpireAt.Before(now) {
		return idToken, nil, expiryError
	}
	// 刷新令牌
	newToken, err := client.RefreshToken(tokenInfo.RefreshToken)
	if err != nil {
		return idToken, nil, err
	}
	// 转化为 id idToken
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
