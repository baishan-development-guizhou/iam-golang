package iam

import (
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/lizhongyue248/iam-golang/iam"
	"golang.org/x/oauth2"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

const placeholder = "超级无敌大帅哥"

// 本地测试时可以改为 false
const skip = true

// 客户端内容可以找相关人员获取
const testClientId = ""
const testClientSecret = ""
const testAuthorizationServerUrl = ""

type fields struct {
	AuthorizationServer string
	ClientId            string
	ClientSecret        string
	RedirectUrl         string
	RedirectLogoutUrl   string
	Scopes              []string
	State               string
	AutoRefresh         bool
	TokenStore          iam.TokenStore
	AuthCodeOption      []oauth2.AuthCodeOption
	Provider            *oidc.Provider
	OAuth2Config        *oauth2.Config
	OidcConfig          *oidc.Config
	Verifier            *oidc.IDTokenVerifier
	Dev                 bool
}

type authorization struct {
	code        string
	state       string
	accessToken string
}

type test struct {
	name          string
	fields        fields
	authorization authorization
	wantErr       bool
	skip          bool
	callback      func(client *iam.Client) bool
	init          func(client *iam.Client) bool
}

func testToClient(tt test) *iam.Client {
	return &iam.Client{
		AuthorizationServer: tt.fields.AuthorizationServer,
		ClientId:            tt.fields.ClientId,
		ClientSecret:        tt.fields.ClientSecret,
		RedirectUrl:         tt.fields.RedirectUrl,
		RedirectLogoutUrl:   tt.fields.RedirectLogoutUrl,
		Scopes:              tt.fields.Scopes,
		State:               tt.fields.State,
		AutoRefresh:         tt.fields.AutoRefresh,
		TokenStore:          tt.fields.TokenStore,
		AuthCodeOption:      tt.fields.AuthCodeOption,
		Provider:            tt.fields.Provider,
		OAuth2Config:        tt.fields.OAuth2Config,
		OidcConfig:          tt.fields.OidcConfig,
		Verifier:            tt.fields.Verifier,
		Dev:                 tt.fields.Dev,
	}
}

func contains(arr []string, target string) bool {
	for _, str := range arr {
		if str == target {
			return true
		}
	}
	return false
}

func testInit(client *iam.Client) bool {
	return client.Init() == nil
}

func testAllInit(tests []test, t *testing.T) {
	testALl(tests, t, func(client *iam.Client, one test) bool {
		return client.Init() != nil == one.wantErr
	})
}

func testAllAuthorizationServerUrl(tests []test, t *testing.T) {
	testALl(tests, t, func(client *iam.Client, one test) bool {
		url := client.AuthorizationServerUrl()
		log.Println(url)
		return (url != "" && strings.Contains(url, "state") &&
			strings.Contains(url, "client_id") &&
			strings.Contains(url, "response_type") &&
			strings.Contains(url, "redirect_uri")) == !one.wantErr
	})
}

func testAllProviderClaim(tests []test, t *testing.T) {
	testALl(tests, t, func(client *iam.Client, one test) bool {
		_, err := client.ProviderClaim()
		if err != nil {
			return true == one.wantErr
		}
		return one.wantErr == false
	})
}

func testAllLogoutUrl(tests []test, t *testing.T) {
	testALl(tests, t, func(client *iam.Client, one test) bool {
		url, err := client.LogoutUrl()
		if err != nil {
			return true == one.wantErr
		}
		return strings.Contains(*url, "redirect_uri")
	})
}

func testAllAuthorization(tests []test, t *testing.T) {
	testALl(tests, t, func(client *iam.Client, one test) bool {
		code := one.authorization.code
		state := one.authorization.state
		if code == "" || state == "" {
			log.Println("请去授权服务器中登陆后使用 code 和 state 进行测试")
			var commands = map[string]string{
				"windows": "start",
				"darwin":  "open",
				"linux":   "xdg-open",
			}
			run, ok := commands[runtime.GOOS]
			if !ok {
				_ = fmt.Errorf("不能够打开 %s 平台浏览器", runtime.GOOS)
				return false
			}
			url := client.AuthorizationServerUrl()
			cmd := exec.Command(run, url)
			err := cmd.Start()
			if err != nil {
				_ = fmt.Errorf("不能够打开 %s 平台浏览器", runtime.GOOS)
			}
			log.Println("如未自动打开浏览器请访问下面的地址进行登录:")
			log.Println(url)
			return false
		}
		authorization, err := client.Authorization(state, code)
		if err != nil {
			return one.wantErr
		}
		log.Println(authorization.AccessToken)
		return !one.wantErr
	})
}

func testAllUserInfo(tests []test, t *testing.T) {
	testALl(tests, t, func(client *iam.Client, one test) bool {
		token := one.authorization.accessToken
		if token == "" {
			return false
		}
		user, err := client.UserInfo(token)
		if err != nil {
			log.Println(err.Error())
			return one.wantErr
		}
		log.Println(user)
		return !one.wantErr
	})
}

func testALl(tests []test, t *testing.T, doing func(client *iam.Client, one test) bool) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip {
				t.Skip()
			}
			client := testToClient(tt)
			if tt.init != nil && !tt.init(client) {
				t.Errorf("Init is fail！")
			}
			if !doing(client, tt) {
				t.Errorf("Doing fail!")
			}
			if tt.callback != nil && !tt.callback(client) {
				t.Errorf("Callback is fail！")
			}
		})
	}
}
