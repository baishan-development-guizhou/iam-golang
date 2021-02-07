package iam

import (
	"github.com/baishan-development-guizhou/iam-golang/iam"
	"github.com/coreos/go-oidc"
	"testing"
)

func TestClient_InitCheckParam(t *testing.T) {
	tests := []test{
		{
			name:    "checkParam ClientId Test",
			fields:  fields{},
			wantErr: true,
		},
		{
			name: "checkParam ClientSecret Test",
			fields: fields{
				ClientId: placeholder,
			},
			wantErr: true,
		},
		{
			name: "checkParam AuthorizationServer Test",
			fields: fields{
				ClientId:     placeholder,
				ClientSecret: placeholder,
			},
			wantErr: true,
		},
		{
			name: "checkParam RedirectUrl Test",
			fields: fields{
				ClientId:            placeholder,
				ClientSecret:        placeholder,
				AuthorizationServer: placeholder,
			},
			wantErr: true,
		},
		{
			name: "checkParam RedirectLogoutUrl Test",
			fields: fields{
				ClientId:            placeholder,
				ClientSecret:        placeholder,
				AuthorizationServer: placeholder,
				RedirectUrl:         placeholder,
			},
			wantErr: true,
		},
		{
			name: "checkParam Scopes Test",
			fields: fields{
				ClientId:            placeholder,
				ClientSecret:        placeholder,
				AuthorizationServer: placeholder,
				RedirectUrl:         placeholder,
				RedirectLogoutUrl:   placeholder,
				Scopes:              []string{"profile"},
			},
			wantErr: true,
			callback: func(client *iam.Client) bool {
				return contains(client.Scopes, oidc.ScopeOpenID) && contains(client.Scopes, "profile")
			},
		},
		{
			name: "checkParam State Test",
			fields: fields{
				ClientId:            placeholder,
				ClientSecret:        placeholder,
				AuthorizationServer: placeholder,
				RedirectUrl:         placeholder,
				RedirectLogoutUrl:   placeholder,
				Scopes:              []string{"profile"},
			},
			wantErr: true,
			callback: func(client *iam.Client) bool {
				return len(client.State) == 24
			},
		},
		{
			name: "checkParam AutoRefresh TokenStore Test",
			fields: fields{
				ClientId:            placeholder,
				ClientSecret:        placeholder,
				AuthorizationServer: placeholder,
				RedirectUrl:         placeholder,
				RedirectLogoutUrl:   placeholder,
				Scopes:              []string{"profile"},
				AutoRefresh:         true,
			},
			wantErr: true,
			callback: func(client *iam.Client) bool {
				return client.TokenStore != nil
			},
		},
	}
	testAllInit(tests, t)
}

func TestClient_Init(t *testing.T) {
	tests := []test{
		{
			name: "Init success.",
			fields: fields{
				ClientId:            testClientId,
				ClientSecret:        testClientSecret,
				AuthorizationServer: testAuthorizationServerUrl,
				RedirectUrl:         "http://127.0.0.1:8081",
				RedirectLogoutUrl:   "http://127.0.0.1:8081",
				Scopes:              []string{"profile"},
			},
			wantErr: false,
			callback: func(client *iam.Client) bool {
				return len(client.State) == 24
			},
			skip: skip,
		},
	}
	testAllInit(tests, t)
}

func TestClient_AuthorizationServerUrl(t *testing.T) {
	tests := []test{
		{
			name: "Authorization Server Url.",
			fields: fields{
				ClientId:            testClientId,
				ClientSecret:        testClientSecret,
				AuthorizationServer: testAuthorizationServerUrl,
				RedirectUrl:         "http://127.0.0.1:8081",
				RedirectLogoutUrl:   "http://127.0.0.1:8081",
				Scopes:              []string{"profile"},
			},
			wantErr: false,
			init:    testInit,
			skip:    skip,
		},
	}
	testAllAuthorizationServerUrl(tests, t)
}

func TestClient_ProviderClaim(t *testing.T) {
	tests := []test{
		{
			name: "Provider Claim.",
			fields: fields{
				ClientId:            testClientId,
				ClientSecret:        testClientSecret,
				AuthorizationServer: testAuthorizationServerUrl,
				RedirectUrl:         "http://127.0.0.1:8081",
				RedirectLogoutUrl:   "http://127.0.0.1:8081",
				Scopes:              []string{"profile"},
			},
			wantErr: false,
			init:    testInit,
			skip:    skip,
		},
	}
	testAllProviderClaim(tests, t)
}

func TestClient_LogoutUrl(t *testing.T) {
	tests := []test{
		{
			name: "Logout Server Url.",
			fields: fields{
				ClientId:            testClientId,
				ClientSecret:        testClientSecret,
				AuthorizationServer: testAuthorizationServerUrl,
				RedirectUrl:         "http://127.0.0.1:8081",
				RedirectLogoutUrl:   "http://127.0.0.1:8081",
				Scopes:              []string{"profile"},
			},
			wantErr: false,
			init:    testInit,
			skip:    skip,
		},
	}
	testAllLogoutUrl(tests, t)
}

func TestClient_Authorization(t *testing.T) {
	tests := []test{
		{
			name: "Authorization User.",
			fields: fields{
				ClientId:            testClientId,
				ClientSecret:        testClientSecret,
				AuthorizationServer: testAuthorizationServerUrl,
				RedirectUrl:         "http://127.0.0.1:8081",
				RedirectLogoutUrl:   "http://127.0.0.1:8081",
				Scopes:              []string{"profile"},
				State:               "test",
			},
			authorization: authorization{
				code:  "7288b5f5-f47c-48b1-8b81-443247b0c570.08afe907-428f-4550-8d92-edc0d457eafc.f5b9d5c5-6fb8-447a-8133-7bd2d55742b4",
				state: "test",
			},
			wantErr: false,
			init:    testInit,
			skip:    skip,
		},
	}
	testAllAuthorization(tests, t)
}

func TestClient_UserInfo(t *testing.T) {
	tests := []test{
		{
			name: "Token To User Info",
			fields: fields{
				ClientId:            testClientId,
				ClientSecret:        testClientSecret,
				AuthorizationServer: testAuthorizationServerUrl,
				RedirectUrl:         "http://127.0.0.1:8081",
				RedirectLogoutUrl:   "http://127.0.0.1:8081",
				Scopes:              []string{"profile"},
				State:               "test",
			},
			authorization: authorization{
				accessToken: "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJpWkxpcjZGd01sZzJlSnNWbkZnMUJqbUw4X3JiQmR0VEZBSDAwMTlOeDdJIn0.eyJleHAiOjE2MDg2NDMwMTYsImlhdCI6MTYwODAzODIxNiwiYXV0aF90aW1lIjoxNjA4MDE1ODI2LCJqdGkiOiI2YWUwZGQ5ZS05NmUxLTQ4NmEtYTg3Ny02N2Q1OWZlNmVlMTYiLCJpc3MiOiJodHRwczovL2FjY291bnQuYnM1OGkuYmFpc2hhbmNkbnguY29tL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6WyJpYW0tdGVzdCIsImFjY291bnQiXSwic3ViIjoiMzMzMTQ3NTQtM2Y4YS00N2I1LWIyZDItZjlhZTAyMzk2NmRkIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiaWFtLXRlc3QiLCJzZXNzaW9uX3N0YXRlIjoiMDhhZmU5MDctNDI4Zi00NTUwLThkOTItZWRjMGQ0NTdlYWZjIiwiYWNyIjoiMCIsInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiemhvbmd5dWUubGkg5p2O5Lit5pyIIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiemhvbmd5dWUubGkiLCJnaXZlbl9uYW1lIjoiemhvbmd5dWUubGkiLCJmYW1pbHlfbmFtZSI6IuadjuS4reaciCIsImVtYWlsIjoiemhvbmd5dWUubGlAYmFpc2hhbi5jb20ifQ.PHGKfkN-UZEeuEWKhk9febqDq6VoNjDDdRdpQXGcH41rtU8E_r2DhcM58RIdlYHGA1RV8LmBFLtrc0EQ9MOHDd3PvT70HeqnXZidC6b_RXTIdhcwlb6odZdW_3LKqD0N2kIfhcIw2FQTsGCxe7DFddjRCh-KQ1qywn_go2auB0UdohJvqNu0G-wgXoveDb8H1FyUKYgpopK-mrSs3v-RdouwhLR2AuIjdJrOcZhU4To2iBDSL0qPFpMdZVadWI6ws7pcLo1XtPCJYB0MpW6LBWoDCBfgIFKeDBygFcWYesL5RkBJ20uvEOEnP1UIN1FbVJZzPcemzAVllqt6_VnCBw",
			},
			wantErr: false,
			init:    testInit,
			skip:    skip,
		},
	}
	testAllUserInfo(tests, t)
}
