package iam_gin

import (
	"github.com/gin-gonic/gin"
	"github.com/lizhongyue248/iam-golang/iam"
	"net/http"
	"strings"
)

const prefix = "Bearer "

func Authentication(client iam.Client, redirect bool, key string, urls ...string) gin.HandlerFunc {
	return func(context *gin.Context) {
		authorization := context.Request.Header.Get("Authorization")
		path := context.Request.URL.Path
		if noAuth(path, urls...) {
			context.Next()
			return
		}
		if len(authorization) < len(prefix) || !strings.EqualFold(authorization[:len(prefix)], prefix) {
			if redirect {
				context.Redirect(http.StatusFound, client.AuthorizationServerUrl())
				context.Abort()
			} else {
				context.AbortWithStatusJSON(http.StatusOK, redirectUrl{client.AuthorizationServerUrl()})
			}
			return
		}
		token := authorization[len(prefix):]
		info, err := client.UserInfo(token)
		if err != nil {
			context.AbortWithStatusJSON(http.StatusInternalServerError, errorResponse{
				Message: err.Error(),
			})
			return
		}
		if info.AccessToken != token {
			if key == "Set-Cookie" {
				context.Header(key, "token="+info.AccessToken)
			}
			context.Header(key, info.AccessToken)
		}
		context.Set("sub", info.Sub)
		context.Set("username", info.FamilyName)
		context.Set("email", info.Email)
		context.Set("givenName", info.GivenName)
		context.Next()
	}
}

func noAuth(path string, urls ...string) bool {
	for _, url := range urls {
		if strings.HasSuffix(path, url) {
			return true
		}
	}
	return false
}
