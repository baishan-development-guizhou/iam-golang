package iam_gin

import (
	"github.com/gin-gonic/gin"
	"github.com/lizhongyue248/iam-golang/iam"
	"net/http"
)

type IamHandler struct {
	AuthorizationServerRedirect gin.HandlerFunc
	AuthorizationServer         gin.HandlerFunc
	Authorization               gin.HandlerFunc
	LogoutRedirect              gin.HandlerFunc
	Logout                      gin.HandlerFunc
	CheckToken                  gin.HandlerFunc
}

func BuildIamHandler(client *iam.Client) (iamHandler *IamHandler, err error) {
	if err = client.Init(); err != nil {
		return nil, err
	}
	return &IamHandler{
		AuthorizationServer: func(context *gin.Context) {
			context.JSON(http.StatusOK, redirectUrl{
				Url: client.AuthorizationServerUrl(),
			})
		},
		AuthorizationServerRedirect: func(context *gin.Context) {
			context.Redirect(http.StatusFound, client.AuthorizationServerUrl())
		},
		Authorization: authorization(client),
		LogoutRedirect: func(context *gin.Context) {
			if url, err := client.LogoutUrl(); err != nil {
				context.JSON(http.StatusInternalServerError, errorResponse{Message: err.Error()})
			} else {
				context.Redirect(http.StatusFound, *url)
			}
		},
		Logout: func(context *gin.Context) {
			if url, err := client.LogoutUrl(); err != nil {
				context.JSON(http.StatusInternalServerError, errorResponse{Message: err.Error()})
			} else {
				context.JSON(http.StatusOK, redirectUrl{Url: *url})
			}
		},
		CheckToken: func(context *gin.Context) {
			token := context.GetHeader("Authorization")[len("Bearer "):]
			if info, err := client.UserInfo(token); err != nil {
				context.JSON(http.StatusInternalServerError, errorResponse{Message: err.Error()})
			} else {
				context.JSON(http.StatusOK, info)
			}
		},
	}, nil
}

func authorization(client *iam.Client) gin.HandlerFunc {
	return func(context *gin.Context) {
		var auth authorizationCode
		if err := context.Bind(&auth); err != nil {
			context.JSON(http.StatusBadRequest, errorResponse{Message: err.Error()})
			return
		}
		userAuthorization, err := client.Authorization(auth.State, auth.Code)
		if err != nil {
			context.JSON(http.StatusInternalServerError, errorResponse{Message: err.Error()})
			return
		}
		context.JSON(http.StatusOK, userAuthorization)
	}
}
