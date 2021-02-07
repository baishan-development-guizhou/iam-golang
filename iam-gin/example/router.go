package example

import (
	"fmt"
	"github.com/baishan-development-guizhou/iam-golang/iam"
	"github.com/gin-gonic/gin"
	iamGin "iam-golang/iam-gin"
)

type TestResponse struct {
	Message string `json:"message"`
}

func GinRouter(client *iam.Client) (*gin.Engine, error) {
	handler, err := iamGin.BuildIamHandler(client)
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}
	router := gin.Default()
	router.Use(iamGin.Authentication(*client, true, "Set-Cookie",
		"/authorizationServer", "/authorization", "/logout", "/checkToken"))
	router.GET("/authorizationServerRedirect", handler.AuthorizationServerRedirect)
	router.GET("/authorizationServer", handler.AuthorizationServer)
	router.POST("/authorization", handler.Authorization)
	router.GET("/logoutRedirect", handler.LogoutRedirect)
	router.GET("/logout", handler.Logout)
	router.GET("/checkToken", handler.CheckToken)
	return router, nil
}
