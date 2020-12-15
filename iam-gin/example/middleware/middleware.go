package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/lizhongyue248/iam-golang/iam"
	"iam-golang/iam-gin/example"
	"net/http"
)

func main() {
	client := iam.Client{
		AuthorizationServer: "",
		ClientId:            "",
		ClientSecret:        "",
		RedirectUrl:         "http://127.0.0.1:8081/login",
		RedirectLogoutUrl:   "http://127.0.0.1:8081/logout",
		Scopes: []string{
			"openid",
			"email",
			"phone",
			"profile",
		},
	}
	router, err := example.GinRouter(&client)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	router.GET("/test", func(context *gin.Context) {
		context.JSON(http.StatusOK, example.TestResponse{
			Message: "Success",
		})
	})
	_ = router.Run(":8080")
}
