package controllers

import (
	"net/http"

	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/pkg/util"
	"github.com/cloudreve/Cloudreve/v4/service/user"
	"github.com/gin-gonic/gin"
)

// OIDCStart initiates OIDC login flow.
func OIDCStart(c *gin.Context) {
	service := ParametersFromContext[*user.OIDCStartService](c, user.OIDCStartParameterCtx{})
	authURL, err := service.Start(c)
	if err != nil {
		c.JSON(200, serializer.Err(c, err))
		return
	}

	c.Redirect(http.StatusFound, authURL)
}

// OIDCCallback handles OIDC callback and injects the login user.
func OIDCCallback(c *gin.Context) {
	service := ParametersFromContext[*user.OIDCCallbackService](c, user.OIDCCallbackParameterCtx{})
	loginUser, err := service.Finish(c, c.Param("provider"))
	if err != nil {
		c.JSON(200, serializer.Err(c, err))
		c.Abort()
		return
	}

	util.WithValue(c, inventory.UserCtx{}, loginUser)
	c.Next()
}
