package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func RobotsTxtHandler(c *gin.Context) {
	c.String(http.StatusOK, "User-agent: *\nDisallow: /\n")
}
