package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func RootHandler(c *gin.Context) {
	c.Redirect(http.StatusMovedPermanently, "https://github.com/rm-hull/dot-block/blob/main/README.md")
}

func RobotsTxtHandler(c *gin.Context) {
	c.String(http.StatusOK, "User-agent: *\nDisallow: /\n")
}
