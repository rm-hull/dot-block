package handlers

import (
	"net/http"
	"runtime"
	"time"

	"github.com/earthboundkid/versioninfo/v2"
	"github.com/gin-gonic/gin"
)

// VersionInfoHandler serves application version and runtime information.
type VersionInfoHandler struct {
	startTime time.Time
}

// NewVersionInfoHandler creates a new VersionInfoHandler with the given server start time.
func NewVersionInfoHandler(startTime time.Time) *VersionInfoHandler {
	return &VersionInfoHandler{startTime: startTime}
}

// Info responds with JSON containing the application version, Go runtime version,
// and server uptime in seconds.
func (h *VersionInfoHandler) Info(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"app_version": versioninfo.Short(),
		"go_version":  runtime.Version(),
		"uptime":      time.Since(h.startTime).Seconds(),
	})
}
