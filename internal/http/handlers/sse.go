package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rm-hull/dot-block/internal/http/sse"
)

func SSEHandler(broadcaster *sse.Broadcaster) gin.HandlerFunc {
	return func(c *gin.Context) {
		if broadcaster == nil {
			c.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		subscriber := broadcaster.Subscribe()
		defer broadcaster.Unsubscribe(subscriber)

		c.Header("Content-Type", "text/event-stream")
		c.Header("Connection", "keep-alive")
		c.Header("Cache-Control", "no-cache")
		c.Header("X-Accel-Buffering", "no")

		c.SSEvent("ping", nil)
		c.Writer.Flush()

		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case event, ok := <-subscriber:
				if !ok {
					return
				}
				c.SSEvent("message", event)
				c.Writer.Flush()
			case <-ticker.C:
				c.SSEvent("ping", nil)
				c.Writer.Flush()
			case <-c.Request.Context().Done():
				return
			}
		}
	}
}
