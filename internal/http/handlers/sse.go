package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rm-hull/dot-block/internal/http/sse"
)

type SSEQueryParams struct {
	Blocked *bool    `form:"blocked"`
	Domain  []string `form:"domain"`
}

func (q *SSEQueryParams) Matches(event sse.Event) bool {
	if q.Blocked != nil && event.Blocked != *q.Blocked {
		return false
	}

	if len(q.Domain) > 0 {
		norm := func(s string) string {
			s = strings.TrimSuffix(s, ".")
			return strings.ToLower(s)
		}
		ed := norm(event.Domain)
		matched := false
		for _, d := range q.Domain {
			qd := norm(d)
			if ed == qd || strings.HasSuffix(ed, "."+qd) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

func SSEHandler(broadcaster *sse.Broadcaster) gin.HandlerFunc {
	return func(c *gin.Context) {
		if broadcaster == nil {
			c.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}

		var query SSEQueryParams
		if err := c.ShouldBindQuery(&query); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid query parameters", "details": err.Error()})
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
				if query.Matches(event) {
					c.SSEvent("message", event)
					c.Writer.Flush()
				}
			case <-ticker.C:
				c.SSEvent("ping", nil)
				c.Writer.Flush()
			case <-c.Request.Context().Done():
				return
			}
		}
	}
}
