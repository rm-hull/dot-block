// Package middleware wires the shared limiter.Limiter into each of
// dot-block's four listeners. Only the Gin/DoH middleware is a real
// drop-in; the UDP/TCP/DoT snippets below are illustrative of where the
// two calls (Allow / RecordResult) belong in each pipeline.
package middlewares

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"

	"github.com/rm-hull/dot-block/internal/limiter"
)

// RateLimit returns Gin middleware for the DoH (/dns-query) endpoint.
//
// If dot-block sits behind a reverse proxy / load balancer, make sure
// Gin's TrustedProxies is configured correctly first — c.ClientIP()
// otherwise trusts X-Forwarded-For blindly, which would let an attacker
// spoof their way past the per-IP limiter entirely.
func RateLimit(l *limiter.Limiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		if ok, reason := l.Allow(ip); !ok {
			seconds := int(l.RetryAfter(ip).Seconds())
			if seconds < 1 {
				seconds = 1
			}
			c.Header("Retry-After", strconv.Itoa(seconds))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":  "rate limited",
				"reason": reason,
			})
			return
		}

		c.Next()

		// After the handler has run, the response should be available on
		// the context (adapt to however dot-block's DoH handler stashes
		// the parsed dns.Msg / rcode today).
		if msg, ok := c.Get("dns_response"); ok {
			if m, ok := msg.(*dns.Msg); ok {
				l.RecordResult(ip, m.Rcode == dns.RcodeNameError)
			}
		}
	}
}
