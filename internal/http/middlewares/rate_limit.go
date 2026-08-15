// Package middleware wires the shared limiter.Limiter into each of
// dot-block's four listeners. Only the Gin/DoH middleware is a real
// drop-in; the UDP/TCP/DoT snippets below are illustrative of where the
// two calls (Allow / RecordResult) belong in each pipeline.
package middlewares

import (
	"net"
	"net/http"

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
			c.Header("Retry-After", "1")
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

// --- UDP listener (illustrative) -------------------------------------------
//
// func (s *Server) handleUDP(conn *net.UDPConn) {
//     buf := make([]byte, 4096)
//     for {
//         n, addr, err := conn.ReadFromUDP(buf)
//         if err != nil { continue }
//
//         ip := addr.IP.String()
//         if ok, _ := s.limiter.Allow(ip); !ok {
//             // Deliberately drop rather than respond. A REFUSED reply to a
//             // spoofed source IP is itself amplification traffic; silence
//             // is the safer default for UDP specifically. TCP/DoT/DoH can
//             // afford an explicit rejection since the handshake already
//             // proves the source address isn't spoofed.
//             continue
//         }
//
//         msg := new(dns.Msg)
//         if err := msg.Unpack(buf[:n]); err != nil { continue }
//
//         resp := s.dispatcher.Resolve(msg) // existing cache/upstream path
//         s.limiter.RecordResult(ip, resp.Rcode == dns.RcodeNameError)
//
//         out, _ := resp.Pack()
//         _, _ = conn.WriteToUDP(out, addr)
//     }
// }

// --- TCP / DoT listener (illustrative) --------------------------------------
//
// func (s *Server) handleConn(conn net.Conn) {
//     defer conn.Close()
//     ip := limiter.ClientIP(conn.RemoteAddr().String())
//
//     // Gate at accept time too, in addition to per-query, since one TCP
//     // connection can pipeline many queries and shouldn't get a free pass
//     // on the RPS check just by staying connected.
//     if ok, _ := s.limiter.Allow(ip); !ok {
//         return // close immediately, no response
//     }
//
//     for {
//         msg, err := readDNSMessage(conn) // existing length-prefixed read
//         if err != nil { return }
//
//         if ok, reason := s.limiter.Allow(ip); !ok {
//             writeRefused(conn, msg, reason)
//             return
//         }
//
//         resp := s.dispatcher.Resolve(msg)
//         s.limiter.RecordResult(ip, resp.Rcode == dns.RcodeNameError)
//         writeDNSMessage(conn, resp)
//     }
// }

var _ = net.SplitHostPort // silence unused import in this illustrative file
