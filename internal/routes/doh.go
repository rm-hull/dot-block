package routes

import (
	"encoding/base64"
	"net"
	"net/http"

	"github.com/cockroachdb/errors"
	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
)

type doHResponseWriter struct {
	msg        *dns.Msg
	remoteAddr net.Addr
}

func NewDoHResponseWriter(req *http.Request) (*doHResponseWriter, error) {
	remoteAddr, err := net.ResolveTCPAddr("tcp", req.RemoteAddr)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to resolve: %s", req.RemoteAddr)
	}

	return &doHResponseWriter{
		msg:        &dns.Msg{},
		remoteAddr: &net.TCPAddr{IP: remoteAddr.IP, Port: remoteAddr.Port},
	}, nil
}

func (w *doHResponseWriter) Write(b []byte) (int, error) {
	return len(b), w.msg.Unpack(b)
}

func (w *doHResponseWriter) LocalAddr() net.Addr {
	return nil
}

func (w *doHResponseWriter) RemoteAddr() net.Addr {
	return w.remoteAddr
}

func (w *doHResponseWriter) WriteMsg(m *dns.Msg) error {
	w.msg = m
	return nil
}

func (w *doHResponseWriter) TsigStatus() error {
	return nil
}

func (w *doHResponseWriter) TsigTimersOnly(bool) {

}

func (w *doHResponseWriter) Hijack() {

}

func (w *doHResponseWriter) Close() error {
	return nil
}

func NewDoHHandler(handler dns.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		encoded := c.Query("dns")
		if c.Request.Method == http.MethodPost {
			body, err := c.GetRawData()
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Failed to read request body",
				})
				return
			}
			encoded = string(body)
		}

		raw := make([]byte, base64.RawURLEncoding.DecodedLen(len(encoded)))
		if _, err := base64.RawURLEncoding.Decode(raw, []byte(encoded)); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to decode base64 DNS message: " + err.Error(),
			})
			return
		}

		msg := new(dns.Msg)

		if err := msg.Unpack(raw); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to parse DNS message: " + err.Error(),
			})
			return
		}

		responseWriter, err := NewDoHResponseWriter(c.Request)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to create response writer: " + err.Error(),
			})
			return
		}
		handler.ServeDNS(responseWriter, msg)

		packed, err := responseWriter.msg.Pack()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to pack DNS response: " + err.Error(),
			})
			return
		}

		c.Data(http.StatusOK, "application/dns-message", packed)
	}
}
