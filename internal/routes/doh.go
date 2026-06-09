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

func NewDoHResponseWriter(clientIP string) (*doHResponseWriter, error) {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return nil, errors.Newf("failed to parse: %s", clientIP)
	}

	return &doHResponseWriter{
		msg:        &dns.Msg{},
		remoteAddr: &net.TCPAddr{IP: ip, Port: 0},
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
		var raw []byte
		var err error

		if c.Request.Method == http.MethodPost {
			if raw, err = c.GetRawData(); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Failed to read request body",
				})
				return
			}
		} else {
			encoded := c.Query("dns")
			if raw, err = base64.RawURLEncoding.DecodeString(encoded); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Failed to decode base64 DNS message: " + err.Error(),
				})
				return
			}
		}

		msg := new(dns.Msg)
		if err := msg.Unpack(raw); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to parse DNS message: " + err.Error(),
			})
			return
		}

		responseWriter, err := NewDoHResponseWriter(c.ClientIP())
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
