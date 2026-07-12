package middlewares

import (
	"log/slog"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/gin-gonic/gin"
)

func RequireBasicAuth(auth string, logger *slog.Logger) (gin.HandlerFunc, error) {
	if auth == "" {
		logger.Warn("Metrics endpoint is not protected by basic auth")
		return func(c *gin.Context) {
			c.Next()
		}, nil
	}

	parts := strings.SplitN(auth, ":", 2)
	if len(parts) != 2 {
		return nil, errors.Newf("unable to extract user:pass from: %s", auth)
	}
	user := parts[0]
	pass := parts[1]

	logger.Info("Protecting /metrics endpoint with basic auth")
	return gin.BasicAuth(gin.Accounts{user: pass}), nil
}
