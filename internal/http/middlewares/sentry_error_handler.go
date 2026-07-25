package middlewares

import (
	"log/slog"

	"github.com/gin-gonic/gin"
)

func SentryErrorHandler(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			for _, e := range c.Errors {
				logger.ErrorContext(c.Request.Context(), "Gin error", "error", e.Err)
			}
		}
	}
}
