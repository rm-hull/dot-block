package handlers

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/rm-hull/dot-block/internal/blocklist"
)

type BlocklistHandler struct {
	updater *blocklist.BlocklistUpdater
	logger  *slog.Logger
}

func NewBlocklistHandler(updater *blocklist.BlocklistUpdater, logger *slog.Logger) *BlocklistHandler {
	return &BlocklistHandler{updater: updater, logger: logger}
}

func (h *BlocklistHandler) Reload(c *gin.Context) {
	go h.updater.Run()
	c.JSON(http.StatusAccepted, gin.H{
		"message": "Blocklist reload triggered",
		"urls":    h.updater.URLs,
	})
}

func (h *BlocklistHandler) Disable(c *gin.Context) {
	var payload struct {
		Duration string `json:"duration"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})
		return
	}

	d, err := time.ParseDuration(payload.Duration)
	if err != nil {
		// Try ISO 8601 duration
		if after, ok := strings.CutPrefix(payload.Duration, "PT"); ok {
			d, err = time.ParseDuration(strings.ToLower(after))
		}
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid duration format"})
			return
		}
	}

	if d <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Duration must be greater than zero"})
		return
	}

	disabledUntil := h.updater.Blocklist.Disable(d)
	c.JSON(http.StatusOK, gin.H{
		"message":  "Blocklist temporarily disabled",
		"duration": d.String(),
		"until":    disabledUntil,
	})
}

func (h *BlocklistHandler) Reenable(c *gin.Context) {
	if h.updater.Blocklist.Reenable() {
		c.JSON(http.StatusOK, gin.H{"message": "Blocklist re-enabled"})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Blocklist is not currently disabled"})
	}
}

func (h *BlocklistHandler) Status(c *gin.Context) {
	c.JSON(http.StatusOK, h.updater.Blocklist.Status())
}

func (h *BlocklistHandler) Check(c *gin.Context) {
	var domains []string

	if c.ContentType() == "application/json" {
		if err := c.ShouldBindJSON(&domains); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON array of domains"})
			return
		}
	} else {
		body, err := c.GetRawData()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
			return
		}
		for line := range strings.SplitSeq(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				domains = append(domains, line)
			}
		}
	}

	if len(domains) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Too many domains: maximum 100 allowed"})
		return
	}

	for _, domain := range domains {
		if _, ok := dns.IsDomainName(domain); !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid domain: " + domain})
			return
		}
	}

	allowed := make([]string, 0)
	blocked := make([]string, 0)

	for _, domain := range domains {
		isBlocked, err := h.updater.Blocklist.IsBlocked(domain)
		if err != nil {
			h.logger.Error("blocklist check failed", "error", err, "domain", domain)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
		if isBlocked {
			blocked = append(blocked, domain)
		} else {
			allowed = append(allowed, domain)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"allowed": allowed,
		"blocked": blocked,
	})
}
