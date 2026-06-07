package routes

import (
	"log/slog"
	"net/http"
	"strings"

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
