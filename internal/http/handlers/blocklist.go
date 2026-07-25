package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	iso8601 "github.com/channelmeter/iso8601duration"
	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/rm-hull/dot-block/internal/blocklist"
)

type BlocklistHandler struct {
	updater *blocklist.Updater
	logger  *slog.Logger
}

func NewBlocklistHandler(updater *blocklist.Updater, logger *slog.Logger) *BlocklistHandler {
	return &BlocklistHandler{updater: updater, logger: logger}
}

func (h *BlocklistHandler) Reload(c *gin.Context) {
	go h.updater.Run()
	m := make(map[string]string, len(h.updater.Blocklists))
	for _, blockList := range h.updater.Blocklists {
		m[blockList.Name()] = blockList.URL()
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message":    "Blocklist reload triggered",
		"blocklists": m,
	})
}

func (h *BlocklistHandler) Disable(c *gin.Context) {
	var payload struct {
		Name     string `json:"name,omitempty"`
		Duration string `json:"duration"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})
		return
	}

	d, err := parseDuration(payload.Duration)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid duration format"})
		return
	}

	if d <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Duration must be greater than zero"})
		return
	}

	for _, bl := range h.updater.Blocklists {
		if payload.Name == bl.Name() || payload.Name == "" {
			bl.Disable(d)
		}
	}

	h.Status(c)
}

func (h *BlocklistHandler) Reenable(c *gin.Context) {
	for _, bl := range h.updater.Blocklists {
		bl.Reenable()
	}

	h.Status(c)
}

func (h *BlocklistHandler) Status(c *gin.Context) {
	blocklists := make(map[string]*blocklist.BlocklistStatus)
	for _, bl := range h.updater.Blocklists {
		blocklists[bl.Name()] = bl.Status()
	}
	c.JSON(http.StatusOK, blocklists)
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
		isBlocked, _, err := h.isBlocked(domain)
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

func (h *BlocklistHandler) isBlocked(fqdn string) (bool, *blocklist.BlockList, error) {
	for _, blockList := range h.updater.Blocklists {
		if isBlocked, err := blockList.IsBlocked(fqdn); isBlocked || err != nil {
			return isBlocked, blockList, err
		}
	}
	return false, nil, nil
}

// parseDuration parses a duration string that may be in Go duration format
// (e.g. "1h30m", "5m") or ISO 8601 duration format (e.g. "PT1H30M", "P1D").
// It first attempts Go duration parsing, then falls back to ISO 8601.
func parseDuration(s string) (time.Duration, error) {
	// Try Go duration format first (e.g. "1h30m", "5m", "90s")
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}

	// Try ISO 8601 duration format (e.g. "PT1H30M", "P1D", "PT90S")
	if d, err := iso8601.FromString(s); err == nil {
		return d.ToDuration(), nil
	}

	return 0, fmt.Errorf("invalid duration format: %s", s)
}
