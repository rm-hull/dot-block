package blocklist

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/rm-hull/dot-block/internal/metrics"
)

// CustomBlocklistName is the identifier for the custom user-managed blocklist.
const CustomBlocklistName = "custom.blocklist"

// CustomBlocklist is a user-managed blocklist backed by an in-memory set of domains.
type CustomBlocklist struct {
	domains       map[string]struct{}
	mutex         *sync.RWMutex
	logger        *slog.Logger
	disabledUntil *time.Time
	lastUpdated   *time.Time
	metrics       *metrics.BlockListMetrics
}

// NewCustomBlocklist constructs a new CustomBlocklist.
func NewCustomBlocklist(logger *slog.Logger) *CustomBlocklist {
	m, _ := metrics.NewBlockListMetrics(CustomBlocklistName)
	return &CustomBlocklist{
		domains: make(map[string]struct{}),
		mutex:   &sync.RWMutex{},
		logger:  logger.With("name", CustomBlocklistName),
		metrics: m,
	}
}

func (b *CustomBlocklist) Name() string {
	return CustomBlocklistName
}

func (b *CustomBlocklist) Title() string {
	return "Custom Blocklist"
}

func (b *CustomBlocklist) Description() string {
	return "In-memory user-managed custom blocked domains set."
}

func (b *CustomBlocklist) URL() string {
	return ""
}

func (b *CustomBlocklist) IsBlocked(fqdn string) (bool, error) {
	domain, _ := strings.CutSuffix(fqdn, ".")
	domain = strings.ToLower(strings.TrimSpace(domain))

	b.mutex.RLock()
	defer b.mutex.RUnlock()

	if b.disabledUntil != nil && time.Now().Before(*b.disabledUntil) {
		return false, nil
	}

	if _, ok := b.domains[domain]; ok {
		return true, nil
	}

	current := domain
	for {
		idx := strings.Index(current, ".")
		if idx == -1 {
			break
		}
		current = current[idx+1:]
		if _, ok := b.domains[current]; ok {
			return true, nil
		}
	}

	return false, nil
}

func (b *CustomBlocklist) Load(items []string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	b.domains = make(map[string]struct{}, len(items))
	for _, item := range items {
		item = strings.ToLower(strings.TrimSpace(item))
		if item != "" {
			b.domains[item] = struct{}{}
		}
	}
	n := uint(len(b.domains))
	b.metrics.Update(n)
	b.logger.Info("Custom blocklist loaded", "size", n)
}

func (b *CustomBlocklist) Add(items []string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	for _, item := range items {
		item = strings.ToLower(strings.TrimSpace(item))
		if item != "" {
			b.domains[item] = struct{}{}
		}
	}
	n := uint(len(b.domains))
	b.metrics.Update(n)
	b.lastUpdated = new(time.Now())
	b.logger.Info("Custom blocklist domains added", "added_count", len(items), "total_size", n)
}

func (b *CustomBlocklist) Remove(items []string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	for _, item := range items {
		item = strings.ToLower(strings.TrimSpace(item))
		delete(b.domains, item)
	}
	n := uint(len(b.domains))
	b.metrics.Update(n)
	b.lastUpdated = new(time.Now())
	b.logger.Info("Custom blocklist domains removed", "removed_count", len(items), "total_size", n)
}

func (b *CustomBlocklist) Domains() []string {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	list := make([]string, 0, len(b.domains))
	for d := range b.domains {
		list = append(list, d)
	}
	return list
}

func (b *CustomBlocklist) Fetch(_ context.Context) error {
	return nil
}

func (b *CustomBlocklist) Disable(duration time.Duration) time.Time {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	until := time.Now().Add(duration)
	b.disabledUntil = &until
	b.logger.Warn("Custom blocklist disabled", "until", until)
	return until
}

func (b *CustomBlocklist) Reenable() bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.disabledUntil == nil || time.Now().After(*b.disabledUntil) {
		return false
	}

	b.disabledUntil = nil
	b.logger.Info("Custom blocklist re-enabled")
	return true
}

func (b *CustomBlocklist) Status() *BlocklistStatus {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	var disabledUntil *time.Time
	if b.disabledUntil != nil && time.Now().Before(*b.disabledUntil) {
		disabledUntil = b.disabledUntil
	}
	size := uint(len(b.domains))

	return &BlocklistStatus{
		Name:          b.Name(),
		Title:         b.Title(),
		Description:   b.Description(),
		URL:           b.URL(),
		Size:          &size,
		DisabledUntil: disabledUntil,
		LastUpdated:   b.lastUpdated,
	}
}
