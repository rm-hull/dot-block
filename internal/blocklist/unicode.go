package blocklist

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/rm-hull/dot-block/internal/config"
)

// UnicodeBlocklistName is the identifier for the unicode/IDN blocker.
const UnicodeBlocklistName = "unicode-idn-blocker"

// UnicodeBlocklist is a heuristic blocklist that rejects any domains
// containing non-ASCII characters or Punycode-encoded IDNs.
type UnicodeBlocklist struct {
	logger        *slog.Logger
	mutex         *sync.RWMutex
	disabledUntil *time.Time
}

// NewUnicodeBlocklist constructs a new UnicodeBlocklist. If enabled is
// false, the blocklist is immediately set to a permanently disabled state
// (disabledUntil is set to a time far in the future) so that it does not
// block any traffic until explicitly re-enabled.
func NewUnicodeBlocklist(cfg *config.UnicodeConfig, logger *slog.Logger) *UnicodeBlocklist {
	blocklist := &UnicodeBlocklist{
		logger: logger.With("name", UnicodeBlocklistName),
		mutex:  &sync.RWMutex{},
	}
	if !cfg.Enabled {
		blocklist.Disable(INDEFINITELY)
	}
	return blocklist
}

// Name returns the blocklist identifier.
func (b *UnicodeBlocklist) Name() string {
	return UnicodeBlocklistName
}

// Title returns a human-readable title.
func (b *UnicodeBlocklist) Title() string {
	return "Unicode/IDN Domain Blocker"
}

// Description returns the description of the blocklist.
func (b *UnicodeBlocklist) Description() string {
	return "Blocks domains containing non-ASCII characters or Punycode (IDN) prefixes."
}

// URL returns the source URL (empty for this heuristic).
func (b *UnicodeBlocklist) URL() string {
	return ""
}

// IsBlocked reports whether the domain should be blocked.
func (b *UnicodeBlocklist) IsBlocked(fqdn string) (bool, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	if b.disabledUntil != nil && time.Now().Before(*b.disabledUntil) {
		return false, nil
	}

	// Check for punycode prefix
	if strings.HasPrefix(strings.ToLower(fqdn), "xn--") {
		return true, nil
	}

	// Check for non-ASCII characters in the domain name.
	// DNS libraries may represent non-ASCII bytes as escaped decimal sequences
	// (e.g. "\230\181\139.com." for "测试.com"), so we need to check both
	// for actual Unicode characters and for escape sequences.
	if strings.Contains(fqdn, "\\") {
		// Check if there are any escape sequences indicating non-ASCII bytes
		// The DNS presentation format uses \DDD where DDD is the decimal
		// value of the byte (100-255 range for non-ASCII)
		for i := 0; i < len(fqdn); i++ {
			if fqdn[i] == '\\' && i+3 < len(fqdn) {
				if num, ok := parseEscapedDecimal(fqdn[i+1:]); ok {
					if num > 127 {
						return true, nil
					}
				}
			}
		}
	}

	for _, r := range fqdn {
		if r > unicode.MaxASCII {
			return true, nil
		}
	}

	return false, nil
}

// parseEscapedDecimal attempts to parse a 3-digit decimal number from the string,
// returning the byte value and true if successful.
func parseEscapedDecimal(s string) (int, bool) {
	if len(s) < 3 {
		return 0, false
	}
	num := 0
	for i := 0; i < 3; i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		num = num*10 + int(s[i]-'0')
	}
	return num, true
}

// Load is a no-op.
func (b *UnicodeBlocklist) Load(_ []string) {}

// Fetch is a no-op.
func (b *UnicodeBlocklist) Fetch(_ context.Context) error {
	return errors.New("unsupported operation")
}

// Disable temporarily disables the blocklist.
func (b *UnicodeBlocklist) Disable(duration time.Duration) time.Time {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	until := time.Now().Add(duration)
	b.disabledUntil = &until
	b.logger.Warn("Blocklist disabled", "name", b.Name(), "until", until)
	return until
}

// Reenable re-enables the blocklist.
func (b *UnicodeBlocklist) Reenable() bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.disabledUntil == nil || time.Now().After(*b.disabledUntil) {
		return false
	}

	b.disabledUntil = nil
	b.logger.Info("Blocklist re-enabled", "name", b.Name())
	return true
}

// Status returns a status snapshot.
func (b *UnicodeBlocklist) Status() *BlocklistStatus {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	var disabledUntil *time.Time
	if b.disabledUntil != nil && time.Now().Before(*b.disabledUntil) {
		disabledUntil = b.disabledUntil
	}

	return &BlocklistStatus{
		Name:          b.Name(),
		Title:         b.Title(),
		Description:   b.Description(),
		URL:           b.URL(),
		DisabledUntil: disabledUntil,
	}
}
