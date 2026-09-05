package blocklist

import (
	"context"
	"time"
)

// Blocklist is the interface satisfied by all blocklist implementations.
//
// A blocklist is responsible for answering whether a given fully-qualified
// domain name should be blocked. Implementations are ordered by importance:
// static (downloaded) blocklists are always evaluated first, and any
// heuristic/dynamic blocklist is only consulted as a last resort when no
// static blocklist matches.
//
// Some operations (e.g. Fetch, Load) are only meaningful for static,
// downloadable blocklists; dynamic implementations may make these no-ops.
type Blocklist interface {
	// Name returns the unique identifier of the blocklist. This is used as
	// the "cause" reported in blocked responses, telemetry and the SSE event
	// stream.
	Name() string

	// Title returns a human-readable title for the blocklist, falling back to
	// the source name when not explicitly set.
	Title() string

	// Description returns the description of the blocklist.
	Description() string

	// URL returns the source URL of the blocklist (may be empty for
	// heuristic blocklists that have no downloadable source).
	URL() string

	// IsBlocked reports whether the given fully-qualified domain name should
	// be blocked. It returns (true, nil) when the domain is blocked, (false,
	// nil) when it is allowed, and (false, err) when an error occurred while
	// evaluating the domain.
	IsBlocked(fqdn string) (bool, error)

	// Load populates the blocklist with the given items. It is primarily used
	// for in-memory seeding/testing of static blocklists; heuristic
	// implementations may treat this as a no-op.
	Load(items []string)

	// Fetch downloads (or otherwise refreshes) the blocklist contents.
	// Heuristic implementations that do not fetch from a URL may make this a
	// no-op.
	Fetch(ctx context.Context) error

	// Disable temporarily disables the blocklist for the given duration.
	Disable(duration time.Duration) time.Time

	// Reenable re-enables a previously disabled blocklist. It returns true if
	// the blocklist was disabled and has now been re-enabled.
	Reenable() bool

	// Status returns a snapshot of the blocklist status for reporting.
	Status() *BlocklistStatus
}

type BlocklistStatus struct {
	Name              string            `json:"name"`
	Title             string            `json:"title,omitempty"`
	Description       string            `json:"description,omitempty"`
	URL               string            `json:"url,omitempty"`
	Size              *uint             `json:"size,omitempty"`
	Schedule          string            `json:"schedule,omitempty"`
	MetaData          map[string]string `json:"metadata,omitempty"`
	LastFetched       *time.Time        `json:"last_fetched,omitempty"`
	LastUpdated       *time.Time        `json:"last_updated,omitempty"`
	LastError         string            `json:"error,omitempty"`
	DisabledUntil     *time.Time        `json:"disabled_until,omitempty"`
	FalsePositiveRate float64           `json:"estimated_false_positive_rate,omitempty"`
}

const INDEFINITELY = 100 * 365 * 24 * time.Hour
