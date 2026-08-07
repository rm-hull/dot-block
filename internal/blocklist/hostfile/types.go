// Package hostfile provides a robust parser for hosts-file and blocklist
// formats using the jasengo parser combinator library.
//
// The parser handles standard hosts-file syntax including:
//   - IP address prefixes (0.0.0.0, 127.0.0.1, ::1, ::)
//   - Wildcard prefixes (*. , www.)
//   - Domain-only lines (no IP prefix)
//   - Inline comments (# ...)
//   - Metadata comments (# Key: Value)
//   - Regular comments (# ...)
//   - Empty lines
//   - UTF-8 BOM headers
//   - Carriage return + line feed (CRLF) and Unix line endings
package hostfile

import (
	"net/netip"
)

// LineKind represents the type of syntactic line parsed from the file.
type LineKind int

const (
	KindEmpty LineKind = iota
	KindComment
	KindMetadata
	KindEntry
)

// File represents a completely parsed hostfile AST containing structured lines,
// as well as aggregated views (metadata map and active host entries).
type File struct {
	Lines    []Line            `json:"lines,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Entries  []Entry           `json:"entries,omitempty"`
}

// Line is a discriminated union / wrapper for an individual line in a hostfile.
type Line struct {
	Kind    LineKind `json:"kind"`
	Raw     string   `json:"raw,omitempty"`     // Original raw line content
	Comment *Comment `json:"comment,omitempty"` // Set if Kind == KindComment or Kind == KindMetadata
	Entry   *Entry   `json:"entry,omitempty"`   // Set if Kind == KindEntry
}

// CommentType distinguishes regular comments from structured metadata comments.
type CommentType int

const (
	CommentRegular CommentType = iota
	CommentMetadata
)

// Comment represents a full-line or inline comment.
type Comment struct {
	Type  CommentType `json:"type"`
	Text  string      `json:"text"`            // Trimmed comment text (without leading '#')
	Key   string      `json:"key,omitempty"`   // Key if Type == CommentMetadata (e.g. "title", "author", "expires")
	Value string      `json:"value,omitempty"` // Value if Type == CommentMetadata (e.g. "StevenBlack List", "2026-07-25")
}

// PrefixType represents the leading address or wildcards specified on a host line.
type PrefixType string

const (
	PrefixIP         PrefixType = "ip"          // e.g. 0.0.0.0, 127.0.0.1, ::1
	PrefixWildcard   PrefixType = "wildcard"    // e.g. *.
	PrefixWww        PrefixType = "www"         // e.g. www.
	PrefixDomainOnly PrefixType = "domain_only" // AdBlock / bare domain format (no IP prefix)
)

// Prefix captures the IP address or format prefix before the hostname(s).
type Prefix struct {
	Type PrefixType `json:"type"`
	Raw  string     `json:"raw"`          // Exact string matched (e.g., "0.0.0.0", "*.", "127.0.0.1")
	IP   netip.Addr `json:"ip,omitempty"` // Parsed IP address if Type == PrefixIP
}

// Entry represents a single hosts file entry containing a prefix, hostnames,
// and an optional inline comment.
type Entry struct {
	Prefix    Prefix   `json:"prefix"`
	Hostnames []string `json:"hostnames"`         // List of hostnames on this line
	Comment   *Comment `json:"comment,omitempty"` // Inline comment on the same line (if present)
}
