package hostfile

import (
	"net/netip"
	"strings"

	"github.com/rm-hull/jasengo/parser"
)

// ---------------------------------------------------------------------------
// Primitive parsers
// ---------------------------------------------------------------------------

var lineWhitespace = parser.RegexP(`[ \t]*`)

var lineEnd = parser.Choice(
	parser.ToAny(parser.StringP("\r\n")),
	parser.ToAny(parser.StringP("\n")),
)

var hostname = parser.RegexP(`[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?`)

// ---------------------------------------------------------------------------
// Prefix parsers
// ---------------------------------------------------------------------------

var ipPrefix = parser.Map(
	parser.Choice(
		parser.StringP("0.0.0.0"),
		parser.StringP("127.0.0.1"),
		parser.StringP("::1"),
		parser.StringP("::"),
	),
	func(s string) Prefix {
		return Prefix{
			Type: PrefixIP,
			Raw:  s,
			IP:   netip.MustParseAddr(s),
		}
	},
)

var wildcardPrefix = parser.Map(
	parser.Choice(
		parser.StringP("*."),
		parser.StringP("www."),
	),
	func(s string) Prefix {
		t := PrefixWildcard
		if s == "www." {
			t = PrefixWww
		}
		return Prefix{
			Type: t,
			Raw:  s,
		}
	},
)

var domainOnlyPrefix = parser.Map(
	parser.FollowedBy(hostname),
	func(_ any) Prefix {
		return Prefix{Type: PrefixDomainOnly}
	},
)

var prefixParser = parser.Choice(
	parser.Map(
		parser.Sequence(
			parser.ToAny(ipPrefix),
			parser.ToAny(parser.RegexP(`[ \t]+`)),
		),
		func(parts []any) Prefix {
			return parts[0].(Prefix)
		},
	),
	wildcardPrefix,
	domainOnlyPrefix,
)

// ---------------------------------------------------------------------------
// Comment parsers
// ---------------------------------------------------------------------------

var commentText = parser.RegexP(`[^\r\n]*`)

var metadataComment = parser.Map(
	parser.Sequence(
		parser.ToAny(parser.StringP("#")),
		parser.ToAny(lineWhitespace),
		parser.ToAny(parser.RegexP(`[^:]+`)), // key up to colon
		parser.ToAny(parser.StringP(":")),
		parser.ToAny(lineWhitespace),
		parser.ToAny(commentText), // value
	),
	func(parts []any) Comment {
		key := strings.TrimSpace(parts[2].(string))
		val := strings.TrimSpace(parts[5].(string))
		normKey := strings.ToLower(strings.Join(strings.Fields(key), "_"))
		return Comment{
			Type:  CommentMetadata,
			Text:  key + ": " + val,
			Key:   normKey,
			Value: val,
		}
	},
)

var regularComment = parser.Map(
	parser.Sequence(
		parser.ToAny(parser.StringP("#")),
		parser.ToAny(lineWhitespace),
		parser.ToAny(commentText),
	),
	func(parts []any) Comment {
		return Comment{
			Type: CommentRegular,
			Text: strings.TrimSpace(parts[2].(string)),
		}
	},
)

var commentParser = parser.Choice(
	parser.Attempt(metadataComment),
	regularComment,
)

// ---------------------------------------------------------------------------
// Entry parser
// ---------------------------------------------------------------------------

var hostnamesList = parser.SepBy1(hostname, parser.RegexP(`[ \t]+`))

var inlineCommentParser = parser.Optional(
	parser.Attempt(
		parser.Map(
			parser.Sequence(
				parser.ToAny(lineWhitespace),
				parser.ToAny(parser.StringP("#")),
				parser.ToAny(lineWhitespace),
				parser.ToAny(commentText),
			),
			func(parts []any) Comment {
				return Comment{
					Type: CommentRegular,
					Text: strings.TrimSpace(parts[3].(string)),
				}
			},
		),
	),
)

var entryParser = parser.Map(
	parser.Sequence(
		parser.ToAny(prefixParser),
		parser.ToAny(lineWhitespace),
		parser.ToAny(hostnamesList),
		parser.ToAny(inlineCommentParser),
	),
	func(parts []any) Entry {
		pref := parts[0].(Prefix)
		hosts := parts[2].([]string)
		var comment *Comment
		if c, ok := parts[3].(*Comment); ok && c != nil {
			comment = c
		}
		return Entry{
			Prefix:    pref,
			Hostnames: hosts,
			Comment:   comment,
		}
	},
)

// ---------------------------------------------------------------------------
// Line parsers (with line ending)
// ---------------------------------------------------------------------------

var commentLineParser = parser.Map(
	parser.Sequence(
		parser.ToAny(commentParser),
		lineEnd,
	),
	func(parts []any) Line {
		c := parts[0].(Comment)
		kind := KindComment
		if c.Type == CommentMetadata {
			kind = KindMetadata
		}
		return Line{Kind: kind, Comment: &c}
	},
)

var entryLineParser = parser.Map(
	parser.Sequence(
		parser.ToAny(lineWhitespace),
		parser.ToAny(parser.Attempt(entryParser)),
		parser.ToAny(lineWhitespace),
		lineEnd,
	),
	func(parts []any) Line {
		e := parts[1].(Entry)
		return Line{Kind: KindEntry, Entry: &e}
	},
)

var emptyLineParser = parser.Map(
	parser.Sequence(
		parser.ToAny(lineWhitespace),
		lineEnd,
	),
	func(_ []any) Line {
		return Line{Kind: KindEmpty}
	},
)

var lineParser = parser.Choice(
	commentLineParser,
	parser.Attempt(entryLineParser),
	emptyLineParser,
)

// Optional last line without trailing newline
var lastLineParser = parser.Choice(
	parser.Map(
		parser.Sequence(
			parser.ToAny(commentParser),
			parser.ToAny(lineWhitespace),
		),
		func(parts []any) Line {
			c := parts[0].(Comment)
			kind := KindComment
			if c.Type == CommentMetadata {
				kind = KindMetadata
			}
			return Line{Kind: kind, Comment: &c}
		},
	),
	parser.Map(
		parser.Sequence(
			parser.ToAny(lineWhitespace),
			parser.ToAny(parser.Attempt(entryParser)),
			parser.ToAny(lineWhitespace),
		),
		func(parts []any) Line {
			e := parts[1].(Entry)
			return Line{Kind: KindEntry, Entry: &e}
		},
	),
	parser.Map(
		lineWhitespace,
		func(_ string) Line {
			return Line{Kind: KindEmpty}
		},
	),
)

// ---------------------------------------------------------------------------
// File parser
// ---------------------------------------------------------------------------

var fileParser = parser.Map(
	parser.Bind(
		parser.Many(lineParser),
		func(lines []Line) parser.Parser[[]Line] {
			return parser.Map(
				parser.Optional(lastLineParser),
				func(maybeLine *Line) []Line {
					if maybeLine != nil && maybeLine.Kind != KindEmpty {
						return append(lines, *maybeLine)
					}
					return lines
				},
			)
		},
	),
	func(lines []Line) File {
		f := File{
			Lines:    lines,
			Metadata: make(map[string]string),
		}
		for _, l := range lines {
			if l.Kind == KindMetadata && l.Comment != nil {
				f.Metadata[l.Comment.Key] = l.Comment.Value
			} else if l.Kind == KindEntry && l.Entry != nil {
				f.Entries = append(f.Entries, *l.Entry)
			}
		}
		return f
	},
)

// Parse parses a hosts-file / blocklist string into a structured File AST.
func Parse(input string) (File, error) {
	input = strings.TrimPrefix(input, "\ufeff")
	if strings.TrimSpace(input) == "" {
		return File{Metadata: make(map[string]string)}, nil
	}
	result, _, err := parser.Run(fileParser, input)
	if err != nil {
		return File{}, err
	}
	return result, nil
}
