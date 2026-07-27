package hostfile

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse_MetadataComments(t *testing.T) {
	input := `# Title: Test Blocklist
# Author: Tester
# Last modified: 2026-07-25
#
0.0.0.0 ads.example.com
`
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Equal(t, "Test Blocklist", file.Metadata["title"])
	assert.Equal(t, "Tester", file.Metadata["author"])
	assert.Equal(t, "2026-07-25", file.Metadata["last_modified"])
	assert.Len(t, file.Entries, 1)
	assert.Equal(t, "ads.example.com", file.Entries[0].Hostnames[0])
}

func TestParse_IPPrefixes(t *testing.T) {
	input := `0.0.0.0 example.com
127.0.0.1 localhost
::1 ipv6host
:: ipv6any
`
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Len(t, file.Entries, 4)

	assert.Equal(t, PrefixIP, file.Entries[0].Prefix.Type)
	assert.Equal(t, "0.0.0.0", file.Entries[0].Prefix.Raw)

	assert.Equal(t, PrefixIP, file.Entries[1].Prefix.Type)
	assert.Equal(t, "127.0.0.1", file.Entries[1].Prefix.Raw)

	assert.Equal(t, PrefixIP, file.Entries[2].Prefix.Type)
	assert.Equal(t, "::1", file.Entries[2].Prefix.Raw)

	assert.Equal(t, PrefixIP, file.Entries[3].Prefix.Type)
	assert.Equal(t, "::", file.Entries[3].Prefix.Raw)
}

func TestParse_WildcardPrefixes(t *testing.T) {
	input := `*.malware.net
www.tracking.com
`
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Len(t, file.Entries, 2)

	assert.Equal(t, PrefixWildcard, file.Entries[0].Prefix.Type)
	assert.Equal(t, "*.", file.Entries[0].Prefix.Raw)

	assert.Equal(t, PrefixWww, file.Entries[1].Prefix.Type)
	assert.Equal(t, "www.", file.Entries[1].Prefix.Raw)
}

func TestParse_DomainOnly(t *testing.T) {
	input := `example.com
malicious.net
`
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Len(t, file.Entries, 2)

	assert.Equal(t, PrefixDomainOnly, file.Entries[0].Prefix.Type)
	assert.Equal(t, "example.com", file.Entries[0].Hostnames[0])

	assert.Equal(t, PrefixDomainOnly, file.Entries[1].Prefix.Type)
	assert.Equal(t, "malicious.net", file.Entries[1].Hostnames[0])
}

func TestParse_MultipleHostnames(t *testing.T) {
	input := `0.0.0.0 ad1.com ad2.com ad3.com
`
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Len(t, file.Entries, 1)
	assert.Len(t, file.Entries[0].Hostnames, 3)
	assert.Equal(t, "ad1.com", file.Entries[0].Hostnames[0])
	assert.Equal(t, "ad2.com", file.Entries[0].Hostnames[1])
	assert.Equal(t, "ad3.com", file.Entries[0].Hostnames[2])
}

func TestParse_InlineComments(t *testing.T) {
	input := `0.0.0.0 ads.example.com # tracker block
127.0.0.1 badsite.org # malicious
`
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Len(t, file.Entries, 2)

	assert.NotNil(t, file.Entries[0].Comment)
	assert.Equal(t, CommentRegular, file.Entries[0].Comment.Type)
	assert.Equal(t, "tracker block", file.Entries[0].Comment.Text)

	assert.NotNil(t, file.Entries[1].Comment)
	assert.Equal(t, CommentRegular, file.Entries[1].Comment.Type)
	assert.Equal(t, "malicious", file.Entries[1].Comment.Text)
}

func TestParse_EmptyLinesAndWhitespace(t *testing.T) {
	input := `

0.0.0.0 example.com

   0.0.0.0 spaced.com   
`
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Len(t, file.Entries, 2)
	assert.Equal(t, "example.com", file.Entries[0].Hostnames[0])
	assert.Equal(t, "spaced.com", file.Entries[1].Hostnames[0])
}

func TestParse_CRLFLineEndings(t *testing.T) {
	input := "0.0.0.0 example.com\r\n127.0.0.1 localhost\r\n"
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Len(t, file.Entries, 2)
	assert.Equal(t, "example.com", file.Entries[0].Hostnames[0])
	assert.Equal(t, "localhost", file.Entries[1].Hostnames[0])
}

func TestParse_BOMHeader(t *testing.T) {
	input := "\ufeff0.0.0.0 example.com\n"
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Len(t, file.Entries, 1)
	assert.Equal(t, "example.com", file.Entries[0].Hostnames[0])
}

func TestParse_RegularComments(t *testing.T) {
	input := `# This is a regular comment
# Another comment
0.0.0.0 example.com
`
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Len(t, file.Entries, 1)
	assert.Len(t, file.Lines, 3)
	assert.Equal(t, KindComment, file.Lines[0].Kind)
	assert.Equal(t, KindComment, file.Lines[1].Kind)
	assert.Equal(t, "This is a regular comment", file.Lines[0].Comment.Text)
}

func TestParse_DoubleOctothorpeComments(t *testing.T) {
	input := `## Double hash comment
0.0.0.0 example.com
`
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Len(t, file.Entries, 1)
	// ## should be parsed as a regular comment with text "# Double hash comment"
	assert.Equal(t, KindComment, file.Lines[0].Kind)
}

func TestParse_EmptyInput(t *testing.T) {
	file, err := Parse("")
	assert.NoError(t, err)
	assert.Empty(t, file.Entries)
	assert.Empty(t, file.Metadata)
}

func TestParse_NoTrailingNewline(t *testing.T) {
	input := `0.0.0.0 example.com`
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Len(t, file.Entries, 1)
	assert.Equal(t, "example.com", file.Entries[0].Hostnames[0])
}

func TestParse_RealBlocklistFormat(t *testing.T) {
	// Simulates the format from data/blocklist.txt
	input := `# Title: dot-block custom blocklist
# Last modified: 19 July 2026 01:15 BST
# Notes: raise an issue/create a PR to add/remove entries from this blocklist
#
07c225f3.online
ad.360yield.com
ad.doubleclick.net
`
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Equal(t, "dot-block custom blocklist", file.Metadata["title"])
	assert.Equal(t, "19 July 2026 01:15 BST", file.Metadata["last_modified"])
	assert.Equal(t, "raise an issue/create a PR to add/remove entries from this blocklist", file.Metadata["notes"])
	assert.Len(t, file.Entries, 3)
	assert.Equal(t, "07c225f3.online", file.Entries[0].Hostnames[0])
	assert.Equal(t, "ad.360yield.com", file.Entries[1].Hostnames[0])
	assert.Equal(t, "ad.doubleclick.net", file.Entries[2].Hostnames[0])
}

func TestParse_HostEntryWithIPAndMultipleDomains(t *testing.T) {
	input := `0.0.0.0 ads.example.com tracker.example.com analytics.example.com
`
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Len(t, file.Entries, 1)
	assert.Equal(t, PrefixIP, file.Entries[0].Prefix.Type)
	assert.Equal(t, "0.0.0.0", file.Entries[0].Prefix.Raw)
	assert.Len(t, file.Entries[0].Hostnames, 3)
}

func TestParse_MixedContent(t *testing.T) {
	input := `# Title: Mixed Test
# Author: Tester
#
0.0.0.0 ads.example.com # inline comment
127.0.0.1 badsite.org
*.malware.net
example.com
`
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Len(t, file.Entries, 4)
	assert.Equal(t, "Mixed Test", file.Metadata["title"])
	assert.Equal(t, "Tester", file.Metadata["author"])

	assert.Equal(t, PrefixIP, file.Entries[0].Prefix.Type)
	assert.Equal(t, "ads.example.com", file.Entries[0].Hostnames[0])
	assert.NotNil(t, file.Entries[0].Comment)

	assert.Equal(t, PrefixIP, file.Entries[1].Prefix.Type)
	assert.Equal(t, "badsite.org", file.Entries[1].Hostnames[0])

	assert.Equal(t, PrefixWildcard, file.Entries[2].Prefix.Type)
	assert.Equal(t, "malware.net", file.Entries[2].Hostnames[0])

	assert.Equal(t, PrefixDomainOnly, file.Entries[3].Prefix.Type)
	assert.Equal(t, "example.com", file.Entries[3].Hostnames[0])
}

func TestParse_CommentWithoutSpace(t *testing.T) {
	input := `#notitle
0.0.0.0 example.com
`
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Len(t, file.Entries, 1)
	assert.Equal(t, KindComment, file.Lines[0].Kind)
}

func TestParse_MetadataWithColonInValue(t *testing.T) {
	input := `# Title: Some: Value: with colons
0.0.0.0 example.com
`
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Equal(t, "Some: Value: with colons", file.Metadata["title"])
}

func TestParse_ExtraWhitespaceAroundHostnames(t *testing.T) {
	input := `   0.0.0.0    spaced.com   
`
	file, err := Parse(input)
	assert.NoError(t, err)
	assert.Len(t, file.Entries, 1)
	assert.Equal(t, "spaced.com", file.Entries[0].Hostnames[0])
}
