package blocklist

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	// Any global setup can go here
	os.Exit(m.Run())
}

func setupTempFile(t *testing.T, content string) io.Reader {
	tmpDir, err := os.MkdirTemp("", "blocklist-test")
	assert.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	tmpFile := filepath.Join(tmpDir, "list.txt")
	err = os.WriteFile(tmpFile, []byte(content), 0644)
	assert.NoError(t, err)

	reader, err := os.Open(tmpFile)
	assert.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close() })

	return reader
}

func TestLoader_Metadata(t *testing.T) {
	tmpFile := setupTempFile(t, "# Title: Test Blocklist\n# Author: Tester\n#\nexample.com\nmalicious.net\n")
	metadata, err := stream(tmpFile, func(_ []byte) bool { return false })
	assert.NoError(t, err)
	assert.Equal(t, "Test Blocklist", metadata["title"])
	assert.Equal(t, "Tester", metadata["author"])
}

func TestLoader_Count(t *testing.T) {
	tmpFile := setupTempFile(t, "# Title: Test\nexample.com\n# Comment\nmalicious.net\n")
	count, err := countNewlines(tmpFile)
	assert.NoError(t, err)
	assert.Equal(t, 4, int(count))
}

func TestLoader_Stream(t *testing.T) {
	tmpFile := setupTempFile(t, "# Title: Test Blocklist\n# Author: Tester\n#\nexample.com\nmalicious.net\n")

	var hosts []string
	scannerFunc := func(host []byte) bool {
		hosts = append(hosts, string(host))
		return false
	}

	_, err := stream(tmpFile, scannerFunc)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(hosts))
	assert.Contains(t, hosts, "example.com")
	assert.Contains(t, hosts, "malicious.net")
}

func TestLoader_AdblockMarkers(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			name:     "basic adblock markers",
			content:  "||dns.mullvad.net^\navastdns.com\n",
			expected: []string{"dns.mullvad.net", "avastdns.com"},
		},
		{
			name:     "only prefix marker",
			content:  "||example.com^\n",
			expected: []string{"example.com"},
		},
		{
			name:     "only suffix marker",
			content:  "example.com^\n",
			expected: []string{"example.com"},
		},
		{
			name:     "only prefix marker without suffix",
			content:  "||example.com\n",
			expected: []string{"example.com"},
		},
		{
			name:     "subdomain with markers",
			content:  "||sub.domain.example.com^\n",
			expected: []string{"sub.domain.example.com"},
		},
		{
			name:     "mixed formats",
			content:  "||avastdns.com^\n0.0.0.0 nextdns.io\n||safedns.com^\nmalicious.net\n",
			expected: []string{"avastdns.com", "nextdns.io", "safedns.com", "malicious.net"},
		},
		{
			name:     "marker with trailing options",
			content:  "||example.com^$thirdparty\n",
			expected: []string{"example.com"},
		},
		{
			name:     "marker with whitespace",
			content:  "  ||example.com^  \n",
			expected: []string{"example.com"},
		},
		{
			name:     "comment lines ignored",
			content:  "# wildcard pihole specific domains\n||avastdns.com^\n# help wanted\n||nextdns.io^\n",
			expected: []string{"avastdns.com", "nextdns.io"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := setupTempFile(t, tt.content)
			var hosts []string
			scannerFunc := func(host []byte) bool {
				hosts = append(hosts, string(host))
				return false
			}
			_, err := stream(tmpFile, scannerFunc)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, hosts)
		})
	}
}

func TestHostnameFromURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{name: "hostname with port", input: "https://example.com:8443/path", expected: "example.com"},
		{name: "hostname without port", input: "http://sub.example.com", expected: "sub.example.com"},
		{name: "missing hostname", input: "https:///path", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hostname, err := hostnameFromURL(test.input)
			if test.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, test.expected, hostname)
		})
	}
}
