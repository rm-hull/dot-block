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
