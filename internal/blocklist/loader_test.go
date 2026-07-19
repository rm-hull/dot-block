package blocklist

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	// Any global setup can go here
	os.Exit(m.Run())
}

func setupTempFile(t *testing.T, content string) string {
	tmpDir, err := os.MkdirTemp("", "blocklist-test")
	assert.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	tmpFile := filepath.Join(tmpDir, "list.txt")
	err = os.WriteFile(tmpFile, []byte(content), 0644)
	assert.NoError(t, err)
	return tmpFile
}

func TestLoader_Metadata(t *testing.T) {
	tmpFile := setupTempFile(t, "# Title: Test Blocklist\n# Author: Tester\n#\nexample.com\nmalicious.net\n")

	metadata, err := extractMetadata(tmpFile)
	assert.NoError(t, err)
	assert.Equal(t, "Test Blocklist", metadata["title"])
	assert.Equal(t, "Tester", metadata["author"])
}

func TestLoader_Count(t *testing.T) {
	tmpFile := setupTempFile(t, "# Title: Test\nexample.com\n# Comment\nmalicious.net\n")

	count, err := countFromFile(tmpFile)
	assert.NoError(t, err)
	assert.Equal(t, 2, int(count))
}

func TestLoader_Stream(t *testing.T) {
	tmpFile := setupTempFile(t, "# Title: Test Blocklist\n# Author: Tester\n#\nexample.com\nmalicious.net\n")

	var hosts []string
	scannerFunc := func(host string) bool {
		hosts = append(hosts, host)
		return false
	}

	err := streamFromFile(tmpFile, nil, scannerFunc)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(hosts))
	assert.Contains(t, hosts, "example.com")
	assert.Contains(t, hosts, "malicious.net")
}
