package blocklist

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoader_Metadata(t *testing.T) {
	// Create a temporary file with header metadata
	tmpDir, _ := os.MkdirTemp("", "blocklist-test")
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tmpFile := filepath.Join(tmpDir, "metadata.txt")
	content := "# Title: Test Blocklist\n# Author: Tester\n#\nexample.com\nmalicious.net\n"
	_ = os.WriteFile(tmpFile, []byte(content), 0644)

	// Test extractMetadata
	metadata, err := extractMetadata(tmpFile)
	assert.NoError(t, err)
	assert.Equal(t, "Test Blocklist", metadata["title"])
	assert.Equal(t, "Tester", metadata["author"])
}

func TestLoader_Count(t *testing.T) {
	// Create a temporary file
	tmpDir, _ := os.MkdirTemp("", "blocklist-test")
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tmpFile := filepath.Join(tmpDir, "count.txt")
	content := "# Title: Test\nexample.com\n# Comment\nmalicious.net\n"
	_ = os.WriteFile(tmpFile, []byte(content), 0644)

	// Test countFromFile
	count, err := countFromFile(tmpFile)
	assert.NoError(t, err)
	// Current behavior: counts comments when logger is nil
	assert.Equal(t, uint(4), count)
}

func TestLoader_Stream(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "blocklist-test")
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tmpFile := filepath.Join(tmpDir, "list.txt")
	content := "# Title: Test Blocklist\n# Author: Tester\n#\nexample.com\nmalicious.net\n"
	_ = os.WriteFile(tmpFile, []byte(content), 0644)

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
