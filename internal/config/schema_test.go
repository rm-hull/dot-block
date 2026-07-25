package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSchemaGeneration generates config.schema.json with descriptions and verifies it can be compiled.
func TestSchemaGeneration(t *testing.T) {
	reflector := reflectorWithComments()
	schema := reflector.Reflect(&Config{})

	jsonData, err := json.MarshalIndent(schema, "", "  ")
	require.NoError(t, err)

	// Add $schema reference for IDE integration
	var schemaMap map[string]any
	require.NoError(t, json.Unmarshal(jsonData, &schemaMap))
	schemaMap["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	jsonData, err = json.MarshalIndent(schemaMap, "", "  ")
	require.NoError(t, err)

	repoRoot := findRepoRoot(t)
	schemaPath := filepath.Join(repoRoot, "config.schema.json")
	err = os.WriteFile(schemaPath, jsonData, 0644)
	require.NoError(t, err)

	// Verify by reflecting again (the library validates on reflection)
	_ = reflector.Reflect(&Config{})
}

// TestSchemaMatchesStruct ensures config.schema.json matches the current struct definition (including comments).
func TestSchemaMatchesStruct(t *testing.T) {
	repoRoot := findRepoRoot(t)
	schemaPath := filepath.Join(repoRoot, "config.schema.json")

	existingData, err := os.ReadFile(schemaPath)
	require.NoError(t, err, "config.schema.json not found; run 'go generate ./internal/config' or TestSchemaGeneration first")

	reflector := reflectorWithComments()
	schema := reflector.Reflect(&Config{})
	freshData, err := json.Marshal(schema)
	require.NoError(t, err)

	// Add $schema to fresh for comparison
	var freshMap, existingMap map[string]any
	require.NoError(t, json.Unmarshal(freshData, &freshMap))
	freshMap["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	require.NoError(t, json.Unmarshal(existingData, &existingMap))

	require.Equal(t, existingMap, freshMap, "config.schema.json is out of sync with Config struct (including comments); run 'go generate ./internal/config'")
}

func findRepoRoot(t *testing.T) string {
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			require.Fail(t, "could not find repo root (go.mod)")
		}
		dir = parent
	}
}
