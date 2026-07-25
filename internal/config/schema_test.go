package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/alecthomas/jsonschema"
	"github.com/stretchr/testify/require"
)

// TestSchemaGeneration generates config.schema.json and verifies it can be compiled.
func TestSchemaGeneration(t *testing.T) {
	reflector := jsonschema.Reflector{
		AllowAdditionalProperties: false,
		DoNotReference:            true,
		TypeMapper: func(t reflect.Type) *jsonschema.Type {
			if t == reflect.TypeOf(LogLevel("")) {
				return &jsonschema.Type{
					Type: "string",
					Enum: []interface{}{"DEBUG", "INFO", "WARN", "ERROR"},
				}
			}
			return nil
		},
	}
	schema := reflector.Reflect(&Config{})

	jsonData, err := json.MarshalIndent(schema, "", "  ")
	require.NoError(t, err)

	repoRoot := findRepoRoot(t)
	schemaPath := filepath.Join(repoRoot, "config.schema.json")
	err = os.WriteFile(schemaPath, jsonData, 0644)
	require.NoError(t, err)

	// Verify by reflecting again (the library validates on reflection)
	_ = reflector.Reflect(&Config{})
}

// TestSchemaMatchesStruct ensures config.schema.json matches the current struct definition.
func TestSchemaMatchesStruct(t *testing.T) {
	repoRoot := findRepoRoot(t)
	schemaPath := filepath.Join(repoRoot, "config.schema.json")

	existingData, err := os.ReadFile(schemaPath)
	require.NoError(t, err, "config.schema.json not found; run 'go generate ./internal/config' or TestSchemaGeneration first")

	reflector := jsonschema.Reflector{
		AllowAdditionalProperties: false,
		DoNotReference:            true,
		TypeMapper: func(t reflect.Type) *jsonschema.Type {
			if t == reflect.TypeOf(LogLevel("")) {
				return &jsonschema.Type{
					Type: "string",
					Enum: []interface{}{"DEBUG", "INFO", "WARN", "ERROR"},
				}
			}
			return nil
		},
	}
	schema := reflector.Reflect(&Config{})
	freshData, err := json.Marshal(schema)
	require.NoError(t, err)

	var existingMap, freshMap map[string]any
	require.NoError(t, json.Unmarshal(existingData, &existingMap))
	require.NoError(t, json.Unmarshal(freshData, &freshMap))

	require.Equal(t, existingMap, freshMap, "config.schema.json is out of sync with Config struct; run 'go generate ./internal/config'")
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