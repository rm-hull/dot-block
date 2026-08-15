package config

import (
	"reflect"
	"time"

	"github.com/alecthomas/jsonschema"
)

// reflectorWithComments returns a Reflector configured with a TypeMapper for LogLevel and time.Duration.
// Field descriptions are now colocated with the structs via the `descr:"..."` tag annotation.
func reflectorWithComments() jsonschema.Reflector {
	return jsonschema.Reflector{
		AllowAdditionalProperties: true,
		DoNotReference:            true,
		CommentMap:                buildCommentMap(),
		TypeMapper: func(t reflect.Type) *jsonschema.Type {
			if t == reflect.TypeFor[LogLevel]() {
				return &jsonschema.Type{
					Type: "string",
					Enum: []any{"DEBUG", "INFO", "WARN", "ERROR"},
				}
			}
			if t == reflect.TypeFor[time.Duration]() {
				return &jsonschema.Type{
					Type:    "string",
					Format:  "duration",
					Pattern: "^([0-9]+(?:\\.[0-9]+)?(?:ns|us|µs|ms|s|m|h))+$",
				}
			}
			return nil // let reflector decide
		},
	}
}

// buildCommentMap generates a CommentMap from the `descr:"..."` struct tags
// on Config and all reachable nested struct types. It walks the type graph
// recursively starting from Config, so new structs added to the config
// hierarchy are automatically included without requiring manual registration.
// The keys are in the format "packagepath.TypeName.FieldName".
func buildCommentMap() map[string]string {
	commentMap := make(map[string]string)
	pkgPath := "github.com/rm-hull/dot-block/internal/config"
	visited := make(map[reflect.Type]struct{})

	walkStructTypes(reflect.TypeFor[Config](), pkgPath, visited, commentMap)
	return commentMap
}

// walkStructTypes recursively discovers all struct types reachable from t
// (via pointer fields, slice elements, and map elements) and collects their
// `descr:"..."` tags into the commentMap. Types outside the config package
// are skipped since only config struct descriptions need to be mapped.
func walkStructTypes(t reflect.Type, pkgPath string, visited map[reflect.Type]struct{}, commentMap map[string]string) {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	// Only recurse into structs defined in the config package.
	if t.Kind() != reflect.Struct || t.PkgPath() != pkgPath {
		return
	}

	// Guard against infinite recursion on cyclic type references.
	if _, seen := visited[t]; seen {
		return
	}
	visited[t] = struct{}{}

	for field := range t.Fields() {
		// Collect the description tag for this field.
		if descr := field.Tag.Get("descr"); descr != "" {
			key := pkgPath + "." + t.Name() + "." + field.Name
			commentMap[key] = descr
		}

		// Recurse into nested struct types (pointer fields, slice/map element types).
		switch field.Type.Kind() {
		case reflect.Pointer:
			walkStructTypes(field.Type.Elem(), pkgPath, visited, commentMap)
		case reflect.Slice:
			walkStructTypes(field.Type.Elem(), pkgPath, visited, commentMap)
		case reflect.Map:
			walkStructTypes(field.Type.Elem(), pkgPath, visited, commentMap)
		}
	}
}
