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

// buildCommentMap generates a CommentMap from the `descr:"..."` struct tags on Config and its nested types.
// The keys are in the format "packagepath.TypeName.FieldName".
func buildCommentMap() map[string]string {
	commentMap := make(map[string]string)
	pkgPath := "github.com/rm-hull/dot-block/internal/config"

	collectDescriptions(reflect.TypeFor[Config](), pkgPath, commentMap)
	collectDescriptions(reflect.TypeFor[ServerConfig](), pkgPath, commentMap)
	collectDescriptions(reflect.TypeFor[ProxyProtocolConfig](), pkgPath, commentMap)
	collectDescriptions(reflect.TypeFor[LetsEncryptConfig](), pkgPath, commentMap)
	collectDescriptions(reflect.TypeFor[DNSConfig](), pkgPath, commentMap)
	collectDescriptions(reflect.TypeFor[ECSConfig](), pkgPath, commentMap)
	collectDescriptions(reflect.TypeFor[CacheConfig](), pkgPath, commentMap)
	collectDescriptions(reflect.TypeFor[NoiseFilter](), pkgPath, commentMap)
	collectDescriptions(reflect.TypeFor[TimeoutsConfig](), pkgPath, commentMap)
	collectDescriptions(reflect.TypeFor[BlocklistConfig](), pkgPath, commentMap)
	collectDescriptions(reflect.TypeFor[BlocklistSource](), pkgPath, commentMap)
	collectDescriptions(reflect.TypeFor[GeoblockConfig](), pkgPath, commentMap)
	collectDescriptions(reflect.TypeFor[IpinfoConfig](), pkgPath, commentMap)
	collectDescriptions(reflect.TypeFor[TelemetryConfig](), pkgPath, commentMap)
	collectDescriptions(reflect.TypeFor[TopKConfig](), pkgPath, commentMap)

	return commentMap
}

// collectDescriptions walks a struct type and collects `descr:"..."` tags into the commentMap.
func collectDescriptions(t reflect.Type, pkgPath string, commentMap map[string]string) {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for field := range t.Fields() {
		field := field
		descr := field.Tag.Get("descr")
		if descr != "" {
			key := pkgPath + "." + t.Name() + "." + field.Name
			commentMap[key] = descr
		}
	}
}
