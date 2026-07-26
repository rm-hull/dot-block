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
			if t == reflect.TypeOf(LogLevel("")) {
				return &jsonschema.Type{
					Type: "string",
					Enum: []any{"DEBUG", "INFO", "WARN", "ERROR"},
				}
			}
			if t == reflect.TypeOf(time.Duration(0)) {
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

	collectDescriptions(reflect.TypeOf(Config{}), pkgPath, commentMap)
	collectDescriptions(reflect.TypeOf(ServerConfig{}), pkgPath, commentMap)
	collectDescriptions(reflect.TypeOf(ProxyProtocolConfig{}), pkgPath, commentMap)
	collectDescriptions(reflect.TypeOf(LetsEncryptConfig{}), pkgPath, commentMap)
	collectDescriptions(reflect.TypeOf(DNSConfig{}), pkgPath, commentMap)
	collectDescriptions(reflect.TypeOf(ECSConfig{}), pkgPath, commentMap)
	collectDescriptions(reflect.TypeOf(CacheConfig{}), pkgPath, commentMap)
	collectDescriptions(reflect.TypeOf(NoiseFilter{}), pkgPath, commentMap)
	collectDescriptions(reflect.TypeOf(TimeoutsConfig{}), pkgPath, commentMap)
	collectDescriptions(reflect.TypeOf(BlocklistConfig{}), pkgPath, commentMap)
	collectDescriptions(reflect.TypeOf(BlocklistSource{}), pkgPath, commentMap)
	collectDescriptions(reflect.TypeOf(GeoblockConfig{}), pkgPath, commentMap)
	collectDescriptions(reflect.TypeOf(IpinfoConfig{}), pkgPath, commentMap)
	collectDescriptions(reflect.TypeOf(TelemetryConfig{}), pkgPath, commentMap)

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
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		descr := field.Tag.Get("descr")
		if descr != "" {
			key := pkgPath + "." + t.Name() + "." + field.Name
			commentMap[key] = descr
		}
	}
}
