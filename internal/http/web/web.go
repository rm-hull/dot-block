package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

// DistFS returns the embedded SPA build, rooted correctly (strips the
// leading "dist" segment so paths match what Gin expects, e.g. "index.html").
func DistFS() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err) // build-time invariant; if this fails, the embed is broken
	}
	return sub
}
