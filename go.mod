module github.com/mrfelfel/the-cat-network-base

go 1.25.9

require (
	golang.org/x/mobile v0.0.0-20260813181013-1960c775504c // indirect
	golang.org/x/mod v0.39.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
)

// gomobile does not track its own dependency graph: these are the versions
// golang.org/x/mobile@20260813 itself builds against. Unpinned, the toolchain
// resolves x/tools to an older tag that no longer compiles, so CI would fail
// with a message that says nothing about the real cause.
tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
)
