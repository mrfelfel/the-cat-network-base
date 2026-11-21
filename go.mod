module github.com/mrfelfel/the-cat-network-base

go 1.26.0

require github.com/makiuchi-d/gozxing v0.1.1

require (
	golang.org/x/mobile v0.0.0-20260813181013-1960c775504c // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)

// gomobile does not track its own dependency graph: these are the versions
// golang.org/x/mobile@20260813 itself builds against. Unpinned, the toolchain
// resolves x/tools to an older tag that no longer compiles, so CI would fail
// with a message that says nothing about the real cause.
tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
)
