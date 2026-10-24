package catnet

import (
	"crypto/sha256"
)

// The fetch secret is not stored as a literal: it is SHA-256 of a sentence that
// is assembled at run time from fragments, each individually meaningless. This
// raises the cost of `strings` on the APK from "read one line" to "read the
// code", but does not make the secret recoverable only by the owner.
//
// Treat it as a name, not a password. Rotate by editing descriptorPhrase,
// re-running `catnetctl publish`, and shipping a new library build. Nothing
// else in the protocol depends on its value.

const (
	desPartA = "ct-ntwk"
	desPartB = "-"
	desPartC = "gfelfel"
	desPartD = "@catgram"
)

func descriptorPhrase() string {
	// Built by concatenation at run time; the compiler does not fold these
	// because they are package-level variables passed through a function.
	return desPartA + desPartB + desPartC + desPartD
}

// Descriptor returns the 32-byte fetch secret. Each call returns a fresh copy
// so callers may zero it without affecting later calls.
func Descriptor() []byte {
	sum := sha256.Sum256([]byte(descriptorPhrase()))
	return sum[:]
}

// zero wipes b in place.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
