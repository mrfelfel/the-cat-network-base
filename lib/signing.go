package catnet

import "crypto/ed25519"

// SigningKeys maps an envelope kid to its Ed25519 public key. Publishing a new
// keypair means adding an entry here and shipping a library build; the old
// entry must stay until no published blob uses it.
type SigningKeys map[uint16]ed25519.PublicKey

// KeyID is the kid used by the current publisher.
const KeyID uint16 = 4

// Keys is the embedded trust set. Only public halves.
var Keys = SigningKeys{
	// kid 4 — generated 2026-10-25, private half in ~/.catnet-keys on the
	// operator machine and in the publish CI secret. Never commit it.
	KeyID: ed25519.PublicKey{
		0xc3, 0xd0, 0xfe, 0x62, 0xd2, 0x4f, 0x3d, 0xb8,
		0xf4, 0x77, 0xb7, 0xb1, 0x9a, 0x8f, 0x92, 0xb6,
		0xb1, 0x41, 0x52, 0x06, 0xd1, 0x98, 0xad, 0x33,
		0x5c, 0x08, 0xf5, 0x81, 0xa2, 0xd4, 0xd1, 0xbf,
	},
}
