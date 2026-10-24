// Package catnet resolves the CatGram server address from a set of
// independent, redundantly-mirrored sources.
//
// The published artifact is a small JSON document (servers.json) whose
// payload is AES-256-GCM encrypted and Ed25519 signed. Callers never deal with
// the envelope: Resolve returns plain Server values or an error.
package catnet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// ProtocolVersion is the envelope version this build understands.
const ProtocolVersion = 1

const (
	magic       = "CNB1"
	nonceSize   = 12
	keySize     = 32
	signSize    = ed25519.SignatureSize
	hkdfInfo    = "catnet/v1/aead"
	maxEnvelope = 1 << 20 // 1 MiB; the real payload is well under 8 KiB
)

var (
	// ErrFormat is returned when the document is not a catnet envelope at all
	// (HTML captive portal, truncated file, wrong file).
	ErrFormat = errors.New("catnet: not a catnet envelope")
	// ErrUnknownKey is returned when the envelope names a signing key that
	// this build does not embed.
	ErrUnknownKey = errors.New("catnet: unknown signing key id")
	// ErrSignature means the content was not produced by the signing key.
	ErrSignature = errors.New("catnet: bad signature")
	// ErrDecrypt means the signature was valid for a different key, or the
	// ciphertext/AAD were altered.
	ErrDecrypt = errors.New("catnet: decryption failed")
)

// envelope is the on-disk JSON shape. JSON is used rather than a packed binary
// so the file diffs and mirrors cleanly; the signature covers decoded bytes,
// so JSON formatting never affects verification.
type envelope struct {
	V   int    `json:"v"`
	Kid uint16 `json:"kid"`
	N   []byte `json:"n"` // std base64 via encoding/json
	Ct  []byte `json:"ct"`
	Sig []byte `json:"sig"`
}

// Envelope is the verified result of opening a published document.
type Envelope struct {
	Payload Payload
	// Raw is the original JSON document, for re-caching without re-encoding.
	Raw []byte
}

// ParseEnvelope decodes, authenticates and decrypts a published servers.json.
// descriptor is the fetch secret from descriptor.go; keys is the embedded
// signing-key set.
func ParseEnvelope(raw []byte, descriptor []byte, keys SigningKeys) (*Envelope, error) {
	if len(raw) > maxEnvelope {
		return nil, fmt.Errorf("%w: too large (%d bytes)", ErrFormat, len(raw))
	}
	var env envelope
	dec := json.NewDecoder(newTrimReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if env.V != ProtocolVersion {
		return nil, fmt.Errorf("%w: protocol version %d, want %d", ErrFormat, env.V, ProtocolVersion)
	}
	if len(env.N) != nonceSize {
		return nil, fmt.Errorf("%w: nonce is %d bytes, want %d", ErrFormat, len(env.N), nonceSize)
	}
	if len(env.Sig) != signSize {
		return nil, fmt.Errorf("%w: signature is %d bytes, want %d", ErrFormat, len(env.Sig), signSize)
	}
	if len(env.Ct) < 16 || len(env.Ct) > maxEnvelope {
		return nil, fmt.Errorf("%w: ciphertext is %d bytes", ErrFormat, len(env.Ct))
	}

	pub, ok := keys[env.Kid]
	if !ok {
		return nil, fmt.Errorf("%w: kid=%d", ErrUnknownKey, env.Kid)
	}

	prologue := prologueFor(env.Kid)
	signed := make([]byte, 0, len(prologue)+len(env.N)+len(env.Ct))
	signed = append(signed, prologue...)
	signed = append(signed, env.N...)
	signed = append(signed, env.Ct...)
	if !ed25519.Verify(pub, signed, env.Sig) {
		return nil, ErrSignature
	}

	key, err := deriveKey(descriptor, env.N)
	if err != nil {
		return nil, err
	}
	plain, err := openGCM(key, env.N, env.Ct, prologue)
	if err != nil {
		return nil, err
	}
	payload, err := decodePayload(plain)
	if err != nil {
		return nil, err
	}
	return &Envelope{Payload: payload, Raw: raw}, nil
}

// SealEnvelope is the inverse of ParseEnvelope. It is used by catnetctl; tests
// use it too. kid selects the signing key; the caller must hold its private
// half.
func SealEnvelope(payload Payload, nonce, descriptor []byte, kid uint16, priv ed25519.PrivateKey) ([]byte, error) {
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("catnet: nonce must be %d bytes", nonceSize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("catnet: invalid private key length %d", len(priv))
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if err := payload.validate(); err != nil {
		return nil, err
	}
	key, err := deriveKey(descriptor, nonce)
	if err != nil {
		return nil, err
	}
	prologue := prologueFor(kid)
	ct, err := sealGCM(key, nonce, plain, prologue)
	if err != nil {
		return nil, err
	}
	signed := make([]byte, 0, len(prologue)+len(nonce)+len(ct))
	signed = append(signed, prologue...)
	signed = append(signed, nonce...)
	signed = append(signed, ct...)
	env := envelope{
		V:   ProtocolVersion,
		Kid: kid,
		N:   nonce,
		Ct:  ct,
		Sig: ed25519.Sign(priv, signed),
	}
	return json.MarshalIndent(env, "", "  ")
}

func prologueFor(kid uint16) []byte {
	p := make([]byte, 6)
	copy(p, magic)
	binary.BigEndian.PutUint16(p[4:], kid)
	return p
}

// deriveKey stretches the library's embedded descriptor with the per-blob
// nonce. Using the nonce as HKDF salt means a single leaked descriptor does
// not decrypt other revisions without also having each revision's nonce
// (which is public, so this is defense-in-depth, not a guarantee).
func deriveKey(descriptor, nonce []byte) ([]byte, error) {
	if len(descriptor) != keySize {
		return nil, fmt.Errorf("catnet: descriptor must be %d bytes, has %d", keySize, len(descriptor))
	}
	k, err := hkdf.Key(sha256.New, descriptor, nonce, hkdfInfo, keySize)
	if err != nil {
		return nil, fmt.Errorf("catnet: derive key: %w", err)
	}
	return k, nil
}

func sealGCM(key, nonce, plain, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return g.Seal(nil, nonce, plain, aad), nil
}

func openGCM(key, nonce, ct, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := g.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}
