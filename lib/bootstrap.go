package catnet

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
)

// bootstrapPayload is the narrow document carried by layer 4 (DNS TXT). It
// answers exactly one question — "which address do I connect to first?" — so it
// fits in a single TXT record.
//
// It deliberately omits the registry. The registry exists to make *future*
// lookups work: mirrors, resolvers, the relay URL. Those are useful only after
// a connection has been made, and they are what make the full document too
// large for one DNS string. So the bootstrap carries addresses, the client
// connects, and the full document is fetched from any of the other layers
// afterwards — see ResolveWithBootstrap.
//
// The wire form is deliberately minimal — hosts and ports only, packed as
// "h1:p1,h2:p2" — because every byte costs ~1.34 base64 characters and the
// record must stay under the 255-byte DNS string limit. Tags and weights are
// registry-ish detail; they arrive with the full document.
type bootstrapPayload struct {
	// Addrs is "host:port" pairs separated by commas.
	Addrs string `json:"a"`
}

// BootstrapMagic distinguishes the compact record from the full document
// without trying to parse it as either.
const bootstrapMagic = "CNB2"

// SealBootstrap produces the base64 string that goes into the TXT record.
//
// Wire format, opaque to anyone without the descriptor:
//
//	magic "CNB2" | kid(2) | nonce(12) | ciphertext | sig(64)
//
// The signature is Ed25519 over `magic|kid|nonce|ciphertext`, so a poisoned
// DNS can return nothing but cannot substitute an address — which is the whole
// point of signing the bootstrap at all.
func SealBootstrap(servers []Server, nonce, descriptor []byte, kid uint16, priv ed25519.PrivateKey) (string, error) {
	if len(nonce) != nonceSize {
		return "", fmt.Errorf("catnet: nonce must be %d bytes", nonceSize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("catnet: invalid private key length %d", len(priv))
	}
	if len(servers) == 0 {
		return "", fmt.Errorf("catnet: bootstrap needs at least one server")
	}
	for _, s := range servers {
		if err := s.validate(); err != nil {
			return "", fmt.Errorf("catnet: %v", err)
		}
	}
	addrs := make([]string, len(servers))
	for i, s := range servers {
		addrs[i] = s.Addr()
	}
	plain, err := json.Marshal(bootstrapPayload{Addrs: strings.Join(addrs, ",")})
	if err != nil {
		return "", err
	}
	key, err := deriveKey(descriptor, nonce)
	if err != nil {
		return "", err
	}
	prologue := bootstrapPrologue(kid)
	ct, err := sealGCM(key, nonce, plain, prologue)
	if err != nil {
		return "", err
	}
	blob := make([]byte, 0, len(prologue)+len(nonce)+len(ct)+signSize)
	blob = append(blob, prologue...)
	blob = append(blob, nonce...)
	blob = append(blob, ct...)
	blob = append(blob, ed25519.Sign(priv, blob)...)
	// Base64 without padding: 4 fewer characters, and DNS providers accept it.
	return base64.RawURLEncoding.EncodeToString(blob), nil
}

// ParseBootstrap verifies and decodes a record produced by SealBootstrap.
func ParseBootstrap(record string, descriptor []byte, keys SigningKeys) ([]Server, error) {
	raw, err := decodeTXTDocument(record)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	minLen := len(bootstrapMagic) + 2 + nonceSize + 16 + signSize
	if len(raw) < minLen {
		return nil, fmt.Errorf("%w: bootstrap too short (%d bytes)", ErrFormat, len(raw))
	}
	if string(raw[:len(bootstrapMagic)]) != bootstrapMagic {
		return nil, ErrFormat
	}
	kid := binary.BigEndian.Uint16(raw[len(bootstrapMagic):])
	pub, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: kid=%d", ErrUnknownKey, kid)
	}
	body := raw[:len(raw)-signSize]
	sig := raw[len(raw)-signSize:]
	if !ed25519.Verify(pub, body, sig) {
		return nil, ErrSignature
	}
	prologue := bootstrapPrologue(kid)
	nonce := raw[len(bootstrapMagic)+2 : len(bootstrapMagic)+2+nonceSize]
	ct := raw[len(bootstrapMagic)+2+nonceSize : len(raw)-signSize]
	key, err := deriveKey(descriptor, nonce)
	if err != nil {
		return nil, err
	}
	plain, err := openGCM(key, nonce, ct, prologue)
	if err != nil {
		return nil, err
	}
	var bp bootstrapPayload
	dec := json.NewDecoder(newTrimReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bp); err != nil {
		return nil, fmt.Errorf("%w: bootstrap payload: %v", ErrFormat, err)
	}
	var out []Server
	for _, a := range strings.Split(bp.Addrs, ",") {
		if a = strings.TrimSpace(a); a == "" {
			continue
		}
		host, port, err := splitHostPort(a)
		if err != nil {
			return nil, fmt.Errorf("%w: bootstrap address %q", ErrFormat, a)
		}
		sv := Server{Host: host, Port: port}
		if err := sv.validate(); err != nil {
			return nil, fmt.Errorf("%w: bootstrap address %q: %v", ErrFormat, a, err)
		}
		out = append(out, sv)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: bootstrap has no servers", ErrFormat)
	}
	return out, nil
}

func bootstrapPrologue(kid uint16) []byte {
	p := make([]byte, 4+2)
	copy(p, bootstrapMagic)
	binary.BigEndian.PutUint16(p[4:], kid)
	return p
}
