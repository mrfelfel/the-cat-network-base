package catnet

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"testing"
)

func photoLike(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	seed := uint32(12345)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			seed = seed*1664525 + 1013904223
			img.Set(x, y, color.RGBA{
				uint8(x*255/w + int(seed>>24)&0x0f),
				uint8(y*255/h + int(seed>>16)&0x0f),
				uint8((x+y)*127/(w+h) + int(seed>>8)&0x0f),
				255,
			})
		}
	}
	return img
}

// The document must survive a real carrier: embed, PNG-encode, decode, extract,
// and still verify against the signing key.
func TestStegoCarriesDocument(t *testing.T) {
	raw, err := os.ReadFile("servers-v2.json")
	if err != nil {
		t.Skip("no document in the package dir")
	}
	stego, err := EmbedPayload(photoLike(400, 300), raw)
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, stego); err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(&buf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ExtractPayload(decoded)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	env, err := ParseEnvelope(got, Descriptor(), Keys)
	if err != nil {
		t.Fatalf("extracted bytes do not verify: %v", err)
	}
	if len(env.Payload.Servers) == 0 {
		t.Fatal("no servers in the extracted document")
	}
}

// A picture with nothing embedded must be reported as such, not decoded to
// noise and handed on to the signature check.
func TestStegoRejectsCleanImage(t *testing.T) {
	if _, err := ExtractPayload(photoLike(80, 80)); err != ErrNoPayload {
		t.Fatalf("want ErrNoPayload, got %v", err)
	}
}

// Damage must be detected. This is the case that matters: a carrier re-encoded
// as JPEG loses its LSB plane, and silently returning wrong bytes would be far
// worse than failing.
func TestStegoDetectsDamage(t *testing.T) {
	stego, err := EmbedPayload(photoLike(300, 300), bytes.Repeat([]byte("payload"), 200))
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	for i := 0; i < 40; i++ {
		r, g, b, a := stego.At(i*7, i*3).RGBA()
		stego.Set(i*7, i*3, color.RGBA{uint8(r>>8) ^ 1, uint8(g>>8), uint8(b>>8), uint8(a>>8)})
	}
	if _, err := ExtractPayload(stego); err == nil {
		t.Fatal("a damaged carrier returned data instead of failing")
	}
}

// A payload larger than the carrier must be refused, not truncated.
func TestStegoCapacityChecked(t *testing.T) {
	small := photoLike(10, 10) // 37 bytes of capacity
	if _, err := EmbedPayload(small, bytes.Repeat([]byte("x"), 500)); err == nil {
		t.Fatal("oversized payload was accepted")
	}
}

// Alpha must be untouched: some encoders rewrite it, and a payload written
// there would vanish without any error.
func TestStegoLeavesAlphaAlone(t *testing.T) {
	src := photoLike(60, 60)
	for y := 0; y < 60; y++ {
		for x := 0; x < 60; x++ {
			src.Set(x, y, color.RGBA{100, 100, 100, uint8(x + y)})
		}
	}
	out, err := EmbedPayload(src, bytes.Repeat([]byte("z"), 100))
	if err != nil {
		t.Fatal(err)
	}
	for y := 0; y < 60; y++ {
		for x := 0; x < 60; x++ {
			_, _, _, want := src.At(x, y).RGBA()
			_, _, _, got := out.At(x, y).RGBA()
			if want != got {
				t.Fatalf("alpha changed at %d,%d", x, y)
			}
		}
	}
}
