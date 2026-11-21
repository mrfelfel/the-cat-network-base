package catnet

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// The carrier text format: base64 of zlib-compressed bytes.
func TestDecodeCarrierText(t *testing.T) {
	doc := []byte(`{"version":1,"servers":[{"host":"1.2.3.4","port":30001}]}`)
	carried, err := encodeForTest(doc)
	if err != nil { t.Fatal(err) }
	got, err := decodeCarrierText(carried)
	if err != nil { t.Fatalf("decode: %v", err) }
	if !bytes.Equal(got, doc) {
		t.Fatalf("round trip lost data: %q", got)
	}
}

func TestDecodeCarrierTextRejectsJunk(t *testing.T) {
	for _, s := range []string{"", "not base64!!", "aGVsbG8="} {
		if _, err := decodeCarrierText(s); err == nil {
			t.Fatalf("junk %q was accepted", s)
		}
	}
}

// A QR placed in a corner must still be found, and must survive the JPEG
// re-encode a CDN applies.
func TestQRFoundInCornerThroughJPEG(t *testing.T) {
	txt := strings.Repeat("carrier-payload-", 20)
	img := renderCarrierForTest(txt)
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}); err != nil { t.Fatal(err) }
	re, err := jpeg.Decode(bytes.NewReader(buf.Bytes()))
	if err != nil { t.Fatal(err) }
	got, err := decodeQRPayload(re)
	if err != nil { t.Fatalf("corner QR lost: %v", err) }
	if got != txt {
		t.Fatalf("wrong text back")
	}
}

// A photo with no code is a clean miss, not a crash.
func TestQRMissingIsCleanMiss(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 200, 200))
	for y := 0; y < 200; y++ { for x := 0; x < 200; x++ { img.Set(x, y, color.RGBA{uint8(x), uint8(y), 90, 255}) } }
	if _, err := decodeQRPayload(img); err == nil {
		t.Fatal("a photo without a code must report a miss")
	}
}

// The live channel currently has no carrier, so this asserts the reader does
// not invent one. It is skipped when the network is unavailable.
func TestEitaaChannelReadsWithoutInventing(t *testing.T) {
	src := EitaaChannelSource{Channel: "roseilandmenu", Timeout: 15 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	id, err := src.newestPostID(ctx, newTestClient())
	if err != nil {
		t.Skipf("channel unreachable: %v", err)
	}
	if id <= 0 {
		t.Fatalf("implausible newest post id %d", id)
	}
	t.Logf("newest post id %d", id)
	raw, err := src.fetchCarrier(ctx, newTestClient(), id)
	if err == nil {
		if _, e := ParseEnvelope(raw, Descriptor(), Keys); e != nil {
			t.Fatalf("found bytes that do not verify: %v", e)
		}
		t.Log("carrier present and verified")
	} else {
		t.Logf("no carrier in the newest post: %v", err)
	}
}

// --- helpers ---

func encodeForTest(doc []byte) (string, error) {
	compressed, err := zlibCompressForTest(doc)
	if err != nil { return "", err }
	return base64.StdEncoding.EncodeToString(compressed), nil
}

func renderCarrierForTest(text string) image.Image {
	// Reuse the same encoder the panel uses, via a tiny QR built in-test is not
	// possible, so a synthetic pattern is substituted only where a real code is
	// available through the library.
	enc := qrcode.NewQRCodeWriter()
	bitmap, err := enc.Encode(text, gozxing.BarcodeFormat_QR_CODE, 0, 0, nil)
	if err != nil { return image.NewRGBA(image.Rect(0, 0, 10, 10)) }
	b := bitmap.GetWidth()
	W, H := 400, 300
	out := image.NewRGBA(image.Rect(0, 0, W, H))
	for y := 0; y < H; y++ { for x := 0; x < W; x++ { out.Set(x, y, color.RGBA{140, 110, 160, 255}) } }
	// Cells must be several pixels wide for a decoder to resolve them; a
	// 133-module code squeezed into 120px is unreadable no matter how clean
	// the source is.
	target := 150
	if b*4 > target { target = b * 4 }
	cell := float64(target) / float64(b)
	ox, oy := W-target-8, H-target-8
	for i := -4; i < b+4; i++ {
		for j := -4; j < b+4; j++ {
			val := uint8(255)
			if i >= 0 && i < b && j >= 0 && j < b && bitmap.Get(j, i) { val = 0 }
			px, py := ox+int(float64(i+4)*cell), oy+int(float64(j+4)*cell)
			for dy := 0; dy < int(cell)+1; dy++ {
				for dx := 0; dx < int(cell)+1; dx++ {
					if px+dx >= 0 && px+dx < W && py+dy >= 0 && py+dy < H {
						out.Set(px+dx, py+dy, color.RGBA{val, val, val, 255})
					}
				}
			}
		}
	}
	return out
}

var _ = fmt.Sprintf
var _ = os.TempDir
var _ = png.Encode
