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
	"net/http"
	"net/http/httptest"
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

// gozxing's finder-pattern detector drops a large, perfectly readable code at
// unpredictable widths: a sweep across 1280..480 decoded only 10 of 21 frames
// with the plain reader, and the failures alternate rather than following any
// size threshold. These four widths are ones the plain reader demonstrably
// misses for this payload, so the test fails if the retry ladder is removed.
func TestLargeCarrierSurvivesDownscaleThroughJPEG(t *testing.T) {
	const W, H = 1280, 853
	payload := strings.Repeat("A", 1588) // the size a real document carries
	img := renderBigCarrierForTest(payload, W, H)

	recovered := 0
	for _, width := range []int{1120, 880, 760, 600} {
		scaled := boxDownscale(img, width)
		var buf bytes.Buffer
		if err := jpeg.Encode(&buf, scaled, &jpeg.Options{Quality: 82}); err != nil {
			t.Fatal(err)
		}
		delivered, err := jpeg.Decode(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		if _, plainErr := readQR(delivered); plainErr != nil {
			recovered++
		}
		got, err := decodeQRPayload(delivered)
		if err != nil {
			t.Fatalf("width %d: carrier unreadable: %v", width, err)
		}
		if got != payload {
			t.Fatalf("width %d: decoded the wrong payload", width)
		}
	}
	if recovered == 0 {
		t.Fatal("the plain reader handled every width — these cases no longer prove the retry ladder is needed")
	}
	t.Logf("the retry ladder was the only reason %d of 4 widths decoded", recovered)
}

func boxDownscale(src image.Image, width int) image.Image {
	sb := src.Bounds()
	h := sb.Dy() * width / sb.Dx()
	out := image.NewRGBA(image.Rect(0, 0, width, h))
	for y := 0; y < h; y++ {
		for x := 0; x < width; x++ {
			x0, x1 := x*sb.Dx()/width, (x+1)*sb.Dx()/width
			y0, y1 := y*sb.Dy()/h, (y+1)*sb.Dy()/h
			if x1 <= x0 { x1 = x0 + 1 }
			if y1 <= y0 { y1 = y0 + 1 }
			var r, g, b, n uint32
			for sy := y0; sy < y1; sy++ {
				for sx := x0; sx < x1; sx++ {
					c := color.RGBAModel.Convert(src.At(sb.Min.X+sx, sb.Min.Y+sy)).(color.RGBA)
					r += uint32(c.R); g += uint32(c.G); b += uint32(c.B); n++
				}
			}
			out.Set(x, y, color.RGBA{uint8(r / n), uint8(g / n), uint8(b / n), 255})
		}
	}
	return out
}

// renderBigCarrierForTest builds the code the way the panel does: a flat white
// card in the lower-right, modules at an integer pixel count.
func renderBigCarrierForTest(text string, W, H int) image.Image {
	enc := qrcode.NewQRCodeWriter()
	bitmap, err := enc.Encode(text, gozxing.BarcodeFormat_QR_CODE, 0, 0, map[gozxing.EncodeHintType]interface{}{
		gozxing.EncodeHintType_ERROR_CORRECTION: "L",
	})
	if err != nil {
		panic(err)
	}
	size := bitmap.GetWidth()
	out := image.NewRGBA(image.Rect(0, 0, W, H))
	// A photograph, not a flat colour: the card has to carry its own contrast.
	for y := 0; y < H; y++ {
		for x := 0; x < W; x++ {
			v := uint8(60 + (x*7+y*3)%120)
			out.Set(x, y, color.RGBA{v, uint8(v / 2), 90, 255})
		}
	}
	const quiet = 4
	cell := (H * 92 / 100) / (size + quiet*2)
	card := cell * (size + quiet*2)
	margin := H * 25 / 1000
	ox, oy := W-card-margin, H-card-margin
	white := color.RGBA{255, 255, 255, 255}
	black := color.RGBA{0, 0, 0, 255}
	for y := oy - cell/2; y < oy+card+cell; y++ {
		for x := ox - cell/2; x < ox+card+cell; x++ {
			if x >= 0 && y >= 0 && x < W && y < H { out.Set(x, y, white) }
		}
	}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if !bitmap.Get(x, y) { continue }
			for dy := 0; dy < cell; dy++ {
				for dx := 0; dx < cell; dx++ {
					px, py := ox+(x+quiet)*cell+dx, oy+(y+quiet)*cell+dy
					if px < W && py < H { out.Set(px, py, black) }
				}
			}
		}
	}
	return out
}

// A post with two images: the first is a plain photo, the second carries the
// code. Reading only the first background-image — which is what this did until
// it broke on the real channel — reports a clean miss and throws away a post
// that was perfectly readable.
func TestPostWithTwoImagesUsesTheSecond(t *testing.T) {
	doc := []byte(`{"version":1,"servers":[{"host":"1.2.3.4","port":30001}]}`)
	carried, err := encodeForTest(doc)
	if err != nil { t.Fatal(err) }

	decoy := plainPhotoForTest()
	carrierImg := renderCarrierForTest(carried)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/s/roseilandmenu/9":
			fmt.Fprintf(w, `<html><body>
				<div style="background-image: url('/photo-decoy')"></div>
				<div style="background-image: url('/photo-carrier')"></div>
				<div style="background-image: url('/photo-carrier')"></div>
			</body></html>`)
		case "/photo-decoy":
			png.Encode(w, decoy)
		case "/photo-carrier":
			png.Encode(w, carrierImg)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	src := EitaaChannelSource{Channel: "roseilandmenu", Timeout: 5 * time.Second}
	client := srv.Client()

	raw, err := src.fetchCarrierAt(context.Background(), client, srv.URL, 9)
	if err != nil {
		t.Fatalf("the second image carried the document and was not read: %v", err)
	}
	if !bytes.Equal(raw, doc) {
		t.Fatalf("wrong document back: %q", raw)
	}
}

// plainPhotoForTest is an image with no code in it, standing in for whatever
// else the operator happened to post alongside the carrier.
func plainPhotoForTest() image.Image {
	img := image.NewRGBA(image.Rect(0, 0, 400, 300))
	for y := 0; y < 300; y++ {
		for x := 0; x < 400; x++ {
			img.Set(x, y, color.RGBA{uint8(40 + x%90), uint8(60 + y%70), 110, 255})
		}
	}
	return img
}
