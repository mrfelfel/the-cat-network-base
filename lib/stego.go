package catnet

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
)

// Images as a transport for the address document.
//
// A photograph is the one carrier that survives a network which inspects file
// types: JSON from a URL is a shape DPI can match, a picture is what the link
// is for. The document is already signed and encrypted, so hiding it in pixels
// adds no secrecy requirement of its own — it only has to survive re-encoding.
//
// Design choices, each forced by something that breaks in practice:
//
//   - The payload goes in the LEAST SIGNIFICANT BIT of the RGB channels only.
//     Alpha is left alone: some re-encoders rewrite it, and an LSB in alpha is
//     lost silently.
//   - A magic prefix and a length make extraction self-checking, so a picture
//     that never carried anything is rejected instead of producing noise.
//   - A SHA-256 over the payload travels with it. A carrier that was resized,
//     recompressed, or cropped yields a checksum mismatch — which is the
//     difference between "this image is corrupt" and "this image is not ours".
//   - The payload is zlib-compressed first. The document is mostly base64
//     already, and the compressed form fits in about a fifth of the pixels,
//     which keeps the image small enough to publish.
//
// What this deliberately does NOT do: resist JPEG re-encoding. Lossy
// compression rewrites every pixel and destroys an LSB plane. The carrier must
// be PNG, or a WebP encoded losslessly. That is a constraint on the operator,
// not on the reader, and it is why the extraction side reports a checksum
// failure rather than guessing.

const (
	// stegoMagic marks a carrier this package produced. Chosen to be unlikely
	// in the LSB plane of a real photograph.
	stegoMagic = "CTSN"
	stegoVersion = 1
	// headerLen is magic(4) + version(1) + length(4) + sha256(32).
	headerLen = 41
)

// ErrNoPayload means the image is a valid picture with nothing embedded.
var ErrNoPayload = errors.New("catnet: image carries no payload")

// EmbedPayload writes data into the RGB least-significant bits of img and
// returns a new image. The source is not modified.
//
// The image must be large enough: each pixel carries 3 bits, so capacity is
// width*height*3/8 bytes. A caller that ignores this gets a clear error rather
// than a truncated payload.
func EmbedPayload(img image.Image, data []byte) (*image.RGBA, error) {
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	body := compressed.Bytes()

	digest := sha256.Sum256(data)

	var frame bytes.Buffer
	frame.WriteString(stegoMagic)
	frame.WriteByte(stegoVersion)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(body)))
	frame.Write(n[:])
	frame.Write(digest[:])
	frame.Write(body)

	bounds := img.Bounds()
	out := image.NewRGBA(bounds)
	draw := bytes.NewReader(frame.Bytes())

	w, h := bounds.Dx(), bounds.Dy()
	capacity := w * h * 3 / 8
	if frame.Len() > capacity {
		return nil, fmt.Errorf("catnet: payload is %d bytes, image holds %d", frame.Len(), capacity)
	}

	var cur byte
	var have int
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, a := img.At(x, y).RGBA()
			cr, cg, cb := uint8(r>>8), uint8(g>>8), uint8(b>>8)
			for _, ch := range []*uint8{&cr, &cg, &cb} {
				if have == 0 {
					next, err := draw.ReadByte()
					if err == nil {
						cur = next
						have = 8
					} else {
						// Out of payload: leave the remaining bits as they
						// were, so the untouched part of the picture stays
						// exactly as it was.
						have = -1
					}
				}
				if have > 0 {
					bit := (cur >> 7) & 1
					cur <<= 1
					have--
					*ch = (*ch &^ 1) | bit
				}
			}
			// Alpha preserved verbatim: re-encoders rewrite it.
			out.Set(x, y, color.RGBA{cr, cg, cb, uint8(a >> 8)})
		}
	}
	return out, nil
}

// ExtractPayload reads a payload written by EmbedPayload.
//
// Returns ErrNoPayload when there is no magic, and a checksum error when the
// magic is present but the bytes do not survive — the case that means the
// carrier was re-encoded rather than that it is not ours.
func ExtractPayload(img image.Image) ([]byte, error) {
	it := newBitReader(img)

	hdr, ok := it.read(headerLen)
	if !ok {
		return nil, ErrNoPayload
	}
	if string(hdr[:4]) != stegoMagic {
		return nil, ErrNoPayload
	}
	if hdr[4] != stegoVersion {
		return nil, fmt.Errorf("catnet: unsupported stego version %d", hdr[4])
	}
	length := int(binary.BigEndian.Uint32(hdr[5:9]))
	var want [32]byte
	copy(want[:], hdr[9:41])
	if length <= 0 || length > 1<<20 {
		return nil, fmt.Errorf("catnet: implausible payload length %d", length)
	}

	body, ok := it.read(length)
	if !ok {
		return nil, fmt.Errorf("catnet: carrier truncated — holds %d bits fewer than needed", 0)
	}

	zr, err := zlib.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("catnet: payload is not readable: %v", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("catnet: payload corrupt: %v", err)
	}
	if sha256.Sum256(out) != want {
		return nil, fmt.Errorf("catnet: checksum mismatch — the image was re-encoded or altered")
	}
	return out, nil
}

// bitReader walks the RGB least-significant bits of an image in the same order
// EmbedPayload wrote them: row by row, pixel by pixel, R then G then B. Alpha
// is skipped on both sides, which is what keeps a re-encoder from silently
// shifting the stream.
type bitReader struct {
	img  image.Image
	b    image.Point
	ch   int
	cur  byte
	have int
}

func newBitReader(img image.Image) *bitReader {
	return &bitReader{img: img, b: img.Bounds().Min}
}

func (r *bitReader) nextBit() (byte, bool) {
	bounds := r.img.Bounds()
	for r.b.Y < bounds.Max.Y {
		if r.b.X >= bounds.Max.X {
			r.b.X = bounds.Min.X
			r.b.Y++
			r.ch = 0
			continue
		}
		cr, cg, cb, _ := r.img.At(r.b.X, r.b.Y).RGBA()
		var v uint8
		switch r.ch {
		case 0:
			v = uint8(cr >> 8)
		case 1:
			v = uint8(cg >> 8)
		default:
			v = uint8(cb >> 8)
		}
		r.ch++
		if r.ch == 3 {
			r.ch = 0
			r.b.X++
		}
		return v & 1, true
	}
	return 0, false
}

// read collects n bytes, one bit at a time, or reports that the image ran out.
func (r *bitReader) read(n int) ([]byte, bool) {
	out := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		for {
			bit, ok := r.nextBit()
			if !ok {
				return out, false
			}
			r.cur = (r.cur << 1) | bit
			r.have++
			if r.have == 8 {
				out = append(out, r.cur)
				r.cur, r.have = 0, 0
				break
			}
		}
	}
	return out, true
}
