package catnet

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"fmt"
	"image"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/makiuchi-d/gozxing"
	qrcode "github.com/makiuchi-d/gozxing/qrcode"
)

// EitaaChannelSource fetches the document out of the newest image posted in an
// Eitaa channel.
//
// The idea: an operator posts a carrier image (see Tools/StegoCarrier.html) and
// the client reads the last post. Eitaa is a domestic Iranian messenger, so the
// host is reachable from Iranian networks when GitHub is not.
//
// Two costs, and both are why this is a last layer rather than a first:
//
//   - It takes TWO requests: the channel page to learn the newest post id, then
//     the post's embed to find the image. There is no shortcut; the post id is
//     not predictable from anywhere the client can see.
//   - The payload travels as base64 of the whole document, which is about a
//     third larger than the file. For a document this size that is acceptable
//     once; it is not something to try on every launch.
//
// The image is read as a QR code. An Eitaa post is re-encoded server-side, so
// an LSB carrier cannot survive the trip — the JPEG the CDN serves has already
// lost those bits. A QR is the only form that works, which is a constraint on
// the operator, not something this reader can work around.
//
// "Newest post" is also the honest limit: if the operator posts anything else
// after the carrier, this layer reads that instead and finds nothing. That is
// reported as a clean miss, not an error, so the next layer still runs.
type EitaaChannelSource struct {
	// Channel is the username, e.g. "roseilandmenu".
	Channel string
	// MaxPosts bounds how far back to look when the newest post carries
	// nothing. Zero means two; more than a handful is a lot of requests for a
	// layer that is already the slowest.
	MaxPosts int
	// Timeout bounds the whole fetch.
	Timeout time.Duration
}

func (e EitaaChannelSource) Name() string { return "eitaa:" + e.Channel }

func (e EitaaChannelSource) Fetch(ctx context.Context) ([]byte, error) {
	if e.Channel == "" {
		return nil, fmt.Errorf("eitaa: channel is required")
	}
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{Timeout: timeout}

	maxPosts := e.MaxPosts
	if maxPosts <= 0 {
		maxPosts = 2
	}

	newest, err := e.newestPostID(ctx, client)
	if err != nil {
		return nil, err
	}

	// Walk back from the newest post: a channel that also posts announcements
	// will have images that carry nothing, and one extra request is cheaper
	// than a layer that only works on a channel used for nothing else.
	for id := newest; id > newest-maxPosts && id > 0; id-- {
		raw, err := e.fetchCarrier(ctx, client, id)
		if err != nil {
			continue
		}
		return raw, nil
	}
	return nil, fmt.Errorf("eitaa: the last %d post(s) carried no document", maxPosts)
}

var (
	eitaaPostIDRe = regexp.MustCompile(`data-post="` + `[^"/]+` + `/(\d+)"`)
	eitaaPhotoRe  = regexp.MustCompile(`background-image:\s*url\('([^']+)'\)`)
)

// newestPostID reads the channel page once and returns the highest post id it
// lists. One request, no pagination: the page shows the latest messages, and
// the largest id on it is the newest.
func (e EitaaChannelSource) newestPostID(ctx context.Context, client *http.Client) (int, error) {
	url := "https://eitaa.com/" + e.Channel
	body, err := httpGet(ctx, client, url)
	if err != nil {
		return 0, fmt.Errorf("eitaa: channel page: %w", err)
	}
	ids := eitaaPostIDRe.FindAllSubmatch(body, -1)
	if len(ids) == 0 {
		return 0, fmt.Errorf("eitaa: no posts found on the channel page")
	}
	newest := 0
	for _, m := range ids {
		if n, err := strconv.Atoi(string(m[1])); err == nil && n > newest {
			newest = n
		}
	}
	return newest, nil
}

// fetchCarrier loads one post's embed and extracts the document from its image.
func (e EitaaChannelSource) fetchCarrier(ctx context.Context, client *http.Client, postID int) ([]byte, error) {
	embedURL := fmt.Sprintf("https://eitaa.com/s/%s/%d?embed=1&mode=eme", e.Channel, postID)
	body, err := httpGet(ctx, client, embedURL)
	if err != nil {
		return nil, err
	}
	m := eitaaPhotoRe.FindSubmatch(body)
	if m == nil {
		return nil, fmt.Errorf("eitaa: post %d has no photo", postID)
	}
	photoURL := "https://eitaa.com" + string(m[1])

	img, err := httpGetImage(ctx, client, photoURL)
	if err != nil {
		return nil, err
	}
	text, err := decodeQRPayload(img)
	if err != nil {
		return nil, err
	}
	return decodeCarrierText(text)
}

// decodeCarrierText turns the QR's text back into the document. The carrier
// holds zlib-compressed, base64-encoded bytes so it fits in a QR at all.
func decodeCarrierText(text string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil {
		return nil, fmt.Errorf("eitaa: payload is not base64: %w", err)
	}
	zr, zerr := zlib.NewReader(bytes.NewReader(raw))
	if zerr != nil {
		return nil, fmt.Errorf("eitaa: payload is not readable: %w", zerr)
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("eitaa: payload is not readable: %w", err)
	}
	return out, nil
}

func httpGet(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; catnet/1)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// The media endpoint answers 206 to a plain GET, serving the bytes it
	// chooses. Treating that as failure made every photo look unreachable.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func httpGetImage(ctx context.Context, client *http.Client, url string) (image.Image, error) {
	body, err := httpGet(ctx, client, url)
	if err != nil {
		return nil, err
	}
	img, _, err := image.Decode(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("eitaa: image is not decodable: %w", err)
	}
	return img, nil
}


// decodeQRPayload reads a carrier image and returns the QR's text.
//
// Tries the whole frame first, then quadrants and a centre crop. A QR placed in
// one corner of a photograph defeats a global threshold: the binarizer picks a
// cut-off for the whole picture and the code loses its contrast. Cropping is
// what makes a corner placement readable without asking the operator to make
// the code enormous.
func decodeQRPayload(img image.Image) (string, error) {
	if text, err := readQR(img); err == nil {
		return text, nil
	}
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	regions := []image.Rectangle{
		image.Rect(w/2, 0, w, h/2),      // top-right
		image.Rect(0, 0, w/2, h/2),      // top-left
		image.Rect(w/2, h/2, w, h),      // bottom-right
		image.Rect(0, h/2, w/2, h),      // bottom-left
		image.Rect(w/4, h/4, 3*w/4, 3*h/4),
	}
	for _, r := range regions {
		if text, err := readQR(crop(img, r)); err == nil {
			return text, nil
		}
	}
	return "", fmt.Errorf("eitaa: no QR code found in the image")
}

func crop(src image.Image, r image.Rectangle) image.Image {
	sb := src.Bounds()
	if r.Min.X < sb.Min.X { r.Min.X = sb.Min.X }
	if r.Min.Y < sb.Min.Y { r.Min.Y = sb.Min.Y }
	if r.Max.X > sb.Max.X { r.Max.X = sb.Max.X }
	if r.Max.Y > sb.Max.Y { r.Max.Y = sb.Max.Y }
	dst := image.NewRGBA(image.Rect(0, 0, r.Dx(), r.Dy()))
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			dst.Set(x-r.Min.X, y-r.Min.Y, src.At(x, y))
		}
	}
	return dst
}

func readQR(img image.Image) (string, error) {
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", err
	}
	res, err := qrcode.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		return "", err
	}
	return res.GetText(), nil
}

// newTestClient is a small seam so tests can reuse the same client the source
// builds, without exporting it.
func newTestClient() *http.Client { return &http.Client{Timeout: 45 * time.Second} }
