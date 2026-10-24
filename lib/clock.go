package catnet

import (
	"strconv"
	"strings"
	"time"
)

func nowUnix() int64 { return time.Now().Unix() }

// bucketSize is how often a published document may change. Clients derive the
// bucket from the wall clock so that every client asks CDNs for the same
// revision in the same window, instead of each request getting an arbitrary
// cached copy.
const bucketSize = 10 * time.Minute

// timeBucket returns the current bucket index.
func timeBucket() int64 { return nowUnix() / int64(bucketSize/time.Second) }

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// freshPath appends the bucket as a query parameter. Hosts that ignore unknown
// query parameters are unaffected; caches that key on the full URL see one
// entry per bucket.
func freshPath(path string) string {
	if path == "" {
		return path
	}
	sep := "?"
	if strings.ContainsRune(path, '?') {
		sep = "&"
	}
	return path + sep + "b=" + itoa(timeBucket())
}

func freshPathSeparator(u string) string {
	if strings.ContainsRune(u, '?') {
		return "&"
	}
	return "?"
}
