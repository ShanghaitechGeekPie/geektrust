package webui

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"
)

func gzipAsset(t *testing.T, data []byte) []byte {
	t.Helper()
	var packed bytes.Buffer
	writer := gzip.NewWriter(&packed)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return packed.Bytes()
}

func TestCompressedAssetsPreserveHTTPBehavior(t *testing.T) {
	html := "<!doctype html><div id=\"root\"></div>"
	script := "console.log('the original JavaScript');"
	font := []byte("wOF2 unchanged font")
	modified := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	files := fstest.MapFS{
		"index.html.gz":      {Data: gzipAsset(t, []byte(html)), ModTime: modified},
		"assets/panel.js.gz": {Data: gzipAsset(t, []byte(script)), ModTime: modified},
		"assets/panel.woff2": {Data: font, ModTime: modified},
	}
	server := &Server{dist: &assetFS{FS: files}, hasUI: true}
	for _, tc := range []struct {
		name, method, path, header, value, body, contentType, cache string
		status                                                      int
	}{
		{"index", "GET", "/", "", "", html, "text/html", "no-cache", 200},
		{"script", "GET", "/assets/panel.js", "", "", script, "text/javascript", "public, max-age=31536000, immutable", 200},
		{"head", "HEAD", "/assets/panel.js", "", "", "", "text/javascript", "public, max-age=31536000, immutable", 200},
		{"range", "GET", "/assets/panel.js", "Range", "bytes=7-12", script[7:13], "text/javascript", "public, max-age=31536000, immutable", 206},
		{"not modified", "GET", "/assets/panel.js", "If-Modified-Since", modified.Format("Mon, 02 Jan 2006 15:04:05 GMT"), "", "", "public, max-age=31536000, immutable", 304},
		{"spa fallback", "GET", "/some/route", "", "", html, "text/html", "no-cache", 200},
		{"font", "GET", "/assets/panel.woff2", "", "", string(font), "", "public, max-age=31536000, immutable", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.header != "" {
				request.Header.Set(tc.header, tc.value)
			}
			response := httptest.NewRecorder()
			server.handleStatic(response, request)
			if response.Code != tc.status || response.Body.String() != tc.body {
				t.Fatalf("response = %d %q, want %d %q", response.Code, response.Body.String(), tc.status, tc.body)
			}
			if !strings.HasPrefix(response.Header().Get("Content-Type"), tc.contentType) {
				t.Errorf("Content-Type = %q", response.Header().Get("Content-Type"))
			}
			if response.Header().Get("Cache-Control") != tc.cache || response.Header().Get("Content-Encoding") != "" {
				t.Errorf("unexpected cache or encoding headers: %v", response.Header())
			}
			if tc.method == "HEAD" && response.Header().Get("Content-Length") != fmt.Sprint(len(script)) {
				t.Errorf("HEAD length = %q, want %d", response.Header().Get("Content-Length"), len(script))
			}
			if tc.name == "range" && response.Header().Get("Content-Range") != fmt.Sprintf("bytes 7-12/%d", len(script)) {
				t.Errorf("Content-Range = %q", response.Header().Get("Content-Range"))
			}
		})
	}
	response := httptest.NewRecorder()
	server.handleStatic(response, httptest.NewRequest("GET", "/assets/missing.js", nil))
	if response.Code != 404 {
		t.Fatalf("missing asset = %d", response.Code)
	}
}

func TestCompressedAssetCorruptionIsRejected(t *testing.T) {
	packed := gzipAsset(t, []byte("original bytes"))
	packed[len(packed)-8] ^= 1 // invalidate the CRC without damaging the header
	files := &assetFS{FS: fstest.MapFS{"index.html.gz": {Data: packed}}}
	if _, err := files.Open("index.html"); err == nil {
		t.Fatal("accepted a corrupt compressed asset")
	}
	if _, err := files.Open("../index.html"); err == nil {
		t.Fatal("accepted a path outside the embedded filesystem")
	}
	if _, err := files.Open("missing.js"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
}

type countedAssets struct {
	fs.FS
	packedOpens atomic.Int32
}

func (f *countedAssets) Open(name string) (fs.File, error) {
	if strings.HasSuffix(name, ".gz") {
		f.packedOpens.Add(1)
	}
	return f.FS.Open(name)
}

func TestCompressedAssetLoadsOnceWithIndependentConcurrentReaders(t *testing.T) {
	data := strings.Repeat("immutable web asset\n", 100)
	base := &countedAssets{FS: fstest.MapFS{"panel.js.gz": {Data: gzipAsset(t, []byte(data))}}}
	files := &assetFS{FS: base}
	var group sync.WaitGroup
	start := make(chan struct{})
	for range 20 {
		group.Go(func() {
			<-start
			file, err := files.Open("panel.js")
			if err != nil {
				t.Error(err)
				return
			}
			defer file.Close()
			got, err := io.ReadAll(file)
			if err != nil || string(got) != data {
				t.Errorf("read = %q, %v", got, err)
			}
		})
	}
	close(start)
	group.Wait()
	if info, err := fs.Stat(files, "panel.js"); err != nil || info.Size() != int64(len(data)) {
		t.Fatalf("Stat = %v, %v", info, err)
	}
	if got := base.packedOpens.Load(); got != 1 {
		t.Fatalf("gzip file opened %d times, want 1", got)
	}
}
