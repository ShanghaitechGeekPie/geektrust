package webui

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"strings"
	"sync"
)

// assetFS presents gzip-stored build assets as their original files. The
// HTTP file server keeps its existing MIME types, HEAD and Range behavior.
// Plain assets and the clean-checkout placeholder work through the same FS.
type assetFS struct {
	fs.FS
	mu     sync.Mutex
	loaded map[string]func() (*assetContent, error)
}

func (f *assetFS) Open(name string) (fs.File, error) {
	file, err := f.FS.Open(name)
	if !errors.Is(err, fs.ErrNotExist) || !fs.ValidPath(name) {
		return file, err
	}
	// Embedded assets are immutable. Decode each existing gzip file once;
	// Stat, HEAD and subsequent requests still get independent file cursors.
	f.mu.Lock()
	load := f.loaded[name]
	if load == nil {
		packed, packedErr := f.FS.Open(name + ".gz")
		if packedErr != nil {
			f.mu.Unlock()
			return nil, err
		}
		load = sync.OnceValues(func() (*assetContent, error) { return readAsset(packed) })
		if f.loaded == nil {
			f.loaded = make(map[string]func() (*assetContent, error))
		}
		f.loaded[name] = load
	}
	f.mu.Unlock()
	content, err := load()
	if err != nil {
		return nil, err
	}
	return &assetFile{Reader: bytes.NewReader(content.data), info: content.info}, nil
}

type assetContent struct {
	data []byte
	info assetInfo
}

func readAsset(packed fs.File) (*assetContent, error) {
	defer packed.Close()
	info, err := packed.Stat()
	if err != nil {
		return nil, err
	}
	reader, err := gzip.NewReader(packed)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return &assetContent{
		data: data,
		info: assetInfo{FileInfo: info, size: int64(len(data))},
	}, nil
}

type assetFile struct {
	*bytes.Reader
	info assetInfo
}

func (f *assetFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *assetFile) Close() error               { return nil }

type assetInfo struct {
	fs.FileInfo
	size int64
}

func (i assetInfo) Name() string { return strings.TrimSuffix(i.FileInfo.Name(), ".gz") }
func (i assetInfo) Size() int64  { return i.size }
