package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source", "nested")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "file.txt"), []byte("round trip"), 0o644); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "archive.zip")
	if err := zipDir(filepath.Dir(source), archive); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dir, "output")
	if err := unzip(archive, destination); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(destination, "source", "nested", "file.txt"))
	if err != nil || string(got) != "round trip" {
		t.Fatalf("extracted content = %q, %v", got, err)
	}
}

func TestExtractCannotWriteThroughExistingSymlink(t *testing.T) {
	for _, name := range []string{"linked/file.txt", "leaf.txt"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			outside, destination := filepath.Join(dir, "outside"), filepath.Join(dir, "output")
			for _, path := range []string{outside, destination} {
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			target, link := outside, filepath.Join(destination, "linked")
			if name == "leaf.txt" {
				target = filepath.Join(outside, "file.txt")
				link = filepath.Join(destination, "leaf.txt")
			}
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			archivePath := filepath.Join(dir, "archive.zip")
			file, err := os.Create(archivePath)
			if err != nil {
				t.Fatal(err)
			}
			archive := zip.NewWriter(file)
			writer, err := archive.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte("escape")); err != nil {
				t.Fatal(err)
			}
			if err := archive.Close(); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if err := unzip(archivePath, destination); err == nil {
				t.Fatal("accepted an escaping symlink")
			}
			if _, err := os.Stat(filepath.Join(outside, "file.txt")); !os.IsNotExist(err) {
				t.Fatalf("wrote outside destination: %v", err)
			}
		})
	}
}
