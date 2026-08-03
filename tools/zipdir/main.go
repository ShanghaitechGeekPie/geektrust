// zipdir creates a ZIP archive containing one directory tree. It exists so
// release packaging needs only the Go toolchain, not a host `zip` command.
package main

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	var err error
	switch {
	case len(os.Args) == 3:
		err = zipDir(os.Args[1], os.Args[2])
	case len(os.Args) == 4 && os.Args[1] == "--extract":
		err = unzip(os.Args[2], os.Args[3])
	default:
		fmt.Fprintln(os.Stderr, "usage: zipdir <source-directory> <output.zip>")
		fmt.Fprintln(os.Stderr, "       zipdir --extract <input.zip> <output-directory>")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "zipdir:", err)
		os.Exit(1)
	}
}

func zipDir(source, output string) (err error) {
	source, err = filepath.Abs(source)
	if err != nil {
		return err
	}
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("source is not a directory: %s", source)
	}

	out, err := os.Create(output)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
	}()

	archive := zip.NewWriter(out)
	defer func() {
		if closeErr := archive.Close(); err == nil {
			err = closeErr
		}
	}()

	parent := filepath.Dir(source)
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			return fmt.Errorf("unsupported file type: %s", path)
		}
		name, err := filepath.Rel(parent, path)
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(name)
		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}
		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(writer, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}

func unzip(archivePath, destination string) error {
	destination, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return err
	}
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer archive.Close()

	for _, entry := range archive.File {
		name := filepath.Clean(filepath.FromSlash(entry.Name))
		if name == "." || filepath.IsAbs(name) || name == ".." ||
			strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe archive path: %q", entry.Name)
		}
		target := filepath.Join(destination, name)
		mode := entry.Mode()
		switch {
		case mode.IsDir():
			if err := os.MkdirAll(target, mode.Perm()); err != nil {
				return err
			}
		case mode.IsRegular():
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			reader, err := entry.Open()
			if err != nil {
				return err
			}
			writer, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode.Perm())
			if err != nil {
				reader.Close()
				return err
			}
			_, copyErr := io.Copy(writer, reader)
			closeWriteErr := writer.Close()
			closeReadErr := reader.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeWriteErr != nil {
				return closeWriteErr
			}
			if closeReadErr != nil {
				return closeReadErr
			}
		default:
			return fmt.Errorf("unsupported file type: %q", entry.Name)
		}
	}
	return nil
}
