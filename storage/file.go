package storage

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Each object is a folder named by its key holding the content and attributes.
const (
	fileData       = "DATA.bin"
	fileAttributes = "ATTR.txt"
)

// StorageFile stores objects under a root folder on the local file system.
// Content types are not persisted and it serves no URLs.
type StorageFile struct {
	root string
}

// NewStorageFile binds to spec.Bucket, which must be an existing folder
// (ErrBucketNotFound otherwise; CreateBucket makes it).
func NewStorageFile(spec Spec) (*StorageFile, error) {
	info, err := os.Stat(spec.Bucket)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && !info.IsDir()) {
		return nil, fmt.Errorf("file: root %s: %w", spec.Bucket, ErrBucketNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("file: root %s: %w", spec.Bucket, err)
	}
	return &StorageFile{root: spec.Bucket}, nil
}

func createBucketFile(spec Spec) error {
	if err := os.MkdirAll(spec.Bucket, 0755); err != nil {
		return fmt.Errorf("file: create root %s: %w", spec.Bucket, err)
	}
	return nil
}

func (s *StorageFile) Bucket() string { return s.root }

// folder maps a key to its object folder, refusing keys that escape the root.
func (s *StorageFile) folder(key string) (string, error) {
	rel := strings.Trim(key, "/")
	if rel == "" || !filepath.IsLocal(filepath.FromSlash(rel)) {
		return "", fmt.Errorf("file: invalid key %q", key)
	}
	return filepath.Join(s.root, filepath.FromSlash(rel)), nil
}

func fileErr(op, key string, err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("file: %s %s: %w", op, key, ErrNotFound)
	}
	return fmt.Errorf("file: %s %s: %w", op, key, err)
}

// writeTemp writes data next to name and returns the temp path.
func writeTemp(name string, data io.Reader) (string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(name), filepath.Base(name)+".*.tmp")
	if err != nil {
		return "", err
	}
	if data == nil {
		data = strings.NewReader("")
	}
	if _, err := io.Copy(tmp, data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// writeAtomic renames a fully written temp file over name, so a reader never
// sees a partial file.
func writeAtomic(name string, data io.Reader) error {
	tmp, err := writeTemp(name, data)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	return os.Rename(tmp, name)
}

// writeIfAbsent links the temp file to name, which fails when name exists;
// a rename would overwrite silently.
func writeIfAbsent(name string, data io.Reader) error {
	tmp, err := writeTemp(name, data)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.Link(tmp, name); errors.Is(err, fs.ErrExist) {
		return ErrExists
	} else if err != nil {
		return err
	}
	return nil
}

func encodeAttributes(attributes map[string]string) ([]byte, error) {
	var b bytes.Buffer
	for k, v := range attributes {
		if k == "" || strings.ContainsAny(k, "=\r\n") || strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("file: attribute %q cannot be stored", k)
		}
		b.WriteString(k + "=" + v + "\n")
	}
	return b.Bytes(), nil
}

func (s *StorageFile) put(key string, data io.Reader, attributes map[string]string, write func(name string, data io.Reader) error) error {
	folder, err := s.folder(key)
	if err != nil {
		return err
	}
	attrs, err := encodeAttributes(attributes)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(folder, 0755); err != nil {
		return fileErr("put", key, err)
	}
	if err := write(filepath.Join(folder, fileData), data); err != nil {
		return fileErr("put", key, err)
	}
	if err := writeAtomic(filepath.Join(folder, fileAttributes), bytes.NewReader(attrs)); err != nil {
		return fileErr("put", key, err)
	}
	return nil
}

func (s *StorageFile) PutObject(_ context.Context, key string, data io.Reader, _ string, attributes map[string]string) error {
	return s.put(key, data, attributes, writeAtomic)
}

func (s *StorageFile) PutObjectIfAbsent(_ context.Context, key string, data io.Reader, _ string, attributes map[string]string) error {
	return s.put(key, data, attributes, writeIfAbsent)
}

func (s *StorageFile) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	folder, err := s.folder(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(folder, fileData))
	if err != nil {
		return nil, fileErr("get", key, err)
	}
	return f, nil
}

func (s *StorageFile) GetObjectAndAttributes(ctx context.Context, key string) (*Component, error) {
	folder, err := s.folder(key)
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(filepath.Join(folder, fileData))
	if err != nil {
		return nil, fileErr("get", key, err)
	}
	attrs, err := s.GetObjectAttributes(ctx, key)
	if err != nil {
		return nil, err
	}
	return NewComponent(content, attrs), nil
}

// DeleteObject removes the object's files, then every folder left empty up to
// the root: folders only exist to hold objects, as on the cloud backends.
func (s *StorageFile) DeleteObject(_ context.Context, key string) error {
	folder, err := s.folder(key)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(folder, fileData)); err != nil {
		return fileErr("delete", key, err)
	}
	if err := os.Remove(filepath.Join(folder, fileAttributes)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fileErr("delete", key, err)
	}
	for dir := folder; dir != s.root; dir = filepath.Dir(dir) {
		if entries, err := os.ReadDir(dir); err != nil || len(entries) > 0 {
			break
		}
		if err := os.Remove(dir); err != nil {
			return fileErr("delete", key, err)
		}
	}
	return nil
}

// splitPrefix returns the folder a prefix names and the partial name that
// follows its last "/".
func (s *StorageFile) splitPrefix(prefix string) (dir, partial string, err error) {
	dir, partial = path.Split(strings.TrimLeft(prefix, "/"))
	dir = strings.TrimSuffix(dir, "/")
	start := s.root
	if dir != "" {
		if start, err = s.folder(dir); err != nil {
			return "", "", err
		}
	}
	return start, partial, nil
}

// ListObjects walks the deepest folder the prefix names and keeps keys that
// start with prefix, matching the cloud backends' string-prefix semantics.
func (s *StorageFile) ListObjects(_ context.Context, prefix string, limit int) ([]string, error) {
	start, _, err := s.splitPrefix(prefix)
	if err != nil {
		return nil, err
	}
	var keys []string
	err = filepath.WalkDir(start, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && p == start {
				return fs.SkipAll
			}
			return err
		}
		if d.IsDir() || d.Name() != fileData {
			return nil
		}
		rel, err := filepath.Rel(s.root, filepath.Dir(p))
		if err != nil {
			return err
		}
		if key := filepath.ToSlash(rel); strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
			if limit > 0 && len(keys) == limit {
				return fs.SkipAll
			}
		}
		return nil
	})
	if err != nil {
		return nil, fileErr("list", prefix, err)
	}
	return keys, nil
}

// ListPrefixes returns the child folders of the folder the prefix names whose
// name starts with the partial segment after its last "/".
func (s *StorageFile) ListPrefixes(_ context.Context, prefix string, limit int) ([]string, error) {
	start, partial, err := s.splitPrefix(prefix)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(start)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fileErr("list", prefix, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), partial) {
			names = append(names, e.Name())
			if limit > 0 && len(names) == limit {
				break
			}
		}
	}
	return names, nil
}

func (s *StorageFile) SetObjectAttributes(_ context.Context, key string, attributes map[string]string) error {
	folder, err := s.folder(key)
	if err != nil {
		return err
	}
	attrs, err := encodeAttributes(attributes)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(folder, fileData)); err != nil {
		return fileErr("set attributes", key, err)
	}
	if err := writeAtomic(filepath.Join(folder, fileAttributes), bytes.NewReader(attrs)); err != nil {
		return fileErr("set attributes", key, err)
	}
	return nil
}

func (s *StorageFile) GetObjectAttributes(_ context.Context, key string) (map[string]string, error) {
	folder, err := s.folder(key)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(folder, fileData)); err != nil {
		return nil, fileErr("attributes", key, err)
	}
	attrs := map[string]string{}
	file, err := os.Open(filepath.Join(folder, fileAttributes))
	if errors.Is(err, fs.ErrNotExist) {
		return attrs, nil
	}
	if err != nil {
		return nil, fileErr("attributes", key, err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				return nil, fmt.Errorf("file: malformed attribute line %q for %s", line, key)
			}
			attrs[k] = v
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fileErr("attributes", key, err)
	}
	return attrs, nil
}

func (s *StorageFile) GetSignedURL(_ context.Context, key string, _ int) (string, error) {
	return "", fmt.Errorf("file: sign URL for %s: %w", key, ErrUnsupported)
}

// PublicURL is always "": the key names a folder, not a servable file.
func (s *StorageFile) PublicURL(string) string { return "" }

var _ ObjectStorage = (*StorageFile)(nil)
