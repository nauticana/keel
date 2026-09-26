// Package scan is the content-scanning port and its providers.
package scan

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

const clamdChunk = 65536

// ScannerClamd scans content through a clamd daemon (INSTREAM protocol).
type ScannerClamd struct {
	Addr    string
	Timeout time.Duration // 0 means 60s
}

var _ ContentScanner = (*ScannerClamd)(nil)

func (s *ScannerClamd) Scan(ctx context.Context, content []byte) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	var dialer net.Dialer
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dialer.DialContext(dialCtx, "tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("clamd %s unreachable: %w", s.Addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return err
	}
	size := make([]byte, 4)
	for off := 0; off < len(content); off += clamdChunk {
		end := min(off+clamdChunk, len(content))
		binary.BigEndian.PutUint32(size, uint32(end-off))
		if _, err := conn.Write(size); err != nil {
			return err
		}
		if _, err := conn.Write(content[off:end]); err != nil {
			return err
		}
	}
	binary.BigEndian.PutUint32(size, 0)
	if _, err := conn.Write(size); err != nil {
		return err
	}

	reply := make([]byte, 512)
	n, err := conn.Read(reply)
	if err != nil {
		return fmt.Errorf("clamd response could not be read: %w", err)
	}
	result := strings.TrimRight(string(reply[:n]), "\x00\n")
	switch {
	case strings.HasSuffix(result, "OK"):
		return nil
	case strings.Contains(result, "FOUND"):
		return fmt.Errorf("%w: %s", ErrContentRejected, result)
	default:
		return fmt.Errorf("clamd error: %s", result)
	}
}
