package scan

import (
	"fmt"
	"strings"

	"github.com/nauticana/keel/config"
)

// New builds the scanner named by mode: none → (nil, nil), clamd → ScannerClamd at addr.
func New(mode, addr string) (ContentScanner, error) {
	switch strings.TrimSpace(mode) {
	case "", "none":
		return nil, nil
	case "clamd":
		if strings.TrimSpace(addr) == "" {
			return nil, fmt.Errorf("scan: scan_addr is required when scan_mode=clamd")
		}
		return &ScannerClamd{Addr: addr}, nil
	default:
		return nil, fmt.Errorf("scan: unknown scan_mode %q", mode)
	}
}

// NewFromConfig builds the scanner from the scan_mode and scan_addr flags.
func NewFromConfig() (ContentScanner, error) {
	return New(config.Config().ScanMode, config.Config().ScanAddr)
}
