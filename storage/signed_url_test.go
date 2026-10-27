package storage

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/nauticana/keel/config"
)

func TestGetSignedURLRefusesExpiry(t *testing.T) {
	for _, s := range []ObjectStorage{&StorageS3{}, &StorageGCS{}, &StorageAzure{}} {
		for _, seconds := range []int{0, -1, MaxSignedURLSeconds + 1} {
			if _, err := s.GetSignedURL(context.Background(), "k", seconds); !errors.Is(err, ErrInvalidExpiry) {
				t.Errorf("%T %d: %v, want ErrInvalidExpiry", s, seconds, err)
			}
		}
	}
}

func TestAzureSignedURLStartsInThePast(t *testing.T) {
	saved := config.Config().StorageClockSkew
	t.Cleanup(func() { config.Config().StorageClockSkew = saved })
	config.Config().StorageClockSkew = 5 * time.Minute
	key, err := azblob.NewSharedKeyCredential("acct", base64.StdEncoding.EncodeToString([]byte("secret")))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := (&StorageAzure{sharedKey: key, name: "c", url: "https://acct.blob.core.windows.net"}).GetSignedURL(context.Background(), "k", MaxSignedURLSeconds)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	start, err := time.Parse(time.RFC3339, u.Query().Get("st"))
	if err != nil {
		t.Fatal(err)
	}
	expiry, err := time.Parse(time.RFC3339, u.Query().Get("se"))
	if err != nil {
		t.Fatal(err)
	}
	if skew := time.Since(start); skew < 5*time.Minute-time.Second || skew > 5*time.Minute+time.Minute {
		t.Errorf("start %v is %v in the past, want 5m", start, skew)
	}
	if interval := expiry.Sub(start); interval > MaxSignedURLSeconds*time.Second {
		t.Errorf("SAS interval = %v, exceeds Azure's 7-day limit", interval)
	}
}
