package storage

import (
	"context"
	"errors"
	"testing"
)

type signer struct{ *StorageFile }

func (signer) GetSignedURL(context.Context, string, int) (string, error) {
	return "https://signed", nil
}

func TestCheckSigning(t *testing.T) {
	ctx := context.Background()
	files := newFileStore(t)
	if err := CheckSigning(ctx, files); !errors.Is(err, ErrUnsupported) {
		t.Errorf("file backend: %v, want ErrUnsupported", err)
	}
	if err := CheckSigning(ctx, nil); err == nil {
		t.Error("nil backend passed")
	}
	if err := CheckSigning(ctx, signer{files}); err != nil {
		t.Errorf("signing backend: %v", err)
	}
}
