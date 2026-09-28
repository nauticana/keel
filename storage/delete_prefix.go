package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const deletePrefixPage = 1000

// DeletePrefix deletes every object whose key starts with prefix and returns
// how many it deleted. End the prefix with "/" to stay inside one folder:
// "user/1" also matches "user/10/...". Safe to re-run after a partial failure.
func DeletePrefix(ctx context.Context, s ObjectStorage, prefix string) (int, error) {
	if strings.Trim(prefix, "/") == "" {
		return 0, ErrEmptyPrefix
	}
	deleted := 0
	for {
		keys, err := s.ListObjects(ctx, prefix, deletePrefixPage)
		if err != nil {
			return deleted, fmt.Errorf("delete prefix %s: %w", prefix, err)
		}
		gone := 0
		for _, key := range keys {
			if err := ctx.Err(); err != nil {
				return deleted, err
			}
			switch err := s.DeleteObject(ctx, key); {
			case err == nil:
				deleted++
			case errors.Is(err, ErrNotFound):
				gone++
			default:
				return deleted, fmt.Errorf("delete prefix %s: %w", prefix, err)
			}
		}
		if len(keys) < deletePrefixPage {
			return deleted, nil
		}
		if gone == len(keys) {
			return deleted, fmt.Errorf("delete prefix %s: listing keeps returning deleted keys", prefix)
		}
	}
}
