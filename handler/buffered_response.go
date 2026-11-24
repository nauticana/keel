package handler

import (
	"bytes"
	"net/http"
)

const maxReplayBody = 1 << 20

// bufferedResponse holds a response back until flush, so it can be recorded
// before the client sees it. One larger than maxReplayBody is passed through.
type bufferedResponse struct {
	http.ResponseWriter
	status   int
	body     bytes.Buffer
	overflow bool
}

func (b *bufferedResponse) WriteHeader(status int) {
	if b.status == 0 && status >= http.StatusOK {
		b.status = status
	}
}

func (b *bufferedResponse) Write(p []byte) (int, error) {
	b.WriteHeader(http.StatusOK)
	if !b.overflow && b.body.Len()+len(p) > maxReplayBody {
		b.overflow = true
		if err := b.flush(); err != nil {
			return 0, err
		}
	}
	if b.overflow {
		return b.ResponseWriter.Write(p)
	}
	return b.body.Write(p)
}

func (b *bufferedResponse) flush() error {
	b.ResponseWriter.WriteHeader(b.status)
	if b.body.Len() == 0 {
		return nil
	}
	_, err := b.ResponseWriter.Write(b.body.Bytes())
	return err
}
