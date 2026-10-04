package extract

import "bytes"

// cappedBuffer keeps the first max bytes and drains the rest, so a runaway
// child never blocks on a full pipe; overflowed, when set, stops the child.
// The buffer is a field, not embedded, so io.Copy cannot use its ReadFrom past the cap.
type cappedBuffer struct {
	buf        bytes.Buffer
	max        int64
	overflow   bool
	overflowed func()
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	room := b.max - int64(b.buf.Len())
	if int64(len(p)) <= room {
		return b.buf.Write(p)
	}
	if !b.overflow && b.overflowed != nil {
		b.overflowed()
	}
	b.overflow = true
	if room > 0 {
		b.buf.Write(p[:room])
	}
	return len(p), nil
}

func (b *cappedBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *cappedBuffer) String() string { return b.buf.String() }
