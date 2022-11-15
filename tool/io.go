package tool

import (
	"io"
)

type ReadCloser struct {
	io.Reader
}

// No effect
func (rc *ReadCloser) Close() error {
	return nil
}

type WriterWithMeta struct {
	meta        io.WriterTo
	metaWritten bool // meta is already written
	w           io.Writer
}

func NewWriterWithMeta(meta io.WriterTo, w io.Writer) *WriterWithMeta {
	return &WriterWithMeta{meta: meta, w: w}
}
func (wr *WriterWithMeta) Write(p []byte) (int, error) {
	if !wr.metaWritten {
		if _, err := wr.meta.WriteTo(wr.w); err != nil {
			return 0, err
		}
		wr.metaWritten = true
	}
	return wr.w.Write(p)
}
