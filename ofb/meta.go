package ofb

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/sokcheahay6/encs/tool"
)

type MetaData struct {
	ScryptIterations int32
	Salt             []byte
	IV               []byte
}

func newMeta() (*MetaData, error) {

	var err error
	meta := MetaData{
		ScryptIterations: gScryptIterations,
	}

	meta.Salt, err = tool.ReadBytes(rand.Reader, gSaltSize)
	if err != nil {
		return nil, err
	}

	meta.IV, err = tool.ReadBytes(rand.Reader, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return &meta, nil
}

func (meta *MetaData) AsBytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	if _, err := meta.WriteTo(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (meta *MetaData) WriteTo(w io.Writer) (int64, error) {
	err := binary.Write(w, binary.BigEndian, meta.ScryptIterations)
	if err != nil {
		return 0, err
	}
	n, err := w.Write(meta.Salt)
	n += 4 // already written ScryptIterations is uint32 (4 bytes)
	if err != nil {
		return int64(n), err
	}
	m, err := w.Write(meta.IV)
	return int64(n + m), err
}

func readMeta(r io.Reader) (*MetaData, error) {
	meta := MetaData{}
	err := binary.Read(r, binary.BigEndian, &meta.ScryptIterations)
	if err != nil {
		return nil, err
	}
	meta.Salt, err = tool.ReadBytes(r, gSaltSize)
	if err != nil {
		return nil, err
	}
	meta.IV, err = tool.ReadBytes(r, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return &meta, err
}

func (meta *MetaData) newMetaReader() (io.Reader, error) {
	metaBytes, err := meta.AsBytes()
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(metaBytes), nil
}
