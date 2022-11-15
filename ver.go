package encs

import (
	"bytes"
	"encoding/binary"
	"io"
)

type Version uint32

func (v Version) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (v Version) WriteTo(w io.Writer) (int64, error) {
	err := binary.Write(w, binary.BigEndian, v)
	if err != nil {
		return 0, err
	}
	return 4, nil
}

func (v Version) NewReader() (io.Reader, error) {
	verBytes, err := v.ToBytes()
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(verBytes), nil
}

func ReadVersion(r io.Reader) (v Version, err error) {
	err = binary.Read(r, binary.BigEndian, &v)
	return v, err
}
