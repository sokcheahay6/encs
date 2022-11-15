package ofb

import (
	"crypto/cipher"
	"io"

	"github.com/sokcheahay6/encs/tool"
)

func newOfbStream(password []byte, meta *MetaData) (cipher.Stream, error) {
	block, err := tool.MakeCipherBlock(password, meta.Salt, int(meta.ScryptIterations), gAesKeySize)
	if err != nil {
		return nil, err
	}
	return cipher.NewOFB(block, meta.IV), nil
}

func newOfbReader(plainInput io.Reader, password []byte, meta *MetaData) (io.Reader, error) {
	ofbStream, err := newOfbStream(password, meta)
	if err != nil {
		return nil, err
	}
	return &cipher.StreamReader{S: ofbStream, R: plainInput}, nil
}

func newOfbWriter(encryptedOutput io.Writer, password []byte, meta *MetaData) (io.Writer, error) {
	ofbStream, err := newOfbStream(password, meta)
	if err != nil {
		return nil, err
	}
	return &cipher.StreamWriter{S: ofbStream, W: encryptedOutput}, nil
}
