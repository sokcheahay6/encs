package ofb

import (
	"io"

	"github.com/sokcheahay6/encs/tool"
)

const (
	gScryptIterations int32 = 262144 // 2^18
	gSaltSize         int   = 32
	gAesKeySize       int   = 32 // either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
)

// Note: Need authentication
func NewEncryptReader(plainInput io.Reader, password []byte) (io.Reader, error) {
	meta, err := newMeta()
	if err != nil {
		return nil, err
	}
	metaReader, err := meta.newMetaReader()
	if err != nil {
		return nil, err
	}
	ofbReader, err := newOfbReader(plainInput, password, meta)
	if err != nil {
		return nil, err
	}
	return io.MultiReader(metaReader, ofbReader), nil
}

// Note: Need authentication
func NewEncryptWriter(encryptedOutput io.Writer, password []byte) (io.Writer, error) {
	meta, err := newMeta()
	if err != nil {
		return nil, err
	}
	writerWithMeta := tool.NewWriterWithMeta(meta, encryptedOutput)
	return newOfbWriter(writerWithMeta, password, meta)
}

// Note: Need authentication
func NewDecryptReader(encryptedInput io.Reader, password []byte) (io.ReadCloser, error) {
	meta, err := readMeta(encryptedInput)
	if err != nil {
		return nil, err
	}
	reader, err := newOfbReader(encryptedInput, password, meta)
	if err != nil {
		return nil, err
	}
	return &tool.ReadCloser{Reader: reader}, nil
}
