// encryption stream
package encs

import (
	"fmt"
	"io"

	"github.com/sokcheahay6/encs/ofb"
	"github.com/sokcheahay6/encs/tool"
)

const (
	Version1 Version = iota + 1
)

type encryptReaderMaker func(plainInput io.Reader, password []byte) (io.Reader, error)

// EncryptWriter must not write metadata during creation, it must write meta data
// at first first call to Write() method.
// See tool.WriterWithMeta struct for example.
// This condition is needed for used with golang http.ResponseWriter.
// Writing metadata to ResponseWriter will cause it to send http response code too.
// User may need to create EncryptWriter first then calculate response code later.
// Accordingly, func NewEncryptWriterVersion() expect Maker to meet this condition
// so that uint32 "version" is always at the begining of output.
type encryptWriterMaker func(encryptedOutput io.Writer, password []byte) (io.Writer, error)

// why return io.ReadCloser instead of io.Reader
// some decryption include authentication, it needs to read the whole encrypted input,
// and save to a temporary file, then check the authentication code like hmac.
// it need a close() func to close the temporary file.
type decryptReaderMaker func(encryptedInput io.Reader, password []byte) (io.ReadCloser, error)

var encryptReaderMakers map[Version]encryptReaderMaker
var encryptWriterMakers map[Version]encryptWriterMaker
var decryptReaderMakers map[Version]decryptReaderMaker

func init() {
	encryptReaderMakers = map[Version]encryptReaderMaker{
		Version1: ofb.NewEncryptReader,
	}
	encryptWriterMakers = map[Version]encryptWriterMaker{
		Version1: ofb.NewEncryptWriter,
	}
	decryptReaderMakers = map[Version]decryptReaderMaker{
		Version1: ofb.NewDecryptReader,
	}
}

const PreferedVersion = Version1

func NewEncryptReader(plainInput io.Reader, password []byte) (io.Reader, error) {
	return NewEncryptReaderVersion(PreferedVersion, plainInput, password)
}

func NewEncryptReaderVersion(version Version, plainInput io.Reader, password []byte) (io.Reader, error) {
	maker, ok := encryptReaderMakers[version]
	if !ok {
		return nil, fmt.Errorf("can not find encryptReaderMaker for version: %v", version)
	}
	versionReader, err := version.NewReader()
	if err != nil {
		return nil, err
	}
	encryptReader, err := maker(plainInput, password)
	if err != nil {
		return nil, err
	}
	return io.MultiReader(versionReader, encryptReader), nil
}

func NewEncryptWriter(encryptedOutput io.Writer, password []byte) (io.Writer, error) {
	return NewEncryptWriterVersion(PreferedVersion, encryptedOutput, password)
}

func NewEncryptWriterVersion(version Version, encryptedOutput io.Writer, password []byte) (io.Writer, error) {
	maker, ok := encryptWriterMakers[version]
	if !ok {
		return nil, fmt.Errorf("can not find encryptWriterMaker for version: %v", version)
	}
	writerWithVersion := tool.NewWriterWithMeta(version, encryptedOutput)
	return maker(writerWithVersion, password)
}

func NewDecryptReader(encryptedInput io.Reader, password []byte) (io.ReadCloser, error) {
	version, err := ReadVersion(encryptedInput)
	if err != nil {
		return nil, err
	}
	maker, ok := decryptReaderMakers[version]
	if !ok {
		return nil, fmt.Errorf("can not find decryptReaderMaker for version %d", version)
	}
	return maker(encryptedInput, password)
}
