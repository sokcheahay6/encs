// encryption stream
package encs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/sokcheahay6/encs/ofb"
)

type Version uint32

const (
	Version1 Version = iota + 1
)

type encryptReaderMaker func(plainInput io.Reader, password []byte) (io.Reader, error)
type encryptWriterMaker func(encryptedOutput io.Writer, password []byte) (io.Writer, error)

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
		return nil, fmt.Errorf("can not find encryptReaderMaker for version: %v", PreferedVersion)
	}
	encReader, err := maker(plainInput, password)
	if err != nil {
		return nil, err
	}
	verBytes, err := versionToBytes(version)
	if err != nil {
		return nil, err
	}
	return io.MultiReader(bytes.NewReader(verBytes), encReader), nil
}

func NewEncryptWriter(encryptedOutput io.Writer, password []byte) (io.Writer, error) {
	return NewEncryptWriterVersion(PreferedVersion, encryptedOutput, password)
}

// Note: it writes version (plain bytes) into encryptedOutput stream.
func NewEncryptWriterVersion(version Version, encryptedOutput io.Writer, password []byte) (io.Writer, error) {

	maker, ok := encryptWriterMakers[version]
	if !ok {
		return nil, fmt.Errorf("can not find encryptWriterMaker for version: %v", PreferedVersion)
	}

	v, err := versionToBytes(version)
	if err != nil {
		return nil, err
	}
	_, err = encryptedOutput.Write(v)
	if err != nil {
		return nil, err
	}

	return maker(encryptedOutput, password)
}

func versionToBytes(i Version) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, i); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func NewDecryptReader(encryptedInput io.Reader, password []byte) (io.ReadCloser, error) {

	version, err := readVersion(encryptedInput)
	if err != nil {
		return nil, err
	}
	maker, ok := decryptReaderMakers[version]
	if !ok {
		return nil, fmt.Errorf("can not find decryptReaderMaker for version %d", version)
	}
	return maker(encryptedInput, password)
}

func readVersion(r io.Reader) (v Version, err error) {
	err = binary.Read(r, binary.BigEndian, &v)
	return v, err
}
