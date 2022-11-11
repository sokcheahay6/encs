package tool

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/scrypt"
)

func ReadBytes(r io.Reader, size int) ([]byte, error) {
	buf := make([]byte, size)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func RandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}

func Int32ToBytes(i int32) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, i); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func ReadInt32(r io.Reader) (b []byte, i int32, err error) {
	buf := new(bytes.Buffer)
	tr := io.TeeReader(r, buf)
	err = binary.Read(tr, binary.BigEndian, &i)
	return buf.Bytes(), i, err
}

func MakeAesKey(password, salt []byte, scryptIterations, aesKeySize int) ([]byte, error) {
	return scrypt.Key(password, salt, scryptIterations, 8, 1, aesKeySize)
}

func MakeCipherBlock(password, salt []byte, iterations, aesKeySize int) (cipher.Block, error) {
	aesKey, err := MakeAesKey(password, salt, iterations, aesKeySize)
	if err != nil {
		return nil, err
	}
	return aes.NewCipher(aesKey)
}
