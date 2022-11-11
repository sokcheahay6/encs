package ofb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/sokcheahay6/encs/tool"
)

const (
	gScryptIterations int32 = 262144 // 2^18
	gSaltSize         int   = 32     // 256 bits
	gAesKeySize       int   = 32     // 256 bits
)

// Note: Need authentication
func NewEncryptReader(plainInput io.Reader, password []byte) (io.Reader, error) {

	m, err := newMeta()
	if err != nil {
		return nil, err
	}

	stream, err := newOfbStream(password, m)
	if err != nil {
		return nil, err
	}

	streamReader := &cipher.StreamReader{S: stream, R: plainInput}

	sum := io.MultiReader(bytes.NewReader(m.AsBytes), streamReader)

	return &readCloser{sum}, nil
}

func newOfbStream(password []byte, m *MetaData) (cipher.Stream, error) {

	aesKey, err := tool.MakeAesKey(password, m.Salt, int(m.ScryptIterations), gAesKeySize)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	return cipher.NewOFB(block, m.IV), nil
}

type readCloser struct {
	io.Reader
}

// No effect
func (rc *readCloser) Close() error {
	return nil
}

// Note: Need authentication
func NewEncryptWriter(encryptedOutput io.Writer, password []byte) (io.Writer, error) {

	m, err := newMeta()
	if err != nil {
		return nil, err
	}

	stream, err := newOfbStream(password, m)
	if err != nil {
		return nil, err
	}

	_, err = encryptedOutput.Write(m.AsBytes)
	if err != nil {
		return nil, err
	}

	return &cipher.StreamWriter{S: stream, W: encryptedOutput}, nil
}

type MetaData struct {
	ScryptIterations int32
	Salt             []byte
	IV               []byte
	AsBytes          []byte // all metaData as bytes
}

func newMeta() (*MetaData, error) {

	m := MetaData{
		ScryptIterations: gScryptIterations,
	}

	itersAsBytes, err := tool.Int32ToBytes(m.ScryptIterations)
	if err != nil {
		return nil, err
	}

	m.Salt, err = tool.ReadBytes(rand.Reader, gSaltSize)
	if err != nil {
		return nil, err
	}

	m.IV, err = tool.ReadBytes(rand.Reader, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	m.AsBytes = append(m.AsBytes, itersAsBytes...)
	m.AsBytes = append(m.AsBytes, m.Salt...)
	m.AsBytes = append(m.AsBytes, m.IV...)

	return &m, nil
}

// Note: Need authentication
func NewDecryptReader(encryptedInput io.Reader, password []byte) (io.ReadCloser, error) {

	m, err := readMeta(encryptedInput)
	if err != nil {
		return nil, err
	}

	stream, err := newOfbStream(password, m)
	if err != nil {
		return nil, err
	}

	return &readCloser{
		&cipher.StreamReader{S: stream, R: encryptedInput},
	}, nil
}

func readMeta(encryptedInput io.Reader) (*MetaData, error) {

	m := MetaData{}

	iterAsBytes, iter, err := tool.ReadInt32(encryptedInput)
	if err != nil {
		return nil, err
	}
	m.ScryptIterations = iter

	m.Salt, err = tool.ReadBytes(encryptedInput, gSaltSize)
	if err != nil {
		return nil, err
	}

	m.IV, err = tool.ReadBytes(encryptedInput, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	m.AsBytes = append(m.AsBytes, iterAsBytes...)
	m.AsBytes = append(m.AsBytes, m.Salt...)
	m.AsBytes = append(m.AsBytes, m.IV...)

	return &m, err
}

func ExampleNewOFB() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("some plaintext")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	// OFB mode is the same for both encryption and decryption, so we can
	// also decrypt that ciphertext with NewOFB.

	plaintext2 := make([]byte, len(plaintext))
	stream = cipher.NewOFB(block, iv)
	stream.XORKeyStream(plaintext2, ciphertext[aes.BlockSize:])

	fmt.Printf("%s\n", plaintext2)
	// Output: some plaintext
}

func ExampleStreamReader() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")

	encrypted, _ := hex.DecodeString("cf0495cc6f75dafc23948538e79904a9")
	bReader := bytes.NewReader(encrypted)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// If the key is unique for each ciphertext, then it's ok to use a zero
	// IV.
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	reader := &cipher.StreamReader{S: stream, R: bReader}
	// Copy the input to the output stream, decrypting as we go.
	if _, err := io.Copy(os.Stdout, reader); err != nil {
		panic(err)
	}

	// Note that this example is simplistic in that it omits any
	// authentication of the encrypted data. If you were actually to use
	// StreamReader in this manner, an attacker could flip arbitrary bits in
	// the output.

	// Output: some secret text
}
