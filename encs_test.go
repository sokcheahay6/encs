package encs

import (
	"bytes"
	"crypto/sha512"
	"io"
	"os"
	"strconv"
	"testing"
)

type testData struct {
	password      string
	plainFileName string
	err           error // expected error
}

const testDir = "test"

var encryptFileTests = []testData{
	{"hard to guess password", testDir + "/plain.txt", nil},
}

func TestEncryptAndDecryptFile(t *testing.T) {
	for ver := range encryptWriterMakers {
		t.Logf("testing encryption version %v\n\n", ver)
		for _, data := range encryptFileTests {
			doTestEncryptReaderAndDecryptFile(t, ver, data)
			doTestEncryptWriterAndDecryptFile(t, ver, data)
		}
		t.Logf("------------------------------\n\n")
	}
}

func doTestEncryptReaderAndDecryptFile(t *testing.T, v Version, td testData) {
	t.Logf("doTestEncryptReaderAndDecryptFile data = %#v\n\n", td)

	plainFile, err := os.Open(td.plainFileName)
	if err != nil {
		t.Error(err)
		return
	}
	defer plainFile.Close()

	hashPlain := sha512.New()

	plainTee := io.TeeReader(plainFile, hashPlain)

	// create and open file to save encrypted data.
	// truncate the file if already exists.
	encryptedFileName := td.plainFileName + ".ver" + strconv.FormatUint(uint64(v), 10) + ".encReader.enc.tmp"
	encryptedFile, err := os.OpenFile(encryptedFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		t.Error(err)
		return
	}
	defer encryptedFile.Close()

	encryptReader, err := NewEncryptReaderVersion(v, plainTee, []byte(td.password))
	if err != nil {
		t.Error(err)
		return
	}

	_, err = io.Copy(encryptedFile, encryptReader)
	if err != nil {
		t.Error(err)
		return
	}

	// seek back to the begining of encrypted file
	_, err = encryptedFile.Seek(0, 0)
	if err != nil {
		t.Error(err)
		return
	}

	// create and open file to save decrypted data.
	// truncate the file if already exists.
	decryptedFileName := td.plainFileName + ".ver" + strconv.FormatUint(uint64(v), 10) + ".encReader.dec.tmp"
	decryptedFile, err := os.OpenFile(decryptedFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		t.Error(err)
		return
	}
	defer decryptedFile.Close()

	decrypter, err := NewDecryptReader(encryptedFile, []byte(td.password))
	if err != nil {
		t.Error(err)
		return
	}

	hashDecrypted := sha512.New()
	decryptedTee := io.MultiWriter(decryptedFile, hashDecrypted)

	_, err = io.Copy(decryptedTee, decrypter)
	if err != nil {
		t.Error(err)
		return
	}

	if !bytes.Equal(hashPlain.Sum(nil), hashDecrypted.Sum(nil)) {
		t.Errorf("hash of plain text not equal hash of decrypted text")
		return
	}
}

func doTestEncryptWriterAndDecryptFile(t *testing.T, v Version, td testData) {

	t.Logf("doTestEncryptWriterAndDecryptFile data = %#v\n\n", td)

	plainFile, err := os.Open(td.plainFileName)
	if err != nil {
		t.Error(err)
		return
	}
	defer plainFile.Close()

	hashPlain := sha512.New()

	plainTee := io.TeeReader(plainFile, hashPlain)

	// create and open file to save encrypted data.
	// truncate the file if already exists.
	encryptedFileName := td.plainFileName + ".ver" + strconv.FormatUint(uint64(v), 10) + ".encWriter.enc.tmp"
	encryptedFile, err := os.OpenFile(encryptedFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		t.Error(err)
		return
	}
	defer encryptedFile.Close()

	encryptWriter, err := NewEncryptWriterVersion(v, encryptedFile, []byte(td.password))
	if err != nil {
		t.Error(err)
		return
	}

	_, err = io.Copy(encryptWriter, plainTee)
	if err != nil {
		t.Error(err)
		return
	}

	// seek back to the begining of encrypted file
	_, err = encryptedFile.Seek(0, 0)
	if err != nil {
		t.Error(err)
		return
	}

	// create and open file to save decrypted data.
	// truncate the file if already exists.
	decryptedFileName := td.plainFileName + ".ver" + strconv.FormatUint(uint64(v), 10) + ".encWriter.dec.tmp"
	decryptedFile, err := os.OpenFile(decryptedFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		t.Error(err)
		return
	}
	defer decryptedFile.Close()

	decrypter, err := NewDecryptReader(encryptedFile, []byte(td.password))
	if err != nil {
		t.Error(err)
		return
	}

	hashDecrypted := sha512.New()
	decryptedTee := io.MultiWriter(decryptedFile, hashDecrypted)

	_, err = io.Copy(decryptedTee, decrypter)
	if err != nil {
		t.Error(err)
		return
	}

	if !bytes.Equal(hashPlain.Sum(nil), hashDecrypted.Sum(nil)) {
		t.Errorf("hash of plain text not equal hash of decrypted text")
		return
	}
}

// exists returns whether the given file or directory exists
func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
