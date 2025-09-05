package sensitive

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
)

var storedPrefix = []byte("RTv1\x00")

const ivLength = 12

// StoredCipherText represents encrypted data with metadata
type StoredCipherText struct {
	EncryptedDek []byte
	IV           []byte
	CipherText   []byte
}

// StoredCipherTextFromBytes parses a StoredCipherText from bytes
func StoredCipherTextFromBytes(data []byte) (*StoredCipherText, error) {
	if len(data) < len(storedPrefix) {
		return nil, fmt.Errorf("invalid stored ciphertext: too short")
	}

	prefix := data[:len(storedPrefix)]
	if !bytes.Equal(prefix, storedPrefix) {
		return nil, fmt.Errorf("invalid stored ciphertext prefix; could this data be plaintext?")
	}

	unprefixedData := data[len(storedPrefix):]
	if len(unprefixedData) < 2 {
		return nil, fmt.Errorf("invalid stored ciphertext length")
	}

	// Read encrypted DEK length (big endian u16)
	encryptedDekLength := binary.BigEndian.Uint16(unprefixedData[:2])

	if len(unprefixedData) < int(2+encryptedDekLength+ivLength) {
		return nil, fmt.Errorf("invalid stored ciphertext length")
	}

	encryptedDek := unprefixedData[2 : 2+encryptedDekLength]
	iv := unprefixedData[2+encryptedDekLength : 2+encryptedDekLength+ivLength]
	cipherText := unprefixedData[2+encryptedDekLength+ivLength:]

	return &StoredCipherText{
		EncryptedDek: encryptedDek,
		IV:           iv,
		CipherText:   cipherText,
	}, nil
}

// Decrypt decrypts the stored cipher text using the provided AEAD cipher
func (s *StoredCipherText) Decrypt(aead cipher.AEAD) ([]byte, error) {
	plaintext, err := aead.Open(nil, s.IV, s.CipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	return plaintext, nil
}

// ToBytes serializes the StoredCipherText to bytes
func (s *StoredCipherText) ToBytes() []byte {
	data := make([]byte, len(storedPrefix)+2+len(s.EncryptedDek)+ivLength+len(s.CipherText))

	offset := 0
	copy(data[offset:], storedPrefix)
	offset += len(storedPrefix)

	// Write encrypted DEK length as big endian u16
	binary.BigEndian.PutUint16(data[offset:offset+2], uint16(len(s.EncryptedDek)))
	offset += 2

	copy(data[offset:], s.EncryptedDek)
	offset += len(s.EncryptedDek)

	copy(data[offset:], s.IV)
	offset += ivLength

	copy(data[offset:], s.CipherText)

	return data
}

// Encrypt encrypts data using the provided AEAD cipher and returns a StoredCipherText
func Encrypt(encryptedDek []byte, aead cipher.AEAD, data []byte) (*StoredCipherText, error) {
	if len(encryptedDek) > math.MaxUint16 {
		return nil, fmt.Errorf("encrypted DEK too long: %d bytes (max %d)", len(encryptedDek), math.MaxInt16)
	}

	iv := make([]byte, ivLength)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	cipherText := aead.Seal(nil, iv, data, nil)

	return &StoredCipherText{
		EncryptedDek: encryptedDek,
		IV:           iv,
		CipherText:   cipherText,
	}, nil
}
