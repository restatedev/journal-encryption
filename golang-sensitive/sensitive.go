package sensitive

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

var globalDekCache *DekCache
var globalDekCacheMutex sync.Mutex

// Sensitive wraps a string value and handles encryption/decryption during JSON marshal/unmarshal
type Sensitive struct {
	value string
}

// NewSensitive creates a new Sensitive wrapper around a string value
func NewSensitive(value string) *Sensitive {
	return &Sensitive{value: value}
}

// Value returns the underlying string value
func (s *Sensitive) Value() string {
	return s.value
}

// String implements the Stringer interface
func (s *Sensitive) String() string {
	return s.value
}

// MarshalJSON encrypts the sensitive value and returns the encrypted data as JSON
func (s *Sensitive) MarshalJSON() ([]byte, error) {
	cache := GetGlobalDekCache()
	if cache == nil {
		return nil, fmt.Errorf("DEK cache not initialized")
	}

	encryptingDek, err := cache.GetEncryptingDek(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get encrypting DEK: %w", err)
	}

	storedCipherText, err := Encrypt(encryptingDek.EncryptedDek, encryptingDek.Key, []byte(s.value))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt sensitive value: %w", err)
	}

	encryptedBytes := storedCipherText.ToBytes()
	encodedString := base64.StdEncoding.EncodeToString(encryptedBytes)

	return json.Marshal(encodedString)
}

// UnmarshalJSON decrypts the encrypted data and stores the plaintext value
func (s *Sensitive) UnmarshalJSON(data []byte) error {
	var encodedString string
	if err := json.Unmarshal(data, &encodedString); err != nil {
		return fmt.Errorf("failed to unmarshal encrypted data: %w", err)
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(encodedString)
	if err != nil {
		return fmt.Errorf("failed to decode base64 encrypted data: %w", err)
	}

	storedCipherText, err := StoredCipherTextFromBytes(encryptedBytes)
	if err != nil {
		return fmt.Errorf("failed to parse stored cipher text: %w", err)
	}

	cache := GetGlobalDekCache()
	if cache == nil {
		return fmt.Errorf("DEK cache not initialized")
	}

	decryptingDek, err := cache.GetDecryptingDek(context.Background(), storedCipherText.EncryptedDek)
	if err != nil {
		return fmt.Errorf("failed to get decrypting DEK: %w", err)
	}

	plaintext, err := storedCipherText.Decrypt(decryptingDek)
	if err != nil {
		return fmt.Errorf("failed to decrypt sensitive value: %w", err)
	}

	s.value = string(plaintext)
	return nil
}

// InitializeGlobalDekCache initializes the global DEK cache with the provided KMS client and key ID
func InitializeGlobalDekCache(kmsClient *kms.Client, encryptingKmsKeyID string) {
	globalDekCacheMutex.Lock()
	defer globalDekCacheMutex.Unlock()

	globalDekCache = NewDekCache(kmsClient, encryptingKmsKeyID)
}

// GetGlobalDekCache returns the global DEK cache instance
func GetGlobalDekCache() *DekCache {
	globalDekCacheMutex.Lock()
	defer globalDekCacheMutex.Unlock()
	return globalDekCache
}
