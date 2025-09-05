package sensitive

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	lru "github.com/hashicorp/golang-lru/v2"
)

// EncryptingDek represents a data encryption key for encryption
type EncryptingDek struct {
	Key          cipher.AEAD
	EncryptedDek []byte
}

// DekCache manages data encryption keys with caching
type DekCache struct {
	kms                *kms.Client
	encryptingKmsKeyID string
	encryptingDek      *EncryptingDek
	encryptingDekMutex sync.RWMutex
	decryptingDeks     *lru.Cache[string, cipher.AEAD]
}

// NewDekCache creates a new DEK cache
func NewDekCache(kmsClient *kms.Client, encryptingKmsKeyID string) *DekCache {
	// cipher.AEAD:
	// 	16 byte interface
	// 	288 'gcm' object underneath
	// = 304 bytes
	// the lru cache itself will probably have some overhead as well, so call it 350.
	// 8192 entries is around 3 megabytes.
	decryptingDeks, err := lru.New[string, cipher.AEAD](8192)
	if err != nil {
		// the library only returns an error if size is <= 0
		panic(err)
	}
	return &DekCache{
		kms:                kmsClient,
		encryptingKmsKeyID: encryptingKmsKeyID,
		decryptingDeks:     decryptingDeks,
	}
}

// GetEncryptingDek returns the encrypting DEK, creating it if necessary
func (d *DekCache) GetEncryptingDek(ctx context.Context) (*EncryptingDek, error) {
	d.encryptingDekMutex.RLock()
	if d.encryptingDek != nil {
		defer d.encryptingDekMutex.RUnlock()
		return d.encryptingDek, nil
	}
	d.encryptingDekMutex.RUnlock()

	d.encryptingDekMutex.Lock()
	defer d.encryptingDekMutex.Unlock()

	// Double-check pattern
	if d.encryptingDek != nil {
		return d.encryptingDek, nil
	}

	start := time.Now()
	result, err := d.kms.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   &d.encryptingKmsKeyID,
		KeySpec: types.DataKeySpecAes256,
	})
	if err != nil {
		log.Printf("Failed to create encrypting dek against KMS key '%s': %v", d.encryptingKmsKeyID, err)
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}

	if result.Plaintext == nil || result.CiphertextBlob == nil {
		return nil, fmt.Errorf("missing plaintext or ciphertext from KMS response")
	}

	// Create AES-GCM cipher for encryption
	block, err := aes.NewCipher(result.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	d.encryptingDek = &EncryptingDek{
		Key:          aead,
		EncryptedDek: result.CiphertextBlob,
	}

	// Cache the decrypting version as well
	d.decryptingDeks.Add(string(result.CiphertextBlob), aead)

	log.Printf("Created encrypting dek against KMS key '%s' in %v", d.encryptingKmsKeyID, time.Since(start))
	return d.encryptingDek, nil
}

// GetDecryptingDek returns a decrypting DEK for the given encrypted DEK
func (d *DekCache) GetDecryptingDek(ctx context.Context, encryptedDek []byte) (cipher.AEAD, error) {
	key := string(encryptedDek)

	if cached, exists := d.decryptingDeks.Get(key); exists {
		return cached, nil
	}

	start := time.Now()
	result, err := d.kms.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: encryptedDek,
	})
	if err != nil {
		log.Printf("Failed to load decrypting dek: %v", err)
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	if result.Plaintext == nil {
		return nil, fmt.Errorf("missing plaintext from KMS decrypt response")
	}

	block, err := aes.NewCipher(result.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	d.decryptingDeks.Add(key, aead)

	log.Printf("Loaded decrypting dek in %v", time.Since(start))
	return aead, nil
}
