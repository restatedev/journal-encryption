package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	sensitive "github.com/restatedev/sensitive"
)

func main() {
	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal("Failed to load AWS config:", err)
	}

	// Create KMS client
	kmsClient := kms.NewFromConfig(cfg)

	// Initialize the global DEK cache
	// Replace with your actual KMS key ID
	kmsKeyID := "50e2ce78-d199-4078-b86f-bc028deb0e3a"
	sensitive.InitializeGlobalDekCache(kmsClient, kmsKeyID)

	// Create a sensitive value
	password := sensitive.NewSensitive("secret-password-123")

	// Demonstrate JSON marshaling (encrypts the value)
	jsonData, err := json.Marshal(password)
	if err != nil {
		log.Fatal("Failed to marshal sensitive value:", err)
	}

	fmt.Printf("Encrypted JSON: %s\n", string(jsonData))

	// Demonstrate JSON unmarshaling (decrypts the value)
	var decrypted sensitive.Sensitive
	err = json.Unmarshal(jsonData, &decrypted)
	if err != nil {
		log.Fatal("Failed to unmarshal sensitive value:", err)
	}

	fmt.Printf("Decrypted value: %s\n", decrypted.Value())

	// Demonstrate usage in a struct
	type Config struct {
		DatabaseURL *sensitive.Sensitive `json:"database_url"`
		APIKey      *sensitive.Sensitive `json:"api_key"`
	}

	config := Config{
		DatabaseURL: sensitive.NewSensitive("postgres://user:pass@localhost/db"),
		APIKey:      sensitive.NewSensitive("sk-1234567890abcdef"),
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		log.Fatal("Failed to marshal config:", err)
	}

	fmt.Printf("Encrypted config JSON: %s\n", string(configJSON))

	var decryptedConfig Config
	err = json.Unmarshal(configJSON, &decryptedConfig)
	if err != nil {
		log.Fatal("Failed to unmarshal config:", err)
	}

	fmt.Printf("Decrypted database URL: %s\n", decryptedConfig.DatabaseURL.Value())
	fmt.Printf("Decrypted API key: %s\n", decryptedConfig.APIKey.Value())

}
