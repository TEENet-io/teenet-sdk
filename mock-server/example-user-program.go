package main

import (
	"fmt"
	"log"

	client "github.com/TEENet-io/teenet-sdk/go"
)

func main() {
	// Create client (reads TEE_CONFIG_ADDR and APP_ID from env vars)
	// TEE_CONFIG_ADDR defaults to localhost:50052
	// APP_ID is required (set via: APP_ID=ethereum-wallet-app go run example-user-program.go)
	teeClient := client.NewClient()
	defer teeClient.Close()

	// Initialize client
	if err := teeClient.Init(); err != nil {
		log.Fatal(err)
	}

	// Sign a message
	message := []byte("Hello, TEE DAO!")
	result, err := teeClient.Sign(message)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✅ Signature: %x\n", result.Signature)

	// Verify the signature
	valid, _ := teeClient.Verify(message, result.Signature)
	fmt.Printf("✅ Valid: %v\n", valid)
}
