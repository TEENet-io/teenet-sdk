package main

import (
	"fmt"
	"log"

	client "github.com/TEENet-io/teenet-sdk/go"
)

func main() {
	// Create and initialize client
	teeClient := client.NewClient()
	defer teeClient.Close()

	teeClient.SetDefaultAppID("ethereum-wallet-app") // if environment variable APP_ID is set, no need to set this

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
