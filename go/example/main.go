// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited. All Rights Reserved.
//
// This software and its associated documentation files (the "Software") are
// the proprietary and confidential information of TEENet Technology (Hong Kong) Limited.
// Unauthorized copying of this file, via any medium, is strictly prohibited.
//
// No license, express or implied, is hereby granted, except by written agreement
// with TEENet Technology (Hong Kong) Limited. Use of this software without permission
// is a violation of applicable laws.
//
// -----------------------------------------------------------------------------

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	client "github.com/TEENet-io/teenet-sdk/go"
)

func main() {
	// Configuration
	configServerAddr := "localhost:50052" // TEE config server address

	fmt.Println("=== TEE DAO Key Management Client with AppID Service Integration ===")

	// Create client
	teeClient := client.NewClient(configServerAddr)
	defer teeClient.Close()

	if err := teeClient.Init(nil); err != nil {
		log.Fatalf("Client initialization failed: %v", err)
	}

	fmt.Println("Client initialized successfully")

	// Example: Get public key by app ID
	fmt.Println("\n1. Get public key by app ID")
	appID := "secure-messaging-app"
	publicKey, protocol, curve, err := teeClient.GetPublicKeyByAppID(appID)
	if err != nil {
		log.Printf("Failed to get public key by app ID: %v", err)
	} else {
		fmt.Printf("Public key for app ID %s:\n", appID)
		fmt.Printf("  - Protocol: %s\n", protocol)
		fmt.Printf("  - Curve: %s\n", curve)
		fmt.Printf("  - Public Key: %s\n", publicKey)
	}

	// Example: Sign message using Sign method
	fmt.Println("\n2. Sign message")
	message := []byte("Hello from AppID Service!")

	signReq := &client.SignRequest{
		Message: message,
		AppID:   appID,
	}
	signResult, err := teeClient.Sign(signReq)
	if err != nil {
		log.Printf("Signing failed: %v", err)
	} else {
		fmt.Printf("Signing successful!\n")
		fmt.Printf("Message: %s\n", string(message))
		fmt.Printf("Signature: %x\n", signResult.Signature)
		fmt.Printf("Success: %t\n", signResult.Success)
		if signResult.Error != "" {
			fmt.Printf("Error: %s\n", signResult.Error)
		}
	}

	// Example: Multi-party voting signature
	fmt.Println("\n3. Multi-party voting signature example")
	votingMessage := []byte("test message for multi-party voting") // Contains "test" to trigger approval

	fmt.Printf("Voting request:\n")
	fmt.Printf("  - Message: %s\n", string(votingMessage))
	fmt.Printf("  - Signer App ID: %s\n", appID)
	fmt.Printf("  - Voting Enabled: true\n")

	// Create HTTP request body similar to signature-tool
	requestData := map[string]interface{}{
		"message":       base64.StdEncoding.EncodeToString(votingMessage),
		"signer_app_id": appID,
	}

	requestBody, err := json.Marshal(requestData)
	if err != nil {
		log.Printf("Failed to create request body: %v", err)
		return
	}

	// Create a mock HTTP request like signature-tool does
	httpReq, err := http.NewRequest("POST", "/vote", bytes.NewBuffer(requestBody))
	if err != nil {
		log.Printf("Failed to create HTTP request: %v", err)
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Make vote decision: approve if message contains "test"
	localApproval := strings.Contains(strings.ToLower(string(votingMessage)), "test")
	fmt.Printf("  - Local Approval: %t\n", localApproval)

	// Sign with voting enabled
	votingSignReq := &client.SignRequest{
		Message:       votingMessage,
		AppID:         appID,
		EnableVoting:  true,
		LocalApproval: localApproval,
		HTTPRequest:   httpReq,
	}

	votingSignResult, err := teeClient.Sign(votingSignReq)
	if err != nil {
		log.Printf("Voting signature failed: %v", err)
	} else {
		fmt.Printf("\nVoting signature completed!\n")
		fmt.Printf("Success: %t\n", votingSignResult.Success)
		if votingSignResult.Signature != nil {
			fmt.Printf("Signature: %x\n", votingSignResult.Signature)
		}

		// Display voting information if available
		if votingSignResult.VotingInfo != nil {
			fmt.Printf("\nVoting Details:\n")
			fmt.Printf("  - Total Targets: %d\n", votingSignResult.VotingInfo.TotalTargets)
			fmt.Printf("  - Successful Votes: %d\n", votingSignResult.VotingInfo.SuccessfulVotes)
			fmt.Printf("  - Required Votes: %d\n", votingSignResult.VotingInfo.RequiredVotes)

			fmt.Printf("\nIndividual Votes:\n")
			for i, vote := range votingSignResult.VotingInfo.VoteDetails {
				fmt.Printf("  %d. Client %s: Success=%t\n", i+1, vote.ClientID, vote.Success)
			}
		}

		if votingSignResult.Error != "" {
			fmt.Printf("Error: %s\n", votingSignResult.Error)
		}
	}

	// Example: Verify signature
	fmt.Println("\n4. Verify signature")
	if signResult != nil && signResult.Signature != nil {
		// Verify the signature we just created
		isValid, err := teeClient.Verify(message, signResult.Signature, appID)
		if err != nil {
			log.Printf("Verification failed: %v", err)
		} else {
			fmt.Printf("Signature verification result: %v\n", isValid)
			fmt.Printf("  - Message: %s\n", string(message))
			fmt.Printf("  - Signature: %x\n", signResult.Signature)
			fmt.Printf("  - App ID: %s\n", appID)
			fmt.Printf("  - Valid: %v\n", isValid)
		}

		// Test with wrong message
		wrongMessage := []byte("Wrong message")
		isValid, err = teeClient.Verify(wrongMessage, signResult.Signature, appID)
		if err != nil {
			log.Printf("Verification with wrong message failed: %v", err)
		} else {
			fmt.Printf("\nVerification with wrong message: %v (expected false)\n", isValid)
		}
	}

	// Example: Verify voting signature
	fmt.Println("\n5. Verify voting signature")
	if votingSignResult != nil && votingSignResult.Signature != nil {
		// Verify the voting signature
		isValid, err := teeClient.Verify(votingMessage, votingSignResult.Signature, appID)
		if err != nil {
			log.Printf("Voting signature verification failed: %v", err)
		} else {
			fmt.Printf("Voting signature verification result: %v\n", isValid)
			fmt.Printf("  - Message: %s\n", string(votingMessage))
			fmt.Printf("  - Signature: %x\n", votingSignResult.Signature)
			fmt.Printf("  - App ID: %s\n", appID)
			fmt.Printf("  - Valid: %v\n", isValid)
		}
	}

	// Example: Test 5 concurrent signatures
	fmt.Println("\n6. Test 5 concurrent signatures")
	testConcurrentSignatures(teeClient, appID)

	fmt.Println("\n=== Example completed ===")
}

// testConcurrentSignatures tests 5 concurrent signature operations
func testConcurrentSignatures(teeClient *client.Client, appID string) {
	const numSignatures = 5
	var wg sync.WaitGroup

	// Channel to collect results
	type signResult struct {
		id        int
		success   bool
		signature []byte
		duration  time.Duration
		err       error
	}
	results := make(chan signResult, numSignatures)

	fmt.Printf("Starting %d concurrent signatures...\n", numSignatures)
	startTime := time.Now()

	// Launch concurrent signature operations
	for i := 0; i < numSignatures; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Create unique message for each signature
			message := []byte(fmt.Sprintf("Concurrent message #%d at %s", id+1, time.Now().Format("15:04:05.000")))

			signReq := &client.SignRequest{
				Message: message,
				AppID:   appID,
			}

			// Time the signature operation
			opStart := time.Now()
			result, err := teeClient.Sign(signReq)
			duration := time.Since(opStart)

			// Send result to channel
			if err != nil {
				results <- signResult{
					id:       id + 1,
					success:  false,
					err:      err,
					duration: duration,
				}
			} else {
				results <- signResult{
					id:        id + 1,
					success:   result.Success,
					signature: result.Signature,
					duration:  duration,
					err:       nil,
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and display results
	successCount := 0
	failureCount := 0
	var totalDuration time.Duration

	fmt.Println("\nConcurrent Signature Results:")
	fmt.Println("------------------------------")

	for result := range results {
		if result.success {
			successCount++
			fmt.Printf("✓ Signature #%d: SUCCESS (Duration: %v)\n", result.id, result.duration)
			if result.signature != nil {
				fmt.Printf("  Signature: %x...\n", result.signature[:16]) // Show first 16 bytes
			}
		} else {
			failureCount++
			if result.err != nil {
				fmt.Printf("✗ Signature #%d: FAILED (Error: %v, Duration: %v)\n", result.id, result.err, result.duration)
			} else {
				fmt.Printf("✗ Signature #%d: FAILED (Duration: %v)\n", result.id, result.duration)
			}
		}
		totalDuration += result.duration
	}

	totalTime := time.Since(startTime)
	avgDuration := totalDuration / numSignatures

	fmt.Println("\n------------------------------")
	fmt.Println("Concurrent Signature Summary:")
	fmt.Printf("  Total Signatures: %d\n", numSignatures)
	fmt.Printf("  Successful: %d\n", successCount)
	fmt.Printf("  Failed: %d\n", failureCount)
	fmt.Printf("  Total Time: %v\n", totalTime)
	fmt.Printf("  Average Duration: %v\n", avgDuration)
	fmt.Printf("  Parallel Speedup: %.2fx\n", float64(totalDuration)/float64(totalTime))

	// Test verification of one successful signature
	if successCount > 0 {
		fmt.Println("\nVerifying one of the concurrent signatures...")
		// Note: In a real scenario, you'd need to store the message along with the signature
		// to verify it later. For this example, we're just showing the structure.
		fmt.Println("(Verification requires storing message-signature pairs)")
	}
}
