// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.


package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	sdk "github.com/TEENet-io/teenet-sdk/go"
)

func main() {
	// Get voter app IDs from environment
	// Example: export VOTER_APP_INSTANCE_IDS="app-id-1,app-id-2,app-id-3"
	voterAppInstanceIDsEnv := os.Getenv("VOTER_APP_INSTANCE_IDS")
	if voterAppInstanceIDsEnv == "" {
		log.Fatal("VOTER_APP_INSTANCE_IDS environment variable is required (comma-separated list of app IDs)")
	}

	voterAppInstanceIDs := strings.Split(voterAppInstanceIDsEnv, ",")
	if len(voterAppInstanceIDs) < 3 {
		log.Fatal("At least 3 voter app IDs are required")
	}

	// Use first voter's app_id as target (for signing after threshold)
	targetAppInstanceID := voterAppInstanceIDs[0]
	publicKeyName := os.Getenv("PUBLIC_KEY_NAME")
	if publicKeyName == "" {
		log.Fatal("PUBLIC_KEY_NAME environment variable is required")
	}

	// SERVICE_URL defaults via SDK if set in env; explicit fallback for local dev.
	serviceURL := os.Getenv("SERVICE_URL")
	if serviceURL == "" {
		serviceURL = "http://localhost:8089"
	}
	message := []byte("Voting test message at " + time.Now().Format("15:04:05"))

	fmt.Printf("🗳️  Voting Test\n")
	fmt.Printf("🎯 Target App Instance ID: %s\n", targetAppInstanceID)
	fmt.Printf("📝 Message: %s\n\n", string(message))

	// Simulate 2 voters voting concurrently (need 2/3 for threshold)
	var wg sync.WaitGroup
	for i := 1; i <= 3; i++ {
		wg.Add(1)
		go func(voteNum int, voterAppInstanceID string) {
			defer wg.Done()

			fmt.Printf("🎯 Vote %d (voter: %s): Submitting...\n", voteNum, voterAppInstanceID[:8])

			client := sdk.NewClient(serviceURL)
			client.SetDefaultAppInstanceID(voterAppInstanceID) // Each voter uses their own app_id

			result, err := client.Sign(context.Background(), message, publicKeyName)

			if err != nil {
				fmt.Printf("❌ Vote %d failed: %v\n\n", voteNum, err)
				client.Close()
				return
			}

			if result.Success {
				fmt.Printf("✅ Vote %d succeeded!\n", voteNum)
				if result.VotingInfo != nil {
					fmt.Printf("   Votes: %d/%d, Status: %s\n",
						result.VotingInfo.CurrentVotes,
						result.VotingInfo.RequiredVotes,
						result.VotingInfo.Status)
				}
				if len(result.Signature) > 0 {
					fmt.Printf("   Signature: %x\n", result.Signature[:32])
				}
				fmt.Println()
			} else {
				fmt.Printf("❌ Vote %d failed: %s\n\n", voteNum, result.Error)
			}

			client.Close()
		}(i, voterAppInstanceIDs[i-1])
	}

	wg.Wait()

	fmt.Println("✅ Voting test completed")
}
