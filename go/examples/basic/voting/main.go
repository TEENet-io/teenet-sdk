// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited.
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
	// Example: export VOTER_APP_IDS="app-id-1,app-id-2,app-id-3"
	voterAppIDsEnv := os.Getenv("VOTER_APP_IDS")
	if voterAppIDsEnv == "" {
		log.Fatal("VOTER_APP_IDS environment variable is required (comma-separated list of app IDs)")
	}

	voterAppIDs := strings.Split(voterAppIDsEnv, ",")
	if len(voterAppIDs) < 3 {
		log.Fatal("At least 3 voter app IDs are required")
	}

	// Use first voter's app_id as target (for signing after threshold)
	targetAppID := voterAppIDs[0]
	publicKeyName := os.Getenv("PUBLIC_KEY_NAME")
	if publicKeyName == "" {
		log.Fatal("PUBLIC_KEY_NAME environment variable is required")
	}

	consensusURL := os.Getenv("CONSENSUS_URL")
	if consensusURL == "" {
		consensusURL = "http://localhost:8089" // Default for local development
	}
	message := []byte("Voting test message at " + time.Now().Format("15:04:05"))

	fmt.Printf("🗳️  Voting Test\n")
	fmt.Printf("🎯 Target App ID: %s\n", targetAppID)
	fmt.Printf("📝 Message: %s\n\n", string(message))

	// Simulate 2 voters voting concurrently (need 2/3 for threshold)
	var wg sync.WaitGroup
	for i := 1; i <= 3; i++ {
		wg.Add(1)
		go func(voteNum int, voterAppID string) {
			defer wg.Done()

			fmt.Printf("🎯 Vote %d (voter: %s): Submitting...\n", voteNum, voterAppID[:8])

			client := sdk.NewClient(consensusURL)
			client.SetDefaultAppID(voterAppID) // Each voter uses their own app_id

			result, err := client.Sign(message, publicKeyName)

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
		}(i, voterAppIDs[i-1])
	}

	wg.Wait()

	fmt.Println("✅ Voting test completed")
}
