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

// Test forwarding with voting
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

func shortPrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func main() {
	// Get voter app IDs from environment
	// Example: export VOTER_APP_IDS="app-id-1,app-id-2"
	voterAppIDsEnv := os.Getenv("VOTER_APP_IDS")
	if voterAppIDsEnv == "" {
		log.Fatal("VOTER_APP_IDS environment variable is required (comma-separated list of app IDs)")
	}

	voterAppIDs := strings.Split(voterAppIDsEnv, ",")
	if len(voterAppIDs) < 2 {
		log.Fatal("At least 2 voter app IDs are required")
	}

	publicKeyName := os.Getenv("PUBLIC_KEY_NAME")
	if publicKeyName == "" {
		log.Fatal("PUBLIC_KEY_NAME environment variable is required")
	}

	// Get consensus URLs from environment
	// Example: export CONSENSUS_URLS="http://localhost:8089,http://localhost:8090"
	consensusURLsEnv := os.Getenv("CONSENSUS_URLS")
	if consensusURLsEnv == "" {
		log.Fatal("CONSENSUS_URLS environment variable is required (comma-separated list of URLs)")
	}

	consensusURLs := strings.Split(consensusURLsEnv, ",")
	if len(consensusURLs) < 2 {
		log.Fatal("At least 2 consensus URLs are required")
	}
	message := []byte("Test forwarding message at " + time.Now().Format("15:04:05"))

	fmt.Printf("🔀 Testing Forwarding with Voting\n")
	fmt.Printf("📝 Message: %s\n\n", string(message))

	// Send 2 votes concurrently (need 2/3 for threshold)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(voteNum int, voterAppID string, url string) {
			defer wg.Done()

			fmt.Printf("🎯 Vote %d (voter: %s): Submitting...\n", voteNum+1, shortPrefix(voterAppID, 8))

			client := sdk.NewClient(url)
			client.SetDefaultAppInstanceID(voterAppID)

			result, err := client.Sign(context.Background(), message, publicKeyName)

			if err != nil {
				fmt.Printf("❌ Vote %d failed: %v\n\n", voteNum+1, err)
				client.Close()
				return
			}

			if result.Success {
				fmt.Printf("✅ Vote %d succeeded!\n", voteNum+1)
				if result.VotingInfo != nil {
					fmt.Printf("   Votes: %d/%d, Status: %s\n",
						result.VotingInfo.CurrentVotes,
						result.VotingInfo.RequiredVotes,
						result.VotingInfo.Status)
				}
				if len(result.Signature) > 0 {
					fmt.Printf("   🎉 Got signature: %x...\n", result.Signature[:min(len(result.Signature), 16)])
				}
				fmt.Println()
			} else {
				fmt.Printf("❌ Vote %d failed: %s\n\n", voteNum+1, result.Error)
			}

			client.Close()
		}(i, voterAppIDs[i], consensusURLs[i])
	}

	wg.Wait()

	fmt.Println("✅ Forwarding test completed")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
