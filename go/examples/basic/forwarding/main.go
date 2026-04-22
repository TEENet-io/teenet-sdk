// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

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
	// Example: export VOTER_APP_INSTANCE_IDS="app-id-1,app-id-2"
	voterAppInstanceIDsEnv := os.Getenv("VOTER_APP_INSTANCE_IDS")
	if voterAppInstanceIDsEnv == "" {
		log.Fatal("VOTER_APP_INSTANCE_IDS environment variable is required (comma-separated list of app IDs)")
	}

	voterAppInstanceIDs := strings.Split(voterAppInstanceIDsEnv, ",")
	if len(voterAppInstanceIDs) < 2 {
		log.Fatal("At least 2 voter app IDs are required")
	}

	publicKeyName := os.Getenv("PUBLIC_KEY_NAME")
	if publicKeyName == "" {
		log.Fatal("PUBLIC_KEY_NAME environment variable is required")
	}

	// Get service URLs from environment
	// Example: export SERVICE_URLS="http://localhost:8089,http://localhost:8090"
	serviceURLsEnv := os.Getenv("SERVICE_URLS")
	if serviceURLsEnv == "" {
		log.Fatal("SERVICE_URLS environment variable is required (comma-separated list of URLs)")
	}

	serviceURLs := strings.Split(serviceURLsEnv, ",")
	if len(serviceURLs) < 2 {
		log.Fatal("At least 2 service URLs are required")
	}
	message := []byte("Test forwarding message at " + time.Now().Format("15:04:05"))

	fmt.Printf("🔀 Testing Forwarding with Voting\n")
	fmt.Printf("📝 Message: %s\n\n", string(message))

	// Send 2 votes concurrently (need 2/3 for threshold)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(voteNum int, voterAppInstanceID string, url string) {
			defer wg.Done()

			fmt.Printf("🎯 Vote %d (voter: %s): Submitting...\n", voteNum+1, shortPrefix(voterAppInstanceID, 8))

			client := sdk.NewClient(url)
			client.SetDefaultAppInstanceID(voterAppInstanceID)

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
		}(i, voterAppInstanceIDs[i], serviceURLs[i])
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
