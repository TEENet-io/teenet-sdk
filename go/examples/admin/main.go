// admin demonstrates the admin management APIs via TEENet SDK.
//
// This example shows how to:
//  1. Invite a passkey user
//  2. List registered passkey users
//  3. Configure a multi-level permission policy on a public key
//  4. Retrieve and then delete the policy
//  5. List audit records
//
// Usage:
//
//	APP_INSTANCE_ID=<your-app-id> CONSENSUS_URL=http://localhost:8089 go run main.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	sdk "github.com/TEENet-io/teenet-sdk/go"
)

func main() {
	consensusURL := os.Getenv("CONSENSUS_URL")
	if consensusURL == "" {
		consensusURL = "http://localhost:8089"
	}

	client := sdk.NewClient(consensusURL)
	if err := client.SetDefaultAppIDFromEnv(); err != nil {
		log.Fatalf("APP_INSTANCE_ID not set: %v", err)
	}
	defer client.Close()

	fmt.Printf("Using App ID: %s\n\n", client.GetDefaultAppID())

	// ─── 1. Invite a passkey user ───────────────────────────────────────────
	fmt.Println("=== Inviting passkey user ===")
	inviteResult, err := client.InvitePasskeyUser(context.Background(), sdk.PasskeyInviteRequest{
		DisplayName:      "Alice",
		ExpiresInSeconds: 86400, // 24 hours
	})
	if err != nil {
		log.Fatalf("InvitePasskeyUser error: %v", err)
	}
	if !inviteResult.Success {
		log.Fatalf("InvitePasskeyUser failed: %s", inviteResult.Error)
	}
	fmt.Printf("  Invite token : %s\n", inviteResult.InviteToken)
	fmt.Printf("  Register URL : %s\n", inviteResult.RegisterURL)
	fmt.Printf("  Expires at   : %s\n\n", inviteResult.ExpiresAt)

	// ─── 2. List passkey users ───────────────────────────────────────────────
	fmt.Println("=== Listing passkey users ===")
	usersResult, err := client.ListPasskeyUsers(context.Background(), 1, 20)
	if err != nil {
		log.Fatalf("ListPasskeyUsers error: %v", err)
	}
	if !usersResult.Success {
		log.Fatalf("ListPasskeyUsers failed: %s", usersResult.Error)
	}
	fmt.Printf("  Total users: %d\n", usersResult.Total)
	for _, u := range usersResult.Users {
		fmt.Printf("  [%d] %s (created: %s)\n", u.ID, u.DisplayName, u.CreatedAt)
	}
	fmt.Println()

	// ─── 3. Upsert permission policy ────────────────────────────────────────
	// The public key name must already be bound to this application.
	const keyName = "my-signing-key"
	fmt.Printf("=== Upserting policy for key %q ===\n", keyName)

	var memberIDs []uint
	for _, u := range usersResult.Users {
		memberIDs = append(memberIDs, u.ID)
	}
	if len(memberIDs) == 0 {
		fmt.Println("  No passkey users to build policy with, skipping.")
	} else {
		threshold := 1
		if len(memberIDs) >= 2 {
			threshold = 2
		}
		upsertResult, err := client.UpsertPermissionPolicy(context.Background(), sdk.PolicyRequest{
			PublicKeyName:  keyName,
			Enabled:        true,
			TimeoutSeconds: 3600,
			Levels: []sdk.PolicyLevel{
				{LevelIndex: 1, Threshold: threshold, MemberIDs: memberIDs},
			},
		})
		if err != nil {
			log.Fatalf("UpsertPermissionPolicy error: %v", err)
		}
		if !upsertResult.Success {
			log.Fatalf("UpsertPermissionPolicy failed: %s", upsertResult.Error)
		}
		fmt.Println("  Policy saved.")
		fmt.Println()

		// ─── 4. Retrieve the policy ──────────────────────────────────────────
		fmt.Printf("=== Retrieving policy for key %q ===\n", keyName)
		policyResult, err := client.GetPermissionPolicy(context.Background(), keyName)
		if err != nil {
			log.Fatalf("GetPermissionPolicy error: %v", err)
		}
		if !policyResult.Success {
			log.Fatalf("GetPermissionPolicy failed: %s", policyResult.Error)
		}
		p := policyResult.Policy
		if p != nil {
			fmt.Printf("  Policy ID     : %d\n", p.ID)
			fmt.Printf("  Enabled       : %v\n", p.Enabled)
			fmt.Printf("  Timeout (s)   : %d\n", p.TimeoutSeconds)
			for _, lvl := range p.Levels {
				fmt.Printf("  Level %d: threshold=%d, members=%v\n", lvl.LevelIndex, lvl.Threshold, lvl.MemberIDs)
			}
		}
		fmt.Println()

		// ─── 5. Delete the policy ────────────────────────────────────────────
		fmt.Printf("=== Deleting policy for key %q ===\n", keyName)
		delResult, err := client.DeletePermissionPolicy(context.Background(), keyName)
		if err != nil {
			log.Fatalf("DeletePermissionPolicy error: %v", err)
		}
		if !delResult.Success {
			log.Fatalf("DeletePermissionPolicy failed: %s", delResult.Error)
		}
		fmt.Println("  Policy deleted.")
		fmt.Println()
	}

	// ─── 6. List audit records ───────────────────────────────────────────────
	fmt.Println("=== Listing audit records ===")
	auditResult, err := client.ListAuditRecords(context.Background(), 1, 10)
	if err != nil {
		log.Fatalf("ListAuditRecords error: %v", err)
	}
	if !auditResult.Success {
		log.Fatalf("ListAuditRecords failed: %s", auditResult.Error)
	}
	fmt.Printf("  Total records: %d\n", auditResult.Total)
	for _, r := range auditResult.Records {
		fmt.Printf("  [%d] event=%s action=%s (created: %s)\n", r.ID, r.EventType, r.Action, r.CreatedAt)
	}
	fmt.Println()

	fmt.Println("Done.")
}
