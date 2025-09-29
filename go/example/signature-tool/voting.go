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
	"context"
	"log"
	"strings"

	pb "github.com/TEENet-io/teenet-sdk/go/proto/voting"
)

// createVotingHandler creates a voting handler function for the application
func createVotingHandler(appID string) func(context.Context, *pb.VotingRequest) (*pb.VotingResponse, error) {
	return func(ctx context.Context, req *pb.VotingRequest) (*pb.VotingResponse, error) {
		// Application-specific voting logic
		var decision bool
		if strings.Contains(string(req.Message), "test") {
			decision = true
			log.Printf("✅ [%s] Transaction validated and approved", appID)
		} else {
			decision = false
			log.Printf("🚨 [%s] test detected, voting NO for security", appID)
		}

		log.Printf("🗳️  [%s] Final decision: %t", appID, decision)

		return &pb.VotingResponse{
			Success: decision,
			TaskId:  req.TaskId,
		}, nil
	}
}
