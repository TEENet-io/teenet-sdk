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

// Package client provides simplified TEE DAO key management client
package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/TEENet-io/teenet-sdk/go/pkg/config"
	"github.com/TEENet-io/teenet-sdk/go/pkg/constants"
	"github.com/TEENet-io/teenet-sdk/go/pkg/task"
	"github.com/TEENet-io/teenet-sdk/go/pkg/usermgmt"
	"github.com/TEENet-io/teenet-sdk/go/pkg/utils"
	"github.com/TEENet-io/teenet-sdk/go/pkg/verification"
	"github.com/TEENet-io/teenet-sdk/go/pkg/voting"
	pb "github.com/TEENet-io/teenet-sdk/go/proto/voting"
	"google.golang.org/grpc"
)

// VoteDetail contains details of each vote
type VoteDetail struct {
	ClientID string `json:"client_id"`
	Success  bool   `json:"success"`
	Response bool   `json:"response"`
	Error    string `json:"error,omitempty"`
}

// SignRequest contains all parameters for sign operations
type SignRequest struct {
	Message      []byte // Message to sign
	AppID        string // App ID for signing
	EnableVoting bool   // Whether to enable voting process

	// Voting-specific fields (only used when EnableVoting is true)
	LocalApproval   bool              // Local approval status for voting
	VoteRequestData []byte            // Vote request body data
	Headers         map[string]string // HTTP headers to forward
	HTTPRequest     *http.Request     // Original HTTP request (optional)
}

// SignResult contains the result of a sign operation
type SignResult struct {
	Signature []byte `json:"signature,omitempty"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`

	// Voting-specific fields (only present when voting was performed)
	VotingInfo *VotingInfo `json:"voting_info,omitempty"`
}

// VotingInfo contains voting-specific information
type VotingInfo struct {
	TotalTargets    int          `json:"total_targets"`
	SuccessfulVotes int          `json:"successful_votes"`
	RequiredVotes   int          `json:"required_votes"`
	VoteDetails     []VoteDetail `json:"vote_details"`
}

// Client is a simplified key management client with voting capabilities
type Client struct {
	configClient   *config.Client
	taskClient     *task.Client
	userMgmtClient *usermgmt.Client
	nodeConfig     *config.NodeConfig
	frostTimeout   time.Duration
	ecdsaTimeout   time.Duration
	votingHandler  func(context.Context, *pb.VotingRequest) (*pb.VotingResponse, error)
	votingServer   *grpc.Server
}

// NewClient creates a new client instance
func NewClient(configServerAddr string) *Client {
	client := &Client{
		configClient: config.NewClient(configServerAddr),
		frostTimeout: constants.DefaultClientTimeout,
		ecdsaTimeout: constants.DefaultClientTimeout * 2,
	}

	// Set default voting handler (auto-approve all votes)
	client.SetVotingHandler(client.createDefaultVotingHandler())

	return client
}

// createDefaultVotingHandler creates a default voting handler that auto-approves all voting requests
func (c *Client) createDefaultVotingHandler() func(context.Context, *pb.VotingRequest) (*pb.VotingResponse, error) {
	return func(ctx context.Context, req *pb.VotingRequest) (*pb.VotingResponse, error) {
		// Simulate processing delay
		time.Sleep(200 * time.Millisecond)

		// Auto-approve all voting requests by default
		log.Printf("✅ [DEFAULT] Auto-approving voting request for task: %s", req.TaskId)

		return &pb.VotingResponse{
			Success: true,
			TaskId:  req.TaskId,
		}, nil
	}
}

// SetVotingHandler allows users to set a custom voting handler and restarts the voting service
func (c *Client) SetVotingHandler(handler func(context.Context, *pb.VotingRequest) (*pb.VotingResponse, error)) {
	c.votingHandler = handler

	// If voting service is already running, restart it with the new handler
	if c.votingServer != nil {
		log.Printf("🔄 Restarting voting service with new handler...")
		if err := voting.StartVotingService(handler, &c.votingServer); err != nil {
			log.Printf("⚠️  Warning: Failed to restart voting service: %v", err)
		}
	}
}

// Init initializes client, fetches config and establishes TLS connection
// If votingHandler is nil, uses the default auto-approve handler
func (c *Client) Init(votingHandler func(context.Context, *pb.VotingRequest) (*pb.VotingResponse, error)) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.frostTimeout)
	defer cancel()

	// 1. Fetch configuration
	nodeConfig, err := c.configClient.GetConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}
	c.nodeConfig = nodeConfig

	// 2. Create task client
	c.taskClient = task.NewClient(nodeConfig)

	// 3. Create TLS configuration for TEE server
	teeTLSConfig, err := utils.CreateTLSConfig(nodeConfig.Cert, nodeConfig.Key, nodeConfig.TargetCert)
	if err != nil {
		return fmt.Errorf("failed to create TEE TLS config: %w", err)
	}

	// 4. Connect to TEE server
	if err := c.taskClient.Connect(ctx, teeTLSConfig); err != nil {
		return fmt.Errorf("failed to connect to TEE server: %w", err)
	}

	// 5. Create user management client
	c.userMgmtClient = usermgmt.NewClient(nodeConfig.AppNodeAddr)

	// 6. Create TLS configuration for App node
	appTLSConfig, err := utils.CreateTLSConfig(nodeConfig.Cert, nodeConfig.Key, nodeConfig.AppNodeCert)
	if err != nil {
		return fmt.Errorf("failed to create App TLS config: %w", err)
	}

	// 7. Connect to user management system
	if err := c.userMgmtClient.Connect(ctx, appTLSConfig); err != nil {
		return fmt.Errorf("failed to connect to user management system: %w", err)
	}

	// 8. Set voting handler and auto-start voting service
	if votingHandler != nil {
		c.votingHandler = votingHandler
		log.Printf("🗳️  Using custom voting handler provided in Init()")
	} else {
		log.Printf("🗳️  Using default auto-approve voting handler")
	}

	if err := voting.StartVotingService(c.votingHandler, &c.votingServer); err != nil {
		log.Printf("⚠️  Warning: Failed to start voting service: %v", err)
		// Don't fail initialization if voting service fails to start
	} else {
		log.Printf("🗳️  Voting service auto-started during initialization")
	}

	log.Printf("✅ Client initialized successfully, node ID: %d", nodeConfig.NodeID)
	return nil
}

// SignWithAppID signs a message using a public key from user management system by app ID
func (c *Client) signWithAppID(message []byte, appID string) ([]byte, error) {
	if c.taskClient == nil {
		return nil, fmt.Errorf("client not initialized")
	}

	// Get public key from user management system
	ctx, cancel := context.WithTimeout(context.Background(), c.frostTimeout)
	defer cancel()

	publicKeyStr, protocolStr, curveStr, err := c.userMgmtClient.GetPublicKeyByAppID(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Parse protocol and curve strings to uint32
	protocol, err := utils.ParseProtocol(protocolStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse protocol: %w", err)
	}

	curve, err := utils.ParseCurve(curveStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse curve: %w", err)
	}

	// Decode the public key from hex (remove 0x prefix if present)
	publicKeyHex := publicKeyStr
	if strings.HasPrefix(publicKeyStr, "0x") || strings.HasPrefix(publicKeyStr, "0X") {
		publicKeyHex = publicKeyStr[2:]
	}
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key from hex: %w", err)
	}

	// Sign the message
	timeout := c.frostTimeout
	if protocol == constants.ProtocolECDSA {
		timeout = c.ecdsaTimeout
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), timeout)
	defer cancel2()

	return c.taskClient.Sign(ctx2, message, publicKey, protocol, curve)
}

// GetPublicKeyByAppID gets public key information for a specific app ID
func (c *Client) GetPublicKeyByAppID(appID string) (publicKey, protocol, curve string, err error) {
	if c.userMgmtClient == nil {
		return "", "", "", fmt.Errorf("client not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.frostTimeout)
	defer cancel()

	return c.userMgmtClient.GetPublicKeyByAppID(ctx, appID)
}

// votingSignWithHeaders performs voting with custom headers forwarded to remote targets
func (c *Client) votingSignWithHeaders(message []byte, signerAppID string, localApproval bool, voteRequestData []byte, headers map[string]string) (*SignResult, error) {
	// Parse isForwarded from the request data
	var requestMap map[string]interface{}
	isForwarded := false
	if json.Unmarshal(voteRequestData, &requestMap) == nil {
		isForwarded, _ = requestMap["is_forwarded"].(bool)
	}

	// Get deployment targets, voting sign path, and required votes from server
	deploymentTargets, votingSignPath, requiredVotes, err := c.userMgmtClient.GetDeploymentTargetsForVotingSign(signerAppID, c.frostTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to get voting sign configuration: %w", err)
	}

	// Extract target app IDs from deployment targets
	var targetAppIDs []string
	for appID := range deploymentTargets {
		targetAppIDs = append(targetAppIDs, appID)
	}

	// If this is a forwarded request, just return the local decision without further forwarding
	if isForwarded {
		log.Printf("🔄 Forwarded request - returning local decision: %t for app %s", localApproval, signerAppID)

		result := &SignResult{
			Success: localApproval,
			VotingInfo: &VotingInfo{
				TotalTargets:    1,
				SuccessfulVotes: 0,
				RequiredVotes:   int(requiredVotes),
				VoteDetails:     []VoteDetail{{ClientID: signerAppID, Success: true, Response: localApproval}},
			},
		}

		if localApproval {
			result.VotingInfo.SuccessfulVotes = 1
		} else {
			result.Error = "Vote rejected"
		}

		return result, nil
	}

	if len(targetAppIDs) == 0 {
		return nil, fmt.Errorf("no target app IDs configured for voting sign")
	}

	if requiredVotes <= 0 || requiredVotes > int32(len(targetAppIDs)) {
		return nil, fmt.Errorf("invalid required votes: %d (should be 1-%d)", requiredVotes, len(targetAppIDs))
	}

	log.Printf("🗳️  Starting HTTP voting process for %s", signerAppID)
	log.Printf("👥 Targets: %v, required votes: %d/%d", targetAppIDs, requiredVotes, len(targetAppIDs))

	// Initialize vote details and approval count
	var voteDetails []VoteDetail
	approvalCount := 0

	// Add local vote only if signerAppID is in targetAppIDs
	signerInTargets := false
	for _, targetAppID := range targetAppIDs {
		if targetAppID == signerAppID {
			signerInTargets = true
			break
		}
	}

	if signerInTargets {
		voteDetails = append(voteDetails, VoteDetail{ClientID: signerAppID, Success: true, Response: localApproval})
		if localApproval {
			approvalCount = 1
		}
	}

	// Batch get deployment targets for remote app IDs (excluding self)
	var remoteTargetAppIDs []string
	for _, targetAppID := range targetAppIDs {
		if targetAppID != signerAppID {
			remoteTargetAppIDs = append(remoteTargetAppIDs, targetAppID)
		}
	}

	// If there are remote targets, send voting requests
	if len(remoteTargetAppIDs) > 0 {
		log.Printf("🔍 Using deployment targets for remote apps: %v", remoteTargetAppIDs)
		log.Printf("📝 VotingSign path: %s", votingSignPath)
		log.Printf("✅ Found %d deployment targets: %v", len(deploymentTargets), func() []string {
			var keys []string
			for k := range deploymentTargets {
				keys = append(keys, k)
			}
			return keys
		}())

		// Send HTTP voting requests to remote targets concurrently
		type voteResult struct {
			appID    string
			approved bool
			err      error
		}

		resultChan := make(chan voteResult, len(remoteTargetAppIDs))
		activeRequests := 0

		// Start concurrent HTTP voting requests
		for _, targetAppID := range remoteTargetAppIDs {
			target, exists := deploymentTargets[targetAppID]
			if !exists {
				log.Printf("❌ No deployment target found for %s, skipping", targetAppID)
				continue
			}

			activeRequests++
			go func(appID string, deployTarget *usermgmt.DeploymentTarget) {
				// Modify request body to mark as forwarded
				modifiedRequestData, err := voting.MarkRequestAsForwarded(voteRequestData)
				if err != nil {
					resultChan <- voteResult{appID: appID, approved: false, err: fmt.Errorf("failed to modify request: %w", err)}
					return
				}
				approved, err := voting.SendHTTPVoteRequestWithHeaders(deployTarget, modifiedRequestData, headers, c.frostTimeout)
				resultChan <- voteResult{appID: appID, approved: approved, err: err}
			}(targetAppID, target)
		}

		// Collect remote voting results
		for i := 0; i < activeRequests; i++ {
			result := <-resultChan

			voteDetail := VoteDetail{
				ClientID: result.appID,
				Success:  result.err == nil,
				Response: result.approved,
			}

			if result.err != nil {
				voteDetail.Error = result.err.Error()
				log.Printf("❌ Failed to get vote from %s: %v", result.appID, result.err)
			} else if result.approved {
				approvalCount++
				log.Printf("✅ Vote approved by %s (%d/%d)", result.appID, approvalCount, int(requiredVotes))
			} else {
				log.Printf("❌ Vote rejected by %s", result.appID)
			}

			voteDetails = append(voteDetails, voteDetail)
		}
	}

	// Create voting result
	signResult := &SignResult{
		VotingInfo: &VotingInfo{
			TotalTargets:    len(targetAppIDs),
			SuccessfulVotes: approvalCount,
			RequiredVotes:   int(requiredVotes),
			VoteDetails:     voteDetails,
		},
	}

	// Check if voting passed
	if approvalCount < int(requiredVotes) {
		signResult.Success = false
		signResult.Error = fmt.Sprintf("Voting failed: only %d/%d approvals received", approvalCount, int(requiredVotes))
		log.Printf("❌ %s", signResult.Error)
		return signResult, nil
	}

	// Generate signature
	log.Printf("🔐 Generating signature for approved message (%d/%d votes received)", approvalCount, int(requiredVotes))
	signature, err := c.signWithAppID(message, signerAppID)
	if err != nil {
		signResult.Success = false
		signResult.Error = fmt.Sprintf("Failed to generate signature: %v", err)
		return signResult, fmt.Errorf("failed to generate signature: %w", err)
	}

	signResult.Success = true
	signResult.Signature = signature

	log.Printf("✅ Voting and signing completed successfully")
	return signResult, nil
}

// Sign performs signing with optional voting based on SignRequest configuration
func (c *Client) Sign(req *SignRequest) (*SignResult, error) {
	if req == nil {
		return nil, fmt.Errorf("sign request cannot be nil")
	}

	// Validate required fields
	if req.AppID == "" {
		return nil, fmt.Errorf("app ID is required")
	}

	// If voting is not enabled, perform direct signing
	if !req.EnableVoting {
		signature, err := c.signWithAppID(req.Message, req.AppID)
		if err != nil {
			return &SignResult{
				Success: false,
				Error:   err.Error(),
			}, err
		}
		return &SignResult{
			Signature: signature,
			Success:   true,
		}, nil
	}

	// Process HTTP request if provided
	var headers map[string]string
	var voteRequestData []byte

	if req.HTTPRequest != nil {
		headers = voting.ExtractHeadersFromRequest(req.HTTPRequest)
		if req.HTTPRequest.Body != nil {
			var err error
			voteRequestData, err = io.ReadAll(req.HTTPRequest.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read request body: %w", err)
			}
		}
	} else {
		// Use provided data if no HTTP request
		headers = req.Headers
		voteRequestData = req.VoteRequestData
	}

	// Perform voting and signing
	return c.votingSignWithHeaders(req.Message, req.AppID, req.LocalApproval, voteRequestData, headers)
}

// Verify verifies a signature against a message using the public key associated with the given app ID
func (c *Client) Verify(message, signature []byte, appID string) (bool, error) {
	if c.userMgmtClient == nil {
		return false, fmt.Errorf("client not initialized")
	}

	// Get public key from user management system
	ctx, cancel := context.WithTimeout(context.Background(), c.frostTimeout)
	defer cancel()

	publicKeyStr, protocolStr, curveStr, err := c.userMgmtClient.GetPublicKeyByAppID(ctx, appID)
	if err != nil {
		return false, fmt.Errorf("failed to get public key: %w", err)
	}

	// Parse protocol and curve strings to uint32
	protocol, err := utils.ParseProtocol(protocolStr)
	if err != nil {
		return false, fmt.Errorf("failed to parse protocol: %w", err)
	}

	curve, err := utils.ParseCurve(curveStr)
	if err != nil {
		return false, fmt.Errorf("failed to parse curve: %w", err)
	}

	// Decode the public key from hex (remove 0x prefix if present)
	publicKeyHex := publicKeyStr
	if strings.HasPrefix(publicKeyStr, "0x") || strings.HasPrefix(publicKeyStr, "0X") {
		publicKeyHex = publicKeyStr[2:]
	}
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key from hex: %w", err)
	}

	// Verify the signature using the verification package
	return verification.VerifySignature(message, publicKey, signature, protocol, curve)
}

// Close closes client connections
func (c *Client) Close() error {
	var errs []error

	// Stop voting service gracefully
	if c.votingServer != nil {
		log.Printf("🛑 Stopping voting service...")
		c.votingServer.GracefulStop()
		c.votingServer = nil
	}

	if c.taskClient != nil {
		if err := c.taskClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if c.userMgmtClient != nil {
		if err := c.userMgmtClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing clients: %v", errs)
	}

	return nil
}
