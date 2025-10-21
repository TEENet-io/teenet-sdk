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
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TEENet-io/teenet-sdk/go/pkg/config"
	"github.com/TEENet-io/teenet-sdk/go/pkg/constants"
	"github.com/TEENet-io/teenet-sdk/go/pkg/task"
	"github.com/TEENet-io/teenet-sdk/go/pkg/usermgmt"
	"github.com/TEENet-io/teenet-sdk/go/pkg/utils"
	"github.com/TEENet-io/teenet-sdk/go/pkg/verification"
	"github.com/TEENet-io/teenet-sdk/go/pkg/voting"
)

// cachedPublicKey holds cached public key information with expiration
type cachedPublicKey struct {
	publicKey []byte
	protocol  uint32
	curve     uint32
	timestamp time.Time
}

// cachedDeployment holds cached deployment targets with expiration
type cachedDeployment struct {
	targets          map[string]*usermgmt.DeploymentTarget
	votingPath       string
	requiredVotes    int32
	enableVotingSign bool
	timestamp        time.Time
}

// ClientMetrics holds performance and usage metrics
type ClientMetrics struct {
	SignCount         atomic.Int64
	SignErrors        atomic.Int64
	VoteCount         atomic.Int64
	VoteErrors        atomic.Int64
	CacheHits         atomic.Int64
	CacheMisses       atomic.Int64
	FailoverCount     atomic.Int64
	TotalSignDuration atomic.Int64 // in nanoseconds
	TotalVoteDuration atomic.Int64 // in nanoseconds
}

// VoteDetail contains details of each vote
type VoteDetail struct {
	ClientID string `json:"client_id"`
	Success  bool   `json:"success"`
	Response bool   `json:"response"`
	Error    string `json:"error,omitempty"`
}

// SignOptions contains optional parameters for sign operations
type SignOptions struct {
	// Voting-specific fields (only used when voting is enabled for this App ID)
	LocalApproval bool          // Local approval status for voting
	HTTPRequest   *http.Request // Original HTTP request (for voting, headers and body will be extracted from this)
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

	// Default App ID (optional, can be set from environment variable)
	DefaultAppID string

	// Caching
	publicKeyCache  sync.Map // key: appID (string), value: *cachedPublicKey
	deploymentCache sync.Map // key: appID (string), value: *cachedDeployment
	cacheTTL        time.Duration
	cleanupTicker   *time.Ticker
	cleanupDone     chan struct{}

	// Metrics
	metrics ClientMetrics

	// Concurrency control
	maxConcurrentVotes int
}

// NewClient creates a new client instance with default settings
func NewClient() *Client {
	return NewClientWithOptions(nil)
}

// ClientOptions holds optional configuration for the client
type ClientOptions struct {
	CacheTTL           time.Duration // Cache TTL, default 5 minutes
	MaxConcurrentVotes int           // Max concurrent voting requests, default 10
	FrostTimeout       time.Duration // Frost protocol timeout, default from constants
	ECDSATimeout       time.Duration // ECDSA timeout, default 2x frost timeout
}

// NewClientWithOptions creates a new client instance with custom options
func NewClientWithOptions(opts *ClientOptions) *Client {
	// Set defaults
	cacheTTL := 5 * time.Minute
	maxConcurrentVotes := 10
	frostTimeout := constants.DefaultClientTimeout
	ecdsaTimeout := constants.DefaultClientTimeout * 2

	if opts != nil {
		if opts.CacheTTL > 0 {
			cacheTTL = opts.CacheTTL
		}
		if opts.MaxConcurrentVotes > 0 {
			maxConcurrentVotes = opts.MaxConcurrentVotes
		}
		if opts.FrostTimeout > 0 {
			frostTimeout = opts.FrostTimeout
		}
		if opts.ECDSATimeout > 0 {
			ecdsaTimeout = opts.ECDSATimeout
		}
	}
	configServerAddr := os.Getenv("TEE_CONFIG_ADDR")
	if configServerAddr == "" {
		configServerAddr = "localhost:50052"
	}

	client := &Client{
		configClient:       config.NewClient(configServerAddr),
		frostTimeout:       frostTimeout,
		ecdsaTimeout:       ecdsaTimeout,
		cacheTTL:           cacheTTL,
		maxConcurrentVotes: maxConcurrentVotes,
		cleanupDone:        make(chan struct{}),
	}

	// Start background cache cleanup
	client.startCacheCleanup()

	return client
}

// startCacheCleanup starts a background goroutine to clean expired cache entries
func (c *Client) startCacheCleanup() {
	c.cleanupTicker = time.NewTicker(c.cacheTTL)
	go func() {
		for {
			select {
			case <-c.cleanupTicker.C:
				c.cleanExpiredCache()
			case <-c.cleanupDone:
				return
			}
		}
	}()
}

// cleanExpiredCache removes expired entries from caches
func (c *Client) cleanExpiredCache() {
	now := time.Now()

	// Clean public key cache
	c.publicKeyCache.Range(func(key, value interface{}) bool {
		if cached, ok := value.(*cachedPublicKey); ok {
			if now.Sub(cached.timestamp) > c.cacheTTL {
				c.publicKeyCache.Delete(key)
			}
		}
		return true
	})

	// Clean deployment cache
	c.deploymentCache.Range(func(key, value interface{}) bool {
		if cached, ok := value.(*cachedDeployment); ok {
			if now.Sub(cached.timestamp) > c.cacheTTL {
				c.deploymentCache.Delete(key)
			}
		}
		return true
	})
}

// SetDefaultAppID sets the default App ID for signing operations
// This is useful when most signing operations use the same App ID
func (c *Client) SetDefaultAppID(appID string) {
	c.DefaultAppID = appID
	log.Printf("✅ Default App ID set to: %s", appID)
}

// SetDefaultAppIDFromEnv sets the default App ID from the environment variable APP_ID
// Returns error if the environment variable is not set
func (c *Client) SetDefaultAppIDFromEnv() error {
	appID := os.Getenv("APP_ID")
	if appID == "" {
		return fmt.Errorf("APP_ID environment variable is not set")
	}
	c.SetDefaultAppID(appID)
	return nil
}

// Init initializes client, fetches config and establishes TLS connection
func (c *Client) Init() error {
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

	// 8. Initialize default App ID from environment variable if set
	if appID := os.Getenv("APP_ID"); appID != "" {
		c.SetDefaultAppID(appID)
		log.Printf("🔑 Default App ID initialized from environment: %s", appID)
	}

	log.Printf("✅ Client initialized successfully, node ID: %d", nodeConfig.NodeID)
	return nil
}

// getPublicKeyInfo retrieves public key info with caching
func (c *Client) getPublicKeyInfo(appID string) (publicKey []byte, protocol, curve uint32, err error) {
	// Check cache first
	if cached, ok := c.publicKeyCache.Load(appID); ok {
		cachedKey := cached.(*cachedPublicKey)
		if time.Since(cachedKey.timestamp) < c.cacheTTL {
			c.metrics.CacheHits.Add(1)
			return cachedKey.publicKey, cachedKey.protocol, cachedKey.curve, nil
		}
		// Expired, remove from cache
		c.publicKeyCache.Delete(appID)
	}

	c.metrics.CacheMisses.Add(1)

	// Fetch from user management system
	ctx, cancel := context.WithTimeout(context.Background(), c.frostTimeout)
	defer cancel()

	publicKeyStr, protocolStr, curveStr, err := c.userMgmtClient.GetPublicKeyByAppID(ctx, appID)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to get public key: %w", err)
	}

	// Parse protocol and curve
	protocol, err = utils.ParseProtocol(protocolStr)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to parse protocol: %w", err)
	}

	curve, err = utils.ParseCurve(curveStr)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to parse curve: %w", err)
	}

	// Decode public key
	publicKeyHex := publicKeyStr
	if strings.HasPrefix(publicKeyStr, "0x") || strings.HasPrefix(publicKeyStr, "0X") {
		publicKeyHex = publicKeyStr[2:]
	}
	publicKey, err = hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to decode public key from hex: %w", err)
	}

	// Cache the result
	c.publicKeyCache.Store(appID, &cachedPublicKey{
		publicKey: publicKey,
		protocol:  protocol,
		curve:     curve,
		timestamp: time.Now(),
	})

	return publicKey, protocol, curve, nil
}

// signWithAppID signs a message using a public key from user management system by app ID
func (c *Client) signWithAppID(message []byte, appID string) ([]byte, error) {
	startTime := time.Now()
	defer func() {
		c.metrics.TotalSignDuration.Add(time.Since(startTime).Nanoseconds())
	}()

	if c.taskClient == nil {
		return nil, fmt.Errorf("client not initialized")
	}

	// Get public key info (with caching)
	publicKey, protocol, curve, err := c.getPublicKeyInfo(appID)
	if err != nil {
		c.metrics.SignErrors.Add(1)
		return nil, err
	}

	// Sign the message
	timeout := c.frostTimeout
	if protocol == constants.ProtocolECDSA {
		timeout = c.ecdsaTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	signature, err := c.taskClient.Sign(ctx, message, publicKey, protocol, curve)
	if err != nil {
		c.metrics.SignErrors.Add(1)

		// Check if error might be due to stale cache (e.g., public key changed)
		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "verification failed") {
			log.Printf("⚠️  Signing failed, possibly due to stale cache. Invalidating cache for app ID: %s", appID)
			c.InvalidatePublicKeyCache(appID)
		}

		return nil, err
	}

	c.metrics.SignCount.Add(1)
	return signature, nil
}

// GetPublicKey gets public key information using the client's default App ID
func (c *Client) GetPublicKey() (publicKey, protocol, curve string, err error) {
	if c.userMgmtClient == nil {
		return "", "", "", fmt.Errorf("client not initialized")
	}

	if c.DefaultAppID == "" {
		return "", "", "", fmt.Errorf("default App ID is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.frostTimeout)
	defer cancel()

	return c.userMgmtClient.GetPublicKeyByAppID(ctx, c.DefaultAppID)
}

// getDeploymentTargets retrieves deployment targets with caching
func (c *Client) getDeploymentTargets(signerAppID string) (map[string]*usermgmt.DeploymentTarget, string, int32, bool, error) {
	// Check cache first
	if cached, ok := c.deploymentCache.Load(signerAppID); ok {
		cachedDeploy := cached.(*cachedDeployment)
		if time.Since(cachedDeploy.timestamp) < c.cacheTTL {
			c.metrics.CacheHits.Add(1)
			return cachedDeploy.targets, cachedDeploy.votingPath, cachedDeploy.requiredVotes, cachedDeploy.enableVotingSign, nil
		}
		// Expired, remove from cache
		c.deploymentCache.Delete(signerAppID)
	}

	c.metrics.CacheMisses.Add(1)

	// Fetch from user management system
	deploymentTargets, votingSignPath, requiredVotes, enableVotingSign, err := c.userMgmtClient.GetDeploymentTargetsForVotingSign(signerAppID, c.frostTimeout)
	if err != nil {
		return nil, "", 0, false, fmt.Errorf("failed to get voting sign configuration: %w", err)
	}

	// Cache the result
	c.deploymentCache.Store(signerAppID, &cachedDeployment{
		targets:          deploymentTargets,
		votingPath:       votingSignPath,
		requiredVotes:    requiredVotes,
		enableVotingSign: enableVotingSign,
		timestamp:        time.Now(),
	})

	return deploymentTargets, votingSignPath, requiredVotes, enableVotingSign, nil
}

// votingSignWithHeaders performs voting with custom headers forwarded to remote targets
func (c *Client) votingSignWithHeaders(message []byte, signerAppID string, localApproval bool, voteRequestData []byte, headers map[string]string) (*SignResult, error) {
	startTime := time.Now()
	defer func() {
		c.metrics.TotalVoteDuration.Add(time.Since(startTime).Nanoseconds())
	}()

	// Parse isForwarded from the request data
	var requestMap map[string]interface{}
	isForwarded := false
	if json.Unmarshal(voteRequestData, &requestMap) == nil {
		isForwarded, _ = requestMap["is_forwarded"].(bool)
	}

	// Get deployment targets with caching
	deploymentTargets, votingSignPath, requiredVotes, _, err := c.getDeploymentTargets(signerAppID)
	if err != nil {
		c.metrics.VoteErrors.Add(1)
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

		// Use semaphore for concurrency control
		semaphore := make(chan struct{}, c.maxConcurrentVotes)

		// Start concurrent HTTP voting requests with concurrency control
		for _, targetAppID := range remoteTargetAppIDs {
			target, exists := deploymentTargets[targetAppID]
			if !exists {
				log.Printf("❌ No deployment target found for %s, skipping", targetAppID)
				continue
			}

			activeRequests++
			go func(appID string, deployTarget *usermgmt.DeploymentTarget) {
				// Acquire semaphore
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

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
		c.metrics.VoteErrors.Add(1)

		// If many votes failed to connect, deployment targets might have changed
		failedConnections := 0
		for _, detail := range voteDetails {
			if !detail.Success && strings.Contains(detail.Error, "connection") {
				failedConnections++
			}
		}
		if failedConnections > len(voteDetails)/2 {
			log.Printf("⚠️  Many connection failures detected. Invalidating deployment cache for: %s", signerAppID)
			c.InvalidateDeploymentCache(signerAppID)
		}

		return signResult, nil
	}

	// Generate signature
	log.Printf("🔐 Generating signature for approved message (%d/%d votes received)", approvalCount, int(requiredVotes))
	signature, err := c.signWithAppID(message, signerAppID)
	if err != nil {
		signResult.Success = false
		signResult.Error = fmt.Sprintf("Failed to generate signature: %v", err)
		c.metrics.VoteErrors.Add(1)
		return signResult, fmt.Errorf("failed to generate signature: %w", err)
	}

	signResult.Success = true
	signResult.Signature = signature

	log.Printf("✅ Voting and signing completed successfully")
	c.metrics.VoteCount.Add(1)
	return signResult, nil
}

// Sign performs signing with optional voting based on configuration
// Voting is enabled/disabled based on the deployment configuration for the App ID
// Uses the client's default App ID which must be set via Init() or SetDefaultAppID()
// opt is optional - omit it or pass nil to use default options (no voting data)
func (c *Client) Sign(message []byte, opt ...*SignOptions) (*SignResult, error) {
	// Use client's default App ID
	if c.DefaultAppID == "" {
		return nil, fmt.Errorf("default App ID is not set (must be set via environment variable APP_ID during Init or via SetDefaultAppID)")
	}
	appID := c.DefaultAppID

	// Use default options if not provided
	var options *SignOptions
	if len(opt) > 0 && opt[0] != nil {
		options = opt[0]
	} else {
		options = &SignOptions{}
	}

	// Check if voting is enabled for this App ID
	_, _, _, enableVotingSign, err := c.getDeploymentTargets(appID)
	if err != nil {
		// If we can't get deployment targets, it might mean voting is not configured
		// In this case, perform direct signing
		log.Printf("Could not get deployment targets for %s, performing direct signing: %v", appID, err)
		signature, err := c.signWithAppID(message, appID)
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

	// If voting is not enabled for this App ID, perform direct signing
	if !enableVotingSign {
		log.Printf("Voting is not enabled for App ID %s, performing direct signing", appID)
		signature, err := c.signWithAppID(message, appID)
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

	// Voting is enabled, process the voting request
	log.Printf("Voting is enabled for App ID %s, processing voting request", appID)

	// Process HTTP request if provided
	var headers map[string]string
	var voteRequestData []byte

	if options.HTTPRequest != nil {
		headers = voting.ExtractHeadersFromRequest(options.HTTPRequest)
		if options.HTTPRequest.Body != nil {
			var err error
			voteRequestData, err = io.ReadAll(options.HTTPRequest.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read request body: %w", err)
			}
		}
	}

	// Perform voting and signing with the resolved appID
	return c.votingSignWithHeaders(message, appID, options.LocalApproval, voteRequestData, headers)
}

// Verify verifies a signature against a message using the client's default App ID
func (c *Client) Verify(message, signature []byte) (bool, error) {
	if c.userMgmtClient == nil {
		return false, fmt.Errorf("client not initialized")
	}

	if c.DefaultAppID == "" {
		return false, fmt.Errorf("default App ID is not set")
	}

	// Get public key info (with caching)
	publicKey, protocol, curve, err := c.getPublicKeyInfo(c.DefaultAppID)
	if err != nil {
		return false, err
	}

	// Verify the signature using the verification package
	return verification.VerifySignature(message, publicKey, signature, protocol, curve)
}

// GetMetrics returns the current client metrics
func (c *Client) GetMetrics() *ClientMetrics {
	return &c.metrics
}

// ClearCache clears all cached data
func (c *Client) ClearCache() {
	c.publicKeyCache.Range(func(key, value interface{}) bool {
		c.publicKeyCache.Delete(key)
		return true
	})
	c.deploymentCache.Range(func(key, value interface{}) bool {
		c.deploymentCache.Delete(key)
		return true
	})
	log.Printf("🧹 Cache cleared")
}

// InvalidatePublicKeyCache invalidates public key cache for a specific app ID
func (c *Client) InvalidatePublicKeyCache(appID string) {
	c.publicKeyCache.Delete(appID)
	log.Printf("🔄 Public key cache invalidated for app ID: %s", appID)
}

// InvalidateDeploymentCache invalidates deployment cache for a specific app ID
func (c *Client) InvalidateDeploymentCache(appID string) {
	c.deploymentCache.Delete(appID)
	log.Printf("🔄 Deployment cache invalidated for app ID: %s", appID)
}

// RefreshPublicKey forces refresh of public key for a specific app ID
func (c *Client) RefreshPublicKey(appID string) error {
	c.InvalidatePublicKeyCache(appID)
	_, _, _, err := c.getPublicKeyInfo(appID)
	if err != nil {
		return fmt.Errorf("failed to refresh public key: %w", err)
	}
	log.Printf("✅ Public key refreshed for app ID: %s", appID)
	return nil
}

// RefreshDeploymentTargets forces refresh of deployment targets for a specific app ID
func (c *Client) RefreshDeploymentTargets(appID string) error {
	c.InvalidateDeploymentCache(appID)
	_, _, _, _, err := c.getDeploymentTargets(appID)
	if err != nil {
		return fmt.Errorf("failed to refresh deployment targets: %w", err)
	}
	log.Printf("✅ Deployment targets refreshed for app ID: %s", appID)
	return nil
}

// Close closes client connections and cleanup resources
func (c *Client) Close() error {
	var errs []error

	// Stop cache cleanup goroutine
	if c.cleanupTicker != nil {
		c.cleanupTicker.Stop()
		close(c.cleanupDone)
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

	// Clear caches
	c.ClearCache()

	if len(errs) > 0 {
		return fmt.Errorf("errors closing clients: %v", errs)
	}

	return nil
}
