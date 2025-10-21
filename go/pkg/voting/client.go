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

// Package voting provides voting service server implementations
package voting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/TEENet-io/teenet-sdk/go/pkg/usermgmt"
	pb "github.com/TEENet-io/teenet-sdk/go/proto/voting"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	httpClientOnce sync.Once
	httpClient     *http.Client
)

// getHTTPClient returns a shared HTTP client with connection pooling
func getHTTPClient() *http.Client {
	httpClientOnce.Do(func() {
		httpClient = &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}
	})
	return httpClient
}

// SendVotingRequestToDeployment sends a voting request to deployment-client which forwards to container
func SendVotingRequestToDeployment(target *usermgmt.DeploymentTarget, taskID string, message []byte, requiredVotes, totalParticipants int, timeout time.Duration) (bool, error) {
	// Connect to deployment-client's gRPC service
	conn, err := grpc.NewClient(target.DeploymentClientAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return false, fmt.Errorf("failed to connect to deployment-client %s: %w", target.DeploymentClientAddress, err)
	}
	defer conn.Close()

	grpcClient := pb.NewVotingServiceClient(conn)

	// Send voting request with container IP for deployment-client to forward
	request := &pb.VotingRequest{
		TaskId:            taskID,
		Message:           message,
		RequiredVotes:     uint32(requiredVotes),
		TotalParticipants: uint32(totalParticipants),
		AppId:             target.AppID,
		TargetContainerIp: target.ContainerIP,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	response, err := grpcClient.Voting(ctx, request)
	if err != nil {
		return false, fmt.Errorf("voting request failed: %w", err)
	}

	if !response.Success {
		return false, nil // Voting rejected
	}

	return true, nil // Voting approved
}

// MarkRequestAsForwarded modifies the request body to set is_forwarded=true
func MarkRequestAsForwarded(requestData []byte) ([]byte, error) {
	var requestMap map[string]interface{}
	if err := json.Unmarshal(requestData, &requestMap); err != nil {
		return nil, fmt.Errorf("failed to parse request JSON: %w", err)
	}

	requestMap["is_forwarded"] = true

	modifiedData, err := json.Marshal(requestMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal modified request: %w", err)
	}

	return modifiedData, nil
}

// SendHTTPVoteRequestWithHeaders sends a vote request to a target app via HTTP with custom headers
func SendHTTPVoteRequestWithHeaders(target *usermgmt.DeploymentTarget, requestData []byte, headers map[string]string, timeout time.Duration) (bool, error) {

	// Build endpoint URL - send to deployment-client on port 8090 for HTTP forwarding
	// Format: http://deployment-host:8090/proxy/{app_id}:{port}{voting_sign_path}
	votingSignPath := target.VotingSignPath
	if !strings.HasPrefix(votingSignPath, "/") {
		votingSignPath = "/" + votingSignPath
	}

	// Include port in proxy path
	var proxyPath string
	if target.ServicePort > 0 {
		proxyPath = fmt.Sprintf("/proxy/%s:%d%s", target.AppID, target.ServicePort, votingSignPath)
	} else {
		// Default to 8080 if no port specified
		proxyPath = fmt.Sprintf("/proxy/%s:8080%s", target.AppID, votingSignPath)
	}
	
	// Extract host from DeploymentClientAddress (format: host:port)
	deploymentHost := target.DeploymentClientAddress
	if colonIndex := strings.LastIndex(deploymentHost, ":"); colonIndex != -1 {
		deploymentHost = deploymentHost[:colonIndex] // Remove port, keep only host
	}
	
	endpoint := fmt.Sprintf("http://%s:8090%s", deploymentHost, proxyPath)

	// Create HTTP request with provided data
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(requestData))
	if err != nil {
		return false, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set default headers
	req.Header.Set("Content-Type", "application/json")

	// Forward custom headers if provided
	if headers != nil {
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}

	// Use shared HTTP client with timeout context
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req = req.WithContext(ctx)

	log.Printf("📤 Sending vote request to %s via deployment-client: %s", target.AppID, endpoint)
	resp, err := getHTTPClient().Do(req)
	if err != nil {
		return false, fmt.Errorf("HTTP vote request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("HTTP vote request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response - only check for approved field
	var response map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return false, fmt.Errorf("failed to parse vote response: %w", err)
	}

	approved, ok := response["approved"].(bool)
	if !ok {
		return false, fmt.Errorf("invalid response format: missing approved field")
	}

	log.Printf("📥 Received vote response from %s: approved=%t", target.AppID, approved)
	return approved, nil
}

// ExtractHeadersFromRequest extracts all headers from HTTP request for forwarding
func ExtractHeadersFromRequest(req *http.Request) map[string]string {
	headers := make(map[string]string)

	for name, values := range req.Header {
		if len(values) > 0 {
			headers[name] = values[0] // Take first value if multiple
		}
	}

	return headers
}
