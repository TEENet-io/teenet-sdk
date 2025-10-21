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

// Package usermgmt provides gRPC client for user management system integration
package usermgmt

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/TEENet-io/teenet-sdk/go/pkg/constants"
	"github.com/TEENet-io/teenet-sdk/go/proto/appid"
)

// Client handles gRPC communication with the user management system
type Client struct {
	conn       *grpc.ClientConn
	client     appid.AppIDServiceClient
	serverAddr string
}

// DeploymentTarget contains deployment information for voting requests
type DeploymentTarget struct {
	AppID                   string
	ContainerIP             string
	DeploymentClientAddress string
	VotingSignPath          string // HTTP API path for VotingSign requests
	HTTPBaseURL             string // HTTP base URL for API forwarding
	ServicePort             int32  // Container service port
}

// NewClient creates a new user management gRPC client
func NewClient(serverAddr string) *Client {
	return &Client{
		serverAddr: serverAddr,
	}
}

// Connect establishes gRPC connection to user management service
func (c *Client) Connect(ctx context.Context, tlsConfig *tls.Config) error {
	// gRPC connection options with TLS and retry configuration
	if c.conn != nil {
		c.conn.Close()
	}

	// gRPC connection options with TLS and retry configuration
	creds := credentials.NewTLS(tlsConfig)

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultServiceConfig(constants.GRPCRetryPolicy),
	}

	conn, err := grpc.NewClient(c.serverAddr, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to user management service: %w", err)
	}

	c.conn = conn
	c.client = appid.NewAppIDServiceClient(conn)
	return nil
}

// Close closes the gRPC connection
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// GetPublicKeyByAppID retrieves public key by app ID via gRPC
func (c *Client) GetPublicKeyByAppID(ctx context.Context, appID string) (string, string, string, error) {
	if c.client == nil {
		return "", "", "", fmt.Errorf("client not connected")
	}

	req := &appid.GetPublicKeyByAppIDRequest{
		AppId: appID,
	}

	resp, err := c.client.GetPublicKeyByAppID(ctx, req)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get public key: %w", err)
	}

	return resp.Publickey, resp.Protocol, resp.Curve, nil
}

// GetDeploymentAddresses retrieves deployment addresses for given app ID via gRPC
func (c *Client) GetDeploymentAddresses(ctx context.Context, appID string) (*appid.GetDeploymentAddressesResponse, error) {
	if c.client == nil {
		return nil, fmt.Errorf("client not connected")
	}

	req := &appid.GetDeploymentAddressesRequest{
		AppId: appID,
	}

	resp, err := c.client.GetDeploymentAddresses(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get deployment addresses: %w", err)
	}

	return resp, nil
}

// GetDeploymentTargetsForVotingSign gets deployment targets for voting sign based on a single app ID
// It returns all target app IDs configured for the voting sign project
func (c *Client) GetDeploymentTargetsForVotingSign(appID string, timeout time.Duration) (map[string]*DeploymentTarget, string, int32, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resp, err := c.GetDeploymentAddresses(ctx, appID)
	if err != nil {
		return nil, "", 0, false, fmt.Errorf("failed to get deployment info: %w", err)
	}

	deployments := resp.Deployments
	notFound := resp.NotFound
	votingSignPath := resp.VotingSignPath
	requiredVotes := resp.RequiredVotes
	enableVotingSign := resp.EnableVotingSign

	result := make(map[string]*DeploymentTarget)

	// Process successful deployments
	for appID, deployment := range deployments {
		if deployment.ContainerIp == "" || deployment.DeploymentClientAddress == "" {
			log.Printf("⚠️  App ID %s missing container IP or deployment client address", appID)
			continue
		}
		result[appID] = &DeploymentTarget{
			AppID:                   appID,
			ContainerIP:             deployment.ContainerIp,
			DeploymentClientAddress: deployment.DeploymentClientAddress,
			VotingSignPath:          votingSignPath, // Use shared voting sign path
			HTTPBaseURL:             deployment.DeploymentHost, // Use deployment host as HTTP base URL
			ServicePort:             deployment.ServicePort, // Container service port
		}
	}

	// Log not found app IDs
	if len(notFound) > 0 {
		log.Printf("⚠️  App IDs not found or not deployed: %v", notFound)
	}

	return result, votingSignPath, requiredVotes, enableVotingSign, nil
}
