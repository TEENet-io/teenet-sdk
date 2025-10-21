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

package task

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/TEENet-io/teenet-sdk/go/pkg/config"
	"github.com/TEENet-io/teenet-sdk/go/pkg/constants"
	pb "github.com/TEENet-io/teenet-sdk/go/proto/key_management"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

const (
	TypeSign uint32 = 3 // Signing
)

// Client executes tasks (with TLS and gRPC built-in retry)
type Client struct {
	config           *config.NodeConfig
	conn             *grpc.ClientConn
	client           pb.UserTaskClient
	currentNodeIndex int         // Current TEE node index for failover
	tlsConfig        *tls.Config // Stored TLS config for failover
}

// NewClient creates a new task client
func NewClient(nodeConfig *config.NodeConfig) *Client {
	return &Client{
		config: nodeConfig,
	}
}

// Connect connects to TEE server using primary node
func (c *Client) Connect(ctx context.Context, tlsConfig *tls.Config) error {
	c.tlsConfig = tlsConfig // Store for failover
	return c.connectToNode(ctx, tlsConfig, 0)
}

// connectToNode connects to a specific TEE node by index
func (c *Client) connectToNode(ctx context.Context, tlsConfig *tls.Config, nodeIndex int) error {
	if c.conn != nil {
		c.conn.Close()
	}

	// Determine which node to connect to
	var targetAddr string
	if nodeIndex < len(c.config.TeeNodes) {
		targetAddr = c.config.TeeNodes[nodeIndex].RPCAddress
		c.currentNodeIndex = nodeIndex
	} else {
		// Fallback to primary address if index out of range
		targetAddr = c.config.RPCAddress
		c.currentNodeIndex = 0
	}

	// gRPC connection options with TLS and retry configuration
	creds := credentials.NewTLS(tlsConfig)

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultServiceConfig(constants.GRPCRetryPolicy),
	}

	conn, err := grpc.NewClient(targetAddr, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to TEE server %s: %w", targetAddr, err)
	}

	c.conn = conn
	c.client = pb.NewUserTaskClient(conn)
	return nil
}

// tryFailover attempts to connect to the next available TEE node
func (c *Client) tryFailover(ctx context.Context, tlsConfig *tls.Config) error {
	totalNodes := len(c.config.TeeNodes)
	if totalNodes <= 1 {
		return fmt.Errorf("no alternative TEE nodes available for failover")
	}

	// Try next nodes in order
	for i := 1; i < totalNodes; i++ {
		nextIndex := (c.currentNodeIndex + i) % totalNodes
		if err := c.connectToNode(ctx, tlsConfig, nextIndex); err == nil {
			fmt.Printf("Failover successful: switched to TEE node %d (%s)\n",
				nextIndex, c.config.TeeNodes[nextIndex].RPCAddress)
			return nil
		}
	}

	return fmt.Errorf("failover failed: all TEE nodes unreachable")
}

// Close closes the connection
func (c *Client) Close() error {
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.client = nil
		return err
	}
	return nil
}

// Sign executes signing operation with retry and failover support
func (c *Client) Sign(ctx context.Context, message, publicKey []byte, protocol, curve uint32) ([]byte, error) {
	if len(message) == 0 || len(publicKey) == 0 {
		return nil, fmt.Errorf("message and public key cannot be empty")
	}

	if c.client == nil {
		return nil, fmt.Errorf("not connected to server")
	}

	// Retry up to 3 times for timeout errors
	maxRetries := 3
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err := c.client.Sign(ctx, &pb.SignRequest{
			From:          c.config.NodeID,
			PublicKeyInfo: publicKey,
			Msg:           message,
			Protocol:      protocol,
			Curve:         curve,
		})
		if err != nil {
			// Check if it's a gRPC error
			if st, ok := status.FromError(err); ok {
				// For connection errors, try failover on first attempt
				if (st.Code() == codes.Unavailable || st.Code() == codes.DeadlineExceeded) && attempt == 0 {
					if c.tlsConfig != nil && len(c.config.TeeNodes) > 1 {
						fmt.Printf("⚠️  TEE node unreachable, attempting failover...\n")
						if failoverErr := c.tryFailover(ctx, c.tlsConfig); failoverErr == nil {
							// Retry with new connection
							continue
						} else {
							fmt.Printf("❌ Failover failed: %v\n", failoverErr)
						}
					}
				}

				// Retry on DeadlineExceeded errors
				if st.Code() == codes.DeadlineExceeded && attempt < maxRetries-1 {
					lastErr = fmt.Errorf("gRPC call failed [%s] (attempt %d/%d): %w", st.Code(), attempt+1, maxRetries, err)
					// Small delay before retry (100ms, 200ms, 300ms)
					time.Sleep(time.Millisecond * 100 * time.Duration(attempt+1))
					continue
				}
				return nil, fmt.Errorf("gRPC call failed [%s]: %w", st.Code(), err)
			}
			return nil, fmt.Errorf("signing failed: %w", err)
		}

		if !resp.Success {
			return nil, fmt.Errorf("signing failed: %s", resp.Error)
		}

		return resp.GetSignature(), nil
	}

	// All retries failed
	return nil, lastErr
}
