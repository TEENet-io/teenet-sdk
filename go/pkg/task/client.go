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
	config *config.NodeConfig
	conn   *grpc.ClientConn
	client pb.UserTaskClient
}

// NewClient creates a new task client
func NewClient(nodeConfig *config.NodeConfig) *Client {
	return &Client{
		config: nodeConfig,
	}
}

// Connect connects to TEE server
func (c *Client) Connect(ctx context.Context, tlsConfig *tls.Config) error {
	if c.conn != nil {
		c.conn.Close()
	}

	// gRPC connection options with TLS and retry configuration
	creds := credentials.NewTLS(tlsConfig)

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultServiceConfig(constants.GRPCRetryPolicy),
	}

	conn, err := grpc.NewClient(c.config.RPCAddress, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to TEE server: %w", err)
	}

	c.conn = conn
	c.client = pb.NewUserTaskClient(conn)
	return nil
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

// Sign executes signing operation with retry for timeout errors
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
