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

package config

import (
	"context"
	"fmt"
	"time"

	"github.com/TEENet-io/teenet-sdk/go/pkg/constants"
	nmpb "github.com/TEENet-io/teenet-sdk/go/proto/node_management"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Type defines node types
const (
	TypeInvalidNode uint32 = 0
	TypeTeeNode     uint32 = 1
	TypeMeshNode    uint32 = 2
	TypeAppNode     uint32 = 3
)

// TeeNodeInfo holds information about a single TEE node
type TeeNodeInfo struct {
	RPCAddress string `json:"rpc_address"`
	Cert       []byte `json:"cert"`
}

// NodeConfig holds node configuration information
type NodeConfig struct {
	NodeID      uint32        `json:"node_id"`
	RPCAddress  string        `json:"rpc_address"` // Primary TEE node address (for backward compatibility)
	Cert        []byte        `json:"cert"`
	Key         []byte        `json:"key"`
	TargetCert  []byte        `json:"target_cert"`  // Primary TEE node cert (for backward compatibility)
	TeeNodes    []TeeNodeInfo `json:"tee_nodes"`    // All available TEE nodes for failover
	AppNodeAddr string        `json:"app_node_addr"`
	AppNodeCert []byte        `json:"app_node_cert"`
}

// Client pulls configuration from server (without TLS)
type Client struct {
	serverAddress string
	timeout       time.Duration
}

// NewClient creates a new configuration client
func NewClient(serverAddress string) *Client {
	return &Client{
		serverAddress: serverAddress,
		timeout:       constants.DefaultConfigTimeout,
	}
}

// GetConfig retrieves node configuration from server
func (c *Client) GetConfig(parentCtx context.Context) (*NodeConfig, error) {
	// Use the parent context but add our own timeout
	ctx, cancel := context.WithTimeout(parentCtx, c.timeout)
	defer cancel()
	return c.fetchFromServer(ctx)
}

// fetchFromServer retrieves configuration from management server
func (c *Client) fetchFromServer(ctx context.Context) (*NodeConfig, error) {
	// Connect to config server (without TLS)
	conn, err := grpc.NewClient(c.serverAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to config server: %w", err)
	}
	defer conn.Close()

	client := nmpb.NewCLIRPCServiceClient(conn)

	// Get node information
	nodeInfo, err := client.GetNodeInfo(ctx, &nmpb.GetNodeInfoRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get node info: %w", err)
	}

	// Get peer nodes
	peers, err := client.GetPeerNode(ctx, &nmpb.GetPeerNodeRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get peer nodes: %w", err)
	}

	// Find all TEE nodes and App node
	var teeNodes []*nmpb.Peer
	var appNode *nmpb.Peer
	for _, peer := range peers.Peers {
		if peer.Type == TypeAppNode {
			appNode = peer
		} else if peer.Type == TypeTeeNode {
			teeNodes = append(teeNodes, peer)
		}
	}

	if len(teeNodes) == 0 && appNode == nil {
		return nil, fmt.Errorf("no TEE or App node found")
	}

	if len(teeNodes) == 0 {
		return nil, fmt.Errorf("no TEE node found")
	}

	// Build TEE node list
	teeNodeInfos := make([]TeeNodeInfo, 0, len(teeNodes))
	for _, node := range teeNodes {
		teeNodeInfos = append(teeNodeInfos, TeeNodeInfo{
			RPCAddress: node.RpcAddress,
			Cert:       node.Cert,
		})
	}

	// Use first TEE node as primary (for backward compatibility)
	primaryTeeNode := teeNodes[0]

	config := &NodeConfig{
		NodeID:      nodeInfo.NodeId,
		Cert:        nodeInfo.Cert,
		Key:         nodeInfo.Key,
		TargetCert:  primaryTeeNode.Cert,
		RPCAddress:  primaryTeeNode.RpcAddress,
		TeeNodes:    teeNodeInfos,
		AppNodeAddr: appNode.RpcAddress,
		AppNodeCert: appNode.Cert,
	}

	fmt.Printf("Retrieved config from server, node ID: %d, TEE nodes: %d\n", config.NodeID, len(teeNodeInfos))
	return config, nil
}

// SetTimeout sets the timeout for config operations
func (c *Client) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}
