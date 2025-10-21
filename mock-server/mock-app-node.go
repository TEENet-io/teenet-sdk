package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"

	pb "tee-dao-mock-server/proto"

	"github.com/btcsuite/btcd/btcec/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// MockAppNode implements the AppIDService
type MockAppNode struct {
	pb.UnimplementedAppIDServiceServer
	// Mock App ID to public key mapping
	appKeys map[string]*AppKeyInfo
}

// AppKeyInfo stores app key information
type AppKeyInfo struct {
	PublicKey   string
	Protocol    string
	Curve       string
	Description string
}

// NewMockAppNode creates a new mock app node
func NewMockAppNode() *MockAppNode {
	return &MockAppNode{
		appKeys: generateMockAppKeys(),
	}
}

// generateMockAppKeys generates real cryptographic keys for all apps
func generateMockAppKeys() map[string]*AppKeyInfo {
	keys := make(map[string]*AppKeyInfo)

	// Generate the same consistent keys as the DAO server
	ed25519Key := generateConsistentED25519Key()
	secp256k1Key := generateConsistentSECP256K1Key()
	secp256r1Key := generateConsistentSECP256R1Key()

	// Generate some example App IDs and corresponding public keys
	apps := []struct {
		appID       string
		protocol    string
		curve       string
		description string
	}{
		{"secure-messaging-app", "schnorr", "ed25519", "Secure Messaging Application - Schnorr/ED25519"},
		{"financial-trading-platform", "ecdsa", "secp256r1", "Financial Trading Platform - ECDSA/SECP256R1"},
		{"digital-identity-service", "schnorr", "secp256k1", "Digital Identity Service - Schnorr/SECP256K1"},
		{"ethereum-wallet-app", "ecdsa", "secp256k1", "Ethereum Wallet - ECDSA/SECP256K1"},
	}

	for _, app := range apps {
		var publicKeyB64 string

		switch app.curve {
		case "ed25519":
			publicKey := ed25519Key.Public().(ed25519.PublicKey)
			publicKeyB64 = hex.EncodeToString(publicKey)
		case "secp256k1":
			// For Ethereum wallet, use 64-byte uncompressed format (X + Y coordinates without prefix)
			if app.appID == "ethereum-wallet-app" {
				// Get uncompressed public key from btcec (65 bytes with 0x04 prefix)
				uncompressedPubKey := secp256k1Key.PubKey().SerializeUncompressed()
				// Remove the 0x04 prefix to get 64 bytes
				publicKeyBytes := uncompressedPubKey[1:]
				publicKeyB64 = hex.EncodeToString(publicKeyBytes)
			} else {
				// For other secp256k1 apps, use compressed format
				publicKeyBytes := secp256k1Key.PubKey().SerializeCompressed()
				publicKeyB64 = hex.EncodeToString(publicKeyBytes)
			}
		case "secp256r1":
			// Generate compressed public key for secp256r1 (P-256)
			publicKeyBytes := elliptic.MarshalCompressed(secp256r1Key.Curve, secp256r1Key.X, secp256r1Key.Y)
			publicKeyB64 = hex.EncodeToString(publicKeyBytes)
		default:
			// Fallback to random key for unknown curves
			keyBytes := make([]byte, 33)
			rand.Read(keyBytes)
			keyBytes[0] = 0x02 // Compressed public key prefix
			publicKeyB64 = hex.EncodeToString(keyBytes)
		}

		keys[app.appID] = &AppKeyInfo{
			PublicKey:   publicKeyB64,
			Protocol:    app.protocol,
			Curve:       app.curve,
			Description: app.description,
		}
	}

	return keys
}

// GetPublicKeyByAppID implements the AppID service method
func (s *MockAppNode) GetPublicKeyByAppID(ctx context.Context, req *pb.GetPublicKeyByAppIDRequest) (*pb.GetPublicKeyByAppIDResponse, error) {
	log.Printf("App node: GetPublicKeyByAppID called for app_id: %s", req.AppId)

	// Verify App ID
	if req.AppId == "" {
		log.Printf("App node: Empty app_id provided")
		return nil, fmt.Errorf("app_id is required")
	}

	// Look up App key information
	keyInfo, exists := s.appKeys[req.AppId]
	if !exists {
		log.Printf("App node: App ID not found: %s", req.AppId)
		return nil, fmt.Errorf("app_id not found: %s", req.AppId)
	}

	log.Printf("App node: Found key for app_id %s - protocol: %s, curve: %s",
		req.AppId, keyInfo.Protocol, keyInfo.Curve)

	return &pb.GetPublicKeyByAppIDResponse{
		Publickey: keyInfo.PublicKey,
		Protocol:  keyInfo.Protocol,
		Curve:     keyInfo.Curve,
	}, nil
}

// GetDeploymentAddresses implements the voting service method
func (s *MockAppNode) GetDeploymentAddresses(ctx context.Context, req *pb.GetDeploymentAddressesRequest) (*pb.GetDeploymentAddressesResponse, error) {
	log.Printf("App node: GetDeploymentAddresses called for app_id: %s", req.AppId)

	// Verify App ID
	if req.AppId == "" {
		log.Printf("App node: Empty app_id provided")
		return nil, fmt.Errorf("app_id is required")
	}

	// Check if the app exists
	_, exists := s.appKeys[req.AppId]
	if !exists {
		log.Printf("App node: App ID not found: %s", req.AppId)
		return &pb.GetDeploymentAddressesResponse{
			Deployments:       make(map[string]*pb.DeploymentInfo),
			NotFound:          []string{req.AppId},
			VotingSignPath:    "/api/v1/voting/sign",
			RequiredVotes:     0,
			EnableVotingSign:  false,
		}, nil
	}

	// Mock deployment info - return empty deployment with voting disabled
	// This simulates the app not being deployed for voting
	log.Printf("App node: App found but no deployments configured (voting disabled)")

	return &pb.GetDeploymentAddressesResponse{
		Deployments:       make(map[string]*pb.DeploymentInfo),
		NotFound:          []string{},
		VotingSignPath:    "/api/v1/voting/sign",
		RequiredVotes:     0,
		EnableVotingSign:  false,
	}, nil
}

// generateConsistentED25519Key generates a consistent ED25519 private key for testing
func generateConsistentED25519Key() ed25519.PrivateKey {
	// Use a deterministic seed for consistent key generation in testing
	seed := make([]byte, ed25519.SeedSize)
	seedString := "tee-dao-mock-server-ed25519-key"
	copy(seed, []byte(seedString))
	
	return ed25519.NewKeyFromSeed(seed)
}

// generateConsistentSECP256K1Key generates a consistent SECP256K1 private key for testing
func generateConsistentSECP256K1Key() *btcec.PrivateKey {
	// Use a deterministic seed for consistent key generation in testing
	seed := []byte("tee-dao-mock-server-secp256k1-key-12345678901234567890123456789012")
	privateKeyInt := new(big.Int).SetBytes(seed[:32])

	// Ensure the private key is valid for secp256k1 (less than curve order)
	curve := btcec.S256()
	for privateKeyInt.Cmp(curve.N) >= 0 {
		privateKeyInt.Sub(privateKeyInt, curve.N)
	}

	// Create secp256k1 private key using btcec library
	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyInt.Bytes())

	return privateKey
}

// generateConsistentSECP256R1Key generates a consistent SECP256R1 (P-256) private key for testing
func generateConsistentSECP256R1Key() *ecdsa.PrivateKey {
	// Use a deterministic seed for consistent key generation in testing
	seed := []byte("tee-dao-mock-server-secp256r1-key-12345678901234567890123456789012")
	privateKeyInt := new(big.Int).SetBytes(seed[:32])
	
	// Ensure the private key is valid for P-256 (less than curve order)
	curve := elliptic.P256()
	for privateKeyInt.Cmp(curve.Params().N) >= 0 {
		privateKeyInt.Sub(privateKeyInt, curve.Params().N)
	}
	
	privateKey := &ecdsa.PrivateKey{
		D: privateKeyInt,
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
	}
	
	// Generate the public key
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(privateKeyInt.Bytes())
	
	return privateKey
}

func main() {
	port := ":50053"
	if p := os.Getenv("APP_NODE_PORT"); p != "" {
		port = ":" + p
	}

	log.Printf("Starting Mock App Node (User Management System) on port %s", port)

	// Create listener
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// Load TLS certificates
	cert, err := tls.LoadX509KeyPair("certs/app-node.crt", "certs/app-node.key")
	if err != nil {
		log.Fatalf("Failed to load TLS credentials: %v", err)
	}

	// Configure TLS for self-signed certificates with client authentication
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert, // Require client certificate but don't verify against CA
	}

	// Create gRPC server with mutual TLS
	creds := credentials.NewTLS(tlsConfig)
	s := grpc.NewServer(grpc.Creds(creds))

	// Register service
	appNode := NewMockAppNode()
	pb.RegisterAppIDServiceServer(s, appNode)

	// Print available App ID list
	fmt.Printf("Mock App Node listening on %s (with mutual TLS)\n", port)
	fmt.Println("Available App IDs for testing:")
	for appID, keyInfo := range appNode.appKeys {
		fmt.Printf("  - %s (%s + %s) - %s\n", appID, keyInfo.Protocol, keyInfo.Curve, keyInfo.Description)
	}
	fmt.Println("")
	fmt.Println("💡 Usage Tips:")
	fmt.Println("   Copy any of the above App IDs to use in your client programs")
	fmt.Println("   Each App ID corresponds to different signature protocol and curve combinations")
	fmt.Println("")

	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
