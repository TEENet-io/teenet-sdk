package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	pb "tee-dao-mock-server/proto"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	// Protocol constants
	ProtocolECDSA   uint32 = 1
	ProtocolSchnorr uint32 = 2

	// Curve constants
	CurveED25519   uint32 = 1
	CurveSECP256K1 uint32 = 2
	CurveSECP256R1 uint32 = 3
)

// MockDAOServer implements the UserTask service
type MockDAOServer struct {
	pb.UnimplementedUserTaskServer
	config        *Config
	ed25519Key    ed25519.PrivateKey   // ED25519 private key
	secp256k1Key  *btcec.PrivateKey    // SECP256K1 private key (real secp256k1)
	secp256r1Key  *ecdsa.PrivateKey    // SECP256R1 (P-256) private key
}

// Config holds server configuration
type Config struct {
	Port          string
	CertFile      string
	KeyFile       string
	CACertFile    string
	SigningDelay  time.Duration
	FailureRate   float32 // 0.0 to 1.0, probability of simulating failures
	EnableLogging bool
}

// NewMockDAOServer creates a new mock DAO server
func NewMockDAOServer(config *Config) *MockDAOServer {
	// Generate consistent private keys for testing
	// This ensures the same signatures for the same messages
	ed25519Key := generateConsistentED25519Key()
	secp256k1Key := generateConsistentSECP256K1Key()
	secp256r1Key := generateConsistentSECP256R1Key()
	
	return &MockDAOServer{
		config:       config,
		ed25519Key:   ed25519Key,
		secp256k1Key: secp256k1Key,
		secp256r1Key: secp256r1Key,
	}
}

// Sign implements the Sign RPC method
func (s *MockDAOServer) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	if s.config.EnableLogging {
		log.Printf("Received signing request from node %d", req.From)
		log.Printf("Message length: %d bytes", len(req.Msg))
		log.Printf("Public key length: %d bytes", len(req.PublicKeyInfo))
		log.Printf("Protocol: %d, Curve: %d", req.Protocol, req.Curve)
	}

	// Validate input
	if len(req.Msg) == 0 {
		return &pb.SignResponse{
			Success: false,
			Error:   "Message cannot be empty",
		}, nil
	}

	if len(req.PublicKeyInfo) == 0 {
		return &pb.SignResponse{
			Success: false,
			Error:   "Public key cannot be empty",
		}, nil
	}

	// Validate protocol and curve
	if !isValidProtocol(req.Protocol) {
		return &pb.SignResponse{
			Success: false,
			Error:   fmt.Sprintf("Unsupported protocol: %d", req.Protocol),
		}, nil
	}

	if !isValidCurve(req.Curve) {
		return &pb.SignResponse{
			Success: false,
			Error:   fmt.Sprintf("Unsupported curve: %d", req.Curve),
		}, nil
	}

	// Simulate signing delay
	if s.config.SigningDelay > 0 {
		time.Sleep(s.config.SigningDelay)
	}

	// Simulate random failures if configured
	if s.config.FailureRate > 0 {
		if randomFloat() < s.config.FailureRate {
			return &pb.SignResponse{
				Success: false,
				Error:   "Simulated signing failure",
			}, nil
		}
	}

	// Generate mock signature based on protocol and curve
	signature, err := s.generateMockSignature(req.Protocol, req.Curve, req.Msg)
	if err != nil {
		return &pb.SignResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to generate signature: %v", err),
		}, nil
	}

	if s.config.EnableLogging {
		log.Printf("Generated signature: %s", hex.EncodeToString(signature))
	}

	return &pb.SignResponse{
		Signature: signature,
		Success:   true,
	}, nil
}

// generateMockSignature generates real cryptographic signatures for all supported algorithms
func (s *MockDAOServer) generateMockSignature(protocol, curve uint32, message []byte) ([]byte, error) {
	switch protocol {
	case ProtocolSchnorr:
		switch curve {
		case CurveED25519:
			// Use proper ED25519 signing for Schnorr on ED25519
			signature := ed25519.Sign(s.ed25519Key, message)
			return signature, nil
		case CurveSECP256K1:
			// For SECP256K1 Schnorr, use SHA256 and proper BIP-340 Schnorr
			hash := sha256.Sum256(message)

			// Sign using BIP-340 Schnorr signature
			sig, err := schnorr.Sign(s.secp256k1Key, hash[:])
			if err != nil {
				return nil, fmt.Errorf("SECP256K1 Schnorr signing failed: %v", err)
			}

			// Return the serialized Schnorr signature (64 bytes)
			return sig.Serialize(), nil
		default:
			return nil, fmt.Errorf("unsupported curve for Schnorr: %d", curve)
		}
	case ProtocolECDSA:
		switch curve {
		case CurveED25519:
			// ED25519 doesn't use ECDSA, return error for invalid combination
			return nil, fmt.Errorf("ECDSA not supported with ED25519 curve")
		case CurveSECP256K1:
			// Use Keccak-256 for Ethereum-compatible signatures (65 bytes)
			hasher := sha3.NewLegacyKeccak256()
			hasher.Write(message)
			messageHash := hasher.Sum(nil)

			// Sign using btcec
			sig := btcecdsa.Sign(s.secp256k1Key, messageHash)

			// Ethereum-style signature: 65 bytes (R + S + V)
			signature := make([]byte, 65)

			// Extract R and S as 32-byte values
			rScalar := sig.R()
			sScalar := sig.S()
			rScalar.PutBytesUnchecked(signature[:32])
			sScalar.PutBytesUnchecked(signature[32:64])

			// Calculate recovery ID (V) for Ethereum compatibility
			// This allows recovering the public key from signature
			recoveryID := calculateRecoveryID(s.secp256k1Key.PubKey())
			signature[64] = byte(recoveryID)

			return signature, nil
		case CurveSECP256R1:
			hash := sha256.Sum256(message)
			r, s_sig, err := ecdsa.Sign(rand.Reader, s.secp256r1Key, hash[:])
			if err != nil {
				return nil, fmt.Errorf("SECP256R1 ECDSA signing failed: %v", err)
			}
			// Convert to 64-byte signature format (32 bytes r + 32 bytes s)
			signature := make([]byte, 64)
			r.FillBytes(signature[:32])
			s_sig.FillBytes(signature[32:])
			return signature, nil
		default:
			return nil, fmt.Errorf("unsupported curve for ECDSA: %d", curve)
		}
	default:
		return nil, fmt.Errorf("unsupported protocol: %d", protocol)
	}
}

// generateMockSignatureBytes generates deterministic mock signature bytes
func (s *MockDAOServer) generateMockSignatureBytes(length int, message []byte) []byte {
	// Generate deterministic bytes based on message for consistent testing
	signature := make([]byte, length)
	messageHash := simpleHash(message)
	
	// Fill signature with deterministic pattern
	for i := 0; i < length; i++ {
		signature[i] = messageHash[i%len(messageHash)] ^ byte(i)
	}
	
	return signature
}

// calculateRecoveryID calculates the recovery ID for ECDSA signature
// This allows recovering the public key from the signature
func calculateRecoveryID(pubKey *btcec.PublicKey) int {
	// Recovery ID is based on Y coordinate parity for secp256k1
	// 0 if Y is even, 1 if Y is odd
	pubKeyBytes := pubKey.SerializeUncompressed()

	// Extract Y coordinate (last 32 bytes of 65-byte uncompressed format)
	// pubKeyBytes[0] = 0x04, pubKeyBytes[1:33] = X, pubKeyBytes[33:65] = Y
	if len(pubKeyBytes) == 65 {
		yByte := pubKeyBytes[64] // Last byte of Y coordinate
		if yByte%2 == 0 {
			return 0 // Y is even
		}
		return 1 // Y is odd
	}

	return 0 // Default to 0
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

// simpleHash creates a simple hash of the message for deterministic signatures
func simpleHash(data []byte) []byte {
	hash := make([]byte, 8)
	for i, b := range data {
		hash[i%8] ^= b
	}
	return hash
}

// isValidProtocol checks if the protocol is supported
func isValidProtocol(protocol uint32) bool {
	return protocol == ProtocolECDSA || protocol == ProtocolSchnorr
}

// isValidCurve checks if the curve is supported
func isValidCurve(curve uint32) bool {
	return curve == CurveED25519 || curve == CurveSECP256K1 || 
		   curve == CurveSECP256R1
}

// randomFloat generates a random float between 0 and 1
func randomFloat() float32 {
	bytes := make([]byte, 4)
	rand.Read(bytes)
	// Convert to float32 between 0 and 1
	return float32(uint32(bytes[0])<<24|uint32(bytes[1])<<16|uint32(bytes[2])<<8|uint32(bytes[3])) / float32(^uint32(0))
}

// loadTLSCredentials loads TLS credentials for the server
func loadTLSCredentials(config *Config) (credentials.TransportCredentials, error) {
	// Load server certificate
	serverCert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	// Configure TLS for self-signed certificates with client authentication
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert, // Require client certificate but don't verify against CA
	}

	return credentials.NewTLS(tlsConfig), nil
}

func main() {
	// Default configuration
	config := &Config{
		Port:          ":50051",
		CertFile:      "certs/dao-server.crt",
		KeyFile:       "certs/dao-server.key", 
		CACertFile:    "", // No CA cert for self-signed certificates
		SigningDelay:  100 * time.Millisecond,
		FailureRate:   0.0,
		EnableLogging: true,
	}

	// Override from environment variables
	if port := os.Getenv("MOCK_DAO_PORT"); port != "" {
		config.Port = ":" + port
	}
	if certFile := os.Getenv("MOCK_DAO_CERT"); certFile != "" {
		config.CertFile = certFile
	}
	if keyFile := os.Getenv("MOCK_DAO_KEY"); keyFile != "" {
		config.KeyFile = keyFile
	}
	if caCert := os.Getenv("MOCK_DAO_CA_CERT"); caCert != "" {
		config.CACertFile = caCert
	}

	log.Printf("Starting Mock DAO Server on port %s", config.Port)
	log.Printf("Configuration:")
	log.Printf("  - Cert: %s", config.CertFile)
	log.Printf("  - Key: %s", config.KeyFile)
	log.Printf("  - CA Cert: %s", config.CACertFile)
	log.Printf("  - Signing Delay: %v", config.SigningDelay)
	log.Printf("  - Failure Rate: %.2f", config.FailureRate)

	// Create listener
	lis, err := net.Listen("tcp", config.Port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// Load TLS credentials
	creds, err := loadTLSCredentials(config)
	if err != nil {
		log.Fatalf("Failed to load TLS credentials: %v", err)
	}

	// Create gRPC server with TLS
	s := grpc.NewServer(grpc.Creds(creds))

	// Register service
	mockDAO := NewMockDAOServer(config)
	pb.RegisterUserTaskServer(s, mockDAO)

	log.Printf("Mock DAO Server listening on %s with TLS enabled", config.Port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}