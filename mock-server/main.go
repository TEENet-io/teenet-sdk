// -----------------------------------------------------------------------------
// Mock Consensus Server for TEENet SDK Testing
//
// This mock server simulates the app-comm-consensus service to enable
// offline testing of the TEENet SDK without connecting to actual TEE nodes.
// It implements real cryptographic signing for all supported algorithms.
// -----------------------------------------------------------------------------

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/sha3"
)

// Protocol constants
const (
	ProtocolECDSA   uint32 = 1
	ProtocolSchnorr uint32 = 2
)

// Curve constants
const (
	CurveED25519   uint32 = 1
	CurveSECP256K1 uint32 = 2
	CurveSECP256R1 uint32 = 3
)

// AppKeyInfo stores app key information
type AppKeyInfo struct {
	PublicKey    string
	PublicKeyRaw []byte
	Protocol     string
	Curve        string
	ProtocolNum  uint32
	CurveNum     uint32
}

// GeneratedKeyInfo stores generated key information (public response)
type GeneratedKeyInfo struct {
	ID                  uint32 `json:"id"`
	Name                string `json:"name"`
	KeyData             string `json:"key_data"`
	Curve               string `json:"curve"`
	Protocol            string `json:"protocol"`
	Threshold           uint32 `json:"threshold,omitempty"`
	ParticipantCount    uint32 `json:"participant_count,omitempty"`
	MaxParticipantCount uint32 `json:"max_participant_count,omitempty"`
	ApplicationID       uint32 `json:"application_id"`
	CreatedByInstanceID string `json:"created_by_instance_id"`
}

// StoredKeyPair stores both public and private key for signing
type StoredKeyPair struct {
	ID           uint32
	PublicKey    []byte
	PublicKeyHex string
	Protocol     string
	Curve        string
	ProtocolNum  uint32
	CurveNum     uint32
	// Private keys (only one will be set based on curve)
	ED25519Key   ed25519.PrivateKey
	SECP256K1Key *btcec.PrivateKey
	SECP256R1Key *ecdsa.PrivateKey
}

// APIKeyInfo stores API key/secret information
type APIKeyInfo struct {
	Name      string
	APIKey    string // The API key value (if stored)
	APISecret []byte // The API secret for HMAC signing (if stored)
	HasKey    bool
	HasSecret bool
}

// MockServer implements a mock consensus server
type MockServer struct {
	// Default cryptographic keys (for pre-configured apps)
	ed25519Key   ed25519.PrivateKey
	secp256k1Key *btcec.PrivateKey
	secp256r1Key *ecdsa.PrivateKey

	// App ID to key mapping (for pre-configured apps)
	appKeys      map[string]*AppKeyInfo
	appKeysMutex sync.RWMutex

	// Generated keys storage (per app) - public info only
	generatedKeys      map[string][]*GeneratedKeyInfo // app_instance_id -> list of keys
	generatedKeysMutex sync.RWMutex
	keyIDCounter       uint32

	// Stored key pairs for signing (includes private keys)
	storedKeyPairs      map[string]*StoredKeyPair // public_key_hex -> key pair
	storedKeyPairsMutex sync.RWMutex

	// API keys storage
	apiKeys      map[string]map[string]*APIKeyInfo // app_instance_id -> name -> APIKeyInfo
	apiKeysMutex sync.RWMutex

	// Configuration
	port          string
	enableLogging bool
}

// NewMockServer creates a new mock server
func NewMockServer(port string) *MockServer {
	s := &MockServer{
		port:           port,
		enableLogging:  true,
		appKeys:        make(map[string]*AppKeyInfo),
		generatedKeys:  make(map[string][]*GeneratedKeyInfo),
		storedKeyPairs: make(map[string]*StoredKeyPair),
		apiKeys:        make(map[string]map[string]*APIKeyInfo),
		keyIDCounter:   1000,
	}

	// Generate consistent cryptographic keys (for default apps)
	s.ed25519Key = generateConsistentED25519Key()
	s.secp256k1Key = generateConsistentSECP256K1Key()
	s.secp256r1Key = generateConsistentSECP256R1Key()

	// Initialize default app keys
	s.initDefaultAppKeys()

	// Initialize sample API keys
	s.initSampleAPIKeys()

	return s
}

// initDefaultAppKeys initializes default application keys for testing
func (s *MockServer) initDefaultAppKeys() {
	// Generate public keys from our private keys
	ed25519PubKey := s.ed25519Key.Public().(ed25519.PublicKey)
	secp256k1PubKeyCompressed := s.secp256k1Key.PubKey().SerializeCompressed()
	secp256k1PubKeyUncompressed := s.secp256k1Key.PubKey().SerializeUncompressed()[1:] // Remove 0x04 prefix
	secp256r1PubKeyCompressed := elliptic.MarshalCompressed(s.secp256r1Key.Curve, s.secp256r1Key.X, s.secp256r1Key.Y)

	// Default app configurations
	apps := []struct {
		appID       string
		protocol    string
		protocolNum uint32
		curve       string
		curveNum    uint32
		pubKey      []byte
	}{
		{"test-schnorr-ed25519", "schnorr", ProtocolSchnorr, "ed25519", CurveED25519, ed25519PubKey},
		{"test-schnorr-secp256k1", "schnorr", ProtocolSchnorr, "secp256k1", CurveSECP256K1, secp256k1PubKeyCompressed},
		{"test-ecdsa-secp256k1", "ecdsa", ProtocolECDSA, "secp256k1", CurveSECP256K1, secp256k1PubKeyUncompressed},
		{"test-ecdsa-secp256r1", "ecdsa", ProtocolECDSA, "secp256r1", CurveSECP256R1, secp256r1PubKeyCompressed},
		{"ethereum-wallet-app", "ecdsa", ProtocolECDSA, "secp256k1", CurveSECP256K1, secp256k1PubKeyUncompressed},
		{"secure-messaging-app", "schnorr", ProtocolSchnorr, "ed25519", CurveED25519, ed25519PubKey},
	}

	for _, app := range apps {
		s.appKeys[app.appID] = &AppKeyInfo{
			PublicKey:    hex.EncodeToString(app.pubKey),
			PublicKeyRaw: app.pubKey,
			Protocol:     app.protocol,
			Curve:        app.curve,
			ProtocolNum:  app.protocolNum,
			CurveNum:     app.curveNum,
		}
	}
}

// initSampleAPIKeys initializes sample API keys for testing
func (s *MockServer) initSampleAPIKeys() {
	// Create sample API keys for test apps
	testApps := []string{"test-schnorr-ed25519", "test-ecdsa-secp256k1", "ethereum-wallet-app"}

	for _, appID := range testApps {
		s.apiKeys[appID] = map[string]*APIKeyInfo{
			"test-api-key": {
				Name:      "test-api-key",
				APIKey:    "sk_test_" + appID + "_12345",
				HasKey:    true,
				HasSecret: false,
			},
			"test-api-secret": {
				Name:      "test-api-secret",
				APISecret: []byte("secret_" + appID + "_abcdef"),
				HasKey:    false,
				HasSecret: true,
			},
			"test-both": {
				Name:      "test-both",
				APIKey:    "key_" + appID,
				APISecret: []byte("secret_" + appID),
				HasKey:    true,
				HasSecret: true,
			},
		}
	}
}

// Start starts the mock server
func (s *MockServer) Start() error {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// Setup routes
	api := router.Group("/api")
	{
		api.GET("/health", s.handleHealth)
		api.GET("/publickey/:app_instance_id", s.handleGetPublicKey)
		api.POST("/submit-request", s.handleSubmitRequest)
		api.POST("/generate-key", s.handleGenerateKey)
		api.GET("/apikey/:name", s.handleGetAPIKey)
		api.POST("/apikey/:name/sign", s.handleSignWithSecret)
	}

	log.Printf("🚀 Mock Consensus Server starting on port %s", s.port)
	log.Printf("📋 Available test App IDs:")
	for appID, keyInfo := range s.appKeys {
		log.Printf("   - %s (%s/%s)", appID, keyInfo.Protocol, keyInfo.Curve)
	}

	return router.Run(":" + s.port)
}

// handleHealth handles GET /api/health
func (s *MockServer) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "TEENet Mock Consensus Server",
	})
}

// handleGetPublicKey handles GET /api/publickey/:app_instance_id
func (s *MockServer) handleGetPublicKey(c *gin.Context) {
	appInstanceID := c.Param("app_instance_id")

	if appInstanceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "app_instance_id is required",
		})
		return
	}

	s.appKeysMutex.RLock()
	keyInfo, exists := s.appKeys[appInstanceID]
	s.appKeysMutex.RUnlock()

	if !exists {
		// Auto-create a new app with default ECDSA secp256k1 key
		s.appKeysMutex.Lock()
		secp256k1PubKey := s.secp256k1Key.PubKey().SerializeUncompressed()[1:]
		keyInfo = &AppKeyInfo{
			PublicKey:    hex.EncodeToString(secp256k1PubKey),
			PublicKeyRaw: secp256k1PubKey,
			Protocol:     "ecdsa",
			Curve:        "secp256k1",
			ProtocolNum:  ProtocolECDSA,
			CurveNum:     CurveSECP256K1,
		}
		s.appKeys[appInstanceID] = keyInfo
		s.appKeysMutex.Unlock()

		if s.enableLogging {
			log.Printf("📝 Auto-created app %s with ECDSA/secp256k1", appInstanceID)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"app_id":     appInstanceID,
		"public_key": keyInfo.PublicKey,
		"protocol":   keyInfo.Protocol,
		"curve":      keyInfo.Curve,
	})
}

// SubmitRequestPayload is the request body for submitting a signature request
type SubmitRequestPayload struct {
	AppInstanceID string `json:"app_instance_id"`
	Message       []byte `json:"message"`
	PublicKey     []byte `json:"public_key,omitempty"`
}

// handleSubmitRequest handles POST /api/submit-request
func (s *MockServer) handleSubmitRequest(c *gin.Context) {
	var req SubmitRequestPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request format: " + err.Error(),
		})
		return
	}

	// Calculate message hash
	hashBytes := sha256.Sum256(req.Message)
	hash := "0x" + hex.EncodeToString(hashBytes[:])

	if s.enableLogging {
		log.Printf("📥 Sign request: app_instance_id=%s, message_len=%d, hash=%s...",
			req.AppInstanceID, len(req.Message), hash[:20])
	}

	// Get app key info
	s.appKeysMutex.RLock()
	keyInfo, exists := s.appKeys[req.AppInstanceID]
	s.appKeysMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": fmt.Sprintf("App instance ID not found: %s", req.AppInstanceID),
			"hash":    hash,
			"status":  "failed",
		})
		return
	}

	// Determine which key to use
	var protocol, curve uint32
	var pubKeyHex string

	if len(req.PublicKey) > 0 {
		// Use provided public key
		pubKeyHex = hex.EncodeToString(req.PublicKey)

		// First, check if this is a stored generated key
		s.storedKeyPairsMutex.RLock()
		storedKeyPair, found := s.storedKeyPairs[pubKeyHex]
		s.storedKeyPairsMutex.RUnlock()

		if found {
			// Use stored key's protocol/curve
			protocol = storedKeyPair.ProtocolNum
			curve = storedKeyPair.CurveNum
		} else {
			// Try to detect key type from bytes
			protocol, curve = s.detectKeyType(req.PublicKey)
			if protocol == 0 {
				// Fall back to app's default
				protocol = keyInfo.ProtocolNum
				curve = keyInfo.CurveNum
			}
		}
	} else {
		// Use default app key
		protocol = keyInfo.ProtocolNum
		curve = keyInfo.CurveNum
		pubKeyHex = keyInfo.PublicKey
	}

	// Generate signature using appropriate key
	signature, err := s.signWithKey(protocol, curve, req.Message, pubKeyHex)
	if err != nil {
		log.Printf("❌ Signing failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success":     false,
			"message":     "Signing failed: " + err.Error(),
			"hash":        hash,
			"status":      "failed",
			"needs_voting": false,
		})
		return
	}

	signatureHex := hex.EncodeToString(signature)

	if s.enableLogging {
		log.Printf("✅ Signed successfully: hash=%s..., sig_len=%d", hash[:20], len(signature))
	}

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"message":       "Direct signing completed",
		"hash":          hash,
		"status":        "signed",
		"signature":     signatureHex,
		"needs_voting":  false,
		"current_votes": 0,
		"required_votes": 0,
	})
}

// detectKeyType tries to determine the key type from the public key bytes
func (s *MockServer) detectKeyType(pubKey []byte) (protocol, curve uint32) {
	switch len(pubKey) {
	case 32:
		// ED25519 public key
		return ProtocolSchnorr, CurveED25519
	case 33:
		// Compressed secp256k1 or secp256r1
		return ProtocolECDSA, CurveSECP256K1
	case 64:
		// Uncompressed secp256k1 (without prefix)
		return ProtocolECDSA, CurveSECP256K1
	case 65:
		// Uncompressed with prefix
		return ProtocolECDSA, CurveSECP256K1
	default:
		return 0, 0
	}
}

// signWithKey generates a signature using the appropriate key (stored or default)
func (s *MockServer) signWithKey(protocol, curve uint32, message []byte, pubKeyHex string) ([]byte, error) {
	// First, try to find a stored key pair
	s.storedKeyPairsMutex.RLock()
	keyPair, found := s.storedKeyPairs[pubKeyHex]
	s.storedKeyPairsMutex.RUnlock()

	if found {
		// Use the stored key pair
		return s.signWithStoredKey(protocol, curve, message, keyPair)
	}

	// Fall back to default keys
	return s.sign(protocol, curve, message)
}

// signWithStoredKey signs with a stored key pair
func (s *MockServer) signWithStoredKey(protocol, curve uint32, message []byte, keyPair *StoredKeyPair) ([]byte, error) {
	switch protocol {
	case ProtocolSchnorr:
		switch curve {
		case CurveED25519:
			if keyPair.ED25519Key == nil {
				return nil, fmt.Errorf("ED25519 key not available")
			}
			return ed25519.Sign(keyPair.ED25519Key, message), nil
		case CurveSECP256K1:
			if keyPair.SECP256K1Key == nil {
				return nil, fmt.Errorf("SECP256K1 key not available")
			}
			hash := sha256.Sum256(message)
			sig, err := schnorr.Sign(keyPair.SECP256K1Key, hash[:])
			if err != nil {
				return nil, fmt.Errorf("Schnorr signing failed: %v", err)
			}
			return sig.Serialize(), nil
		default:
			return nil, fmt.Errorf("unsupported curve for Schnorr: %d", curve)
		}

	case ProtocolECDSA:
		switch curve {
		case CurveSECP256K1:
			if keyPair.SECP256K1Key == nil {
				return nil, fmt.Errorf("SECP256K1 key not available")
			}
			hasher := sha3.NewLegacyKeccak256()
			hasher.Write(message)
			messageHash := hasher.Sum(nil)
			sig := btcecdsa.Sign(keyPair.SECP256K1Key, messageHash)
			derSig := sig.Serialize()
			signature := make([]byte, 65)
			rBytes, sBytes := extractRSFromDER(derSig)
			copy(signature[:32], padTo32(rBytes))
			copy(signature[32:64], padTo32(sBytes))
			pubKeyBytes := keyPair.SECP256K1Key.PubKey().SerializeUncompressed()
			if len(pubKeyBytes) == 65 && pubKeyBytes[64]%2 == 0 {
				signature[64] = 0
			} else {
				signature[64] = 1
			}
			return signature, nil

		case CurveSECP256R1:
			if keyPair.SECP256R1Key == nil {
				return nil, fmt.Errorf("SECP256R1 key not available")
			}
			hash := sha256.Sum256(message)
			r, s_sig, err := ecdsa.Sign(rand.Reader, keyPair.SECP256R1Key, hash[:])
			if err != nil {
				return nil, fmt.Errorf("SECP256R1 ECDSA signing failed: %v", err)
			}
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

// sign generates a real cryptographic signature using default keys
func (s *MockServer) sign(protocol, curve uint32, message []byte) ([]byte, error) {
	switch protocol {
	case ProtocolSchnorr:
		return s.signSchnorr(curve, message)
	case ProtocolECDSA:
		return s.signECDSA(curve, message)
	default:
		return nil, fmt.Errorf("unsupported protocol: %d", protocol)
	}
}

// signSchnorr generates a Schnorr signature
func (s *MockServer) signSchnorr(curve uint32, message []byte) ([]byte, error) {
	switch curve {
	case CurveED25519:
		// ED25519 signature (EdDSA)
		return ed25519.Sign(s.ed25519Key, message), nil

	case CurveSECP256K1:
		// BIP-340 Schnorr signature
		hash := sha256.Sum256(message)
		sig, err := schnorr.Sign(s.secp256k1Key, hash[:])
		if err != nil {
			return nil, fmt.Errorf("Schnorr signing failed: %v", err)
		}
		return sig.Serialize(), nil

	default:
		return nil, fmt.Errorf("unsupported curve for Schnorr: %d", curve)
	}
}

// signECDSA generates an ECDSA signature
func (s *MockServer) signECDSA(curve uint32, message []byte) ([]byte, error) {
	switch curve {
	case CurveSECP256K1:
		// Ethereum-style ECDSA with Keccak-256
		hasher := sha3.NewLegacyKeccak256()
		hasher.Write(message)
		messageHash := hasher.Sum(nil)

		sig := btcecdsa.Sign(s.secp256k1Key, messageHash)

		// Ethereum-style 65-byte signature: R (32) + S (32) + V (1)
		// Serialize the signature to DER and then extract R and S
		derSig := sig.Serialize()

		// Parse the DER signature to get R and S values
		// DER format: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s]
		signature := make([]byte, 65)

		// Use a simpler approach: serialize to compact format
		// The btcec v2 Signature has Serialize() that returns DER
		// We need to extract R and S manually
		rBytes, sBytes := extractRSFromDER(derSig)
		copy(signature[:32], padTo32(rBytes))
		copy(signature[32:64], padTo32(sBytes))

		// Recovery ID
		pubKeyBytes := s.secp256k1Key.PubKey().SerializeUncompressed()
		if len(pubKeyBytes) == 65 && pubKeyBytes[64]%2 == 0 {
			signature[64] = 0
		} else {
			signature[64] = 1
		}

		return signature, nil

	case CurveSECP256R1:
		// ECDSA with SHA-256 on P-256
		hash := sha256.Sum256(message)
		r, s_sig, err := ecdsa.Sign(rand.Reader, s.secp256r1Key, hash[:])
		if err != nil {
			return nil, fmt.Errorf("SECP256R1 ECDSA signing failed: %v", err)
		}

		// 64-byte signature: R (32) + S (32)
		signature := make([]byte, 64)
		r.FillBytes(signature[:32])
		s_sig.FillBytes(signature[32:])
		return signature, nil

	default:
		return nil, fmt.Errorf("unsupported curve for ECDSA: %d", curve)
	}
}

// GenerateKeyRequest is the request for key generation
type GenerateKeyRequest struct {
	AppInstanceID string `json:"app_instance_id" binding:"required"`
	Curve         string `json:"curve" binding:"required"`
	Protocol      string `json:"protocol" binding:"required"`
}

// handleGenerateKey handles POST /api/generate-key
func (s *MockServer) handleGenerateKey(c *gin.Context) {
	var req GenerateKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request format: " + err.Error(),
		})
		return
	}

	if s.enableLogging {
		log.Printf("Generating key: app=%s, curve=%s, protocol=%s",
			req.AppInstanceID, req.Curve, req.Protocol)
	}

	// Generate key ID
	keyID := atomic.AddUint32(&s.keyIDCounter, 1)

	curveLower := strings.ToLower(req.Curve)
	protocolLower := strings.ToLower(req.Protocol)

	var protocolNum, curveNum uint32
	switch protocolLower {
	case "schnorr":
		protocolNum = ProtocolSchnorr
	case "ecdsa":
		protocolNum = ProtocolECDSA
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": fmt.Sprintf("Unsupported protocol: %s", req.Protocol),
		})
		return
	}

	// Generate new random key pair
	keyPair := &StoredKeyPair{
		ID:          keyID,
		Protocol:    protocolLower,
		Curve:       curveLower,
		ProtocolNum: protocolNum,
	}

	var pubKeyHex string
	var pubKeyRaw []byte

	switch curveLower {
	case "ed25519":
		curveNum = CurveED25519
		// Generate new ED25519 key
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": fmt.Sprintf("Failed to generate ED25519 key: %v", err),
			})
			return
		}
		keyPair.ED25519Key = privKey
		pubKeyRaw = privKey.Public().(ed25519.PublicKey)
		pubKeyHex = hex.EncodeToString(pubKeyRaw)

	case "secp256k1":
		curveNum = CurveSECP256K1
		// Generate new SECP256K1 key
		privKey, err := btcec.NewPrivateKey()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": fmt.Sprintf("Failed to generate SECP256K1 key: %v", err),
			})
			return
		}
		keyPair.SECP256K1Key = privKey
		if protocolNum == ProtocolSchnorr {
			pubKeyRaw = privKey.PubKey().SerializeCompressed()
		} else {
			pubKeyRaw = privKey.PubKey().SerializeUncompressed()[1:]
		}
		pubKeyHex = hex.EncodeToString(pubKeyRaw)

	case "secp256r1":
		curveNum = CurveSECP256R1
		// Generate new SECP256R1 key
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": fmt.Sprintf("Failed to generate SECP256R1 key: %v", err),
			})
			return
		}
		keyPair.SECP256R1Key = privKey
		pubKeyRaw = elliptic.MarshalCompressed(privKey.Curve, privKey.X, privKey.Y)
		pubKeyHex = hex.EncodeToString(pubKeyRaw)

	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": fmt.Sprintf("Unsupported curve: %s", req.Curve),
		})
		return
	}

	keyPair.CurveNum = curveNum
	keyPair.PublicKey = pubKeyRaw
	keyPair.PublicKeyHex = pubKeyHex

	// Store key pair for later signing
	s.storedKeyPairsMutex.Lock()
	s.storedKeyPairs[pubKeyHex] = keyPair
	s.storedKeyPairsMutex.Unlock()

	// Store generated key info
	keyInfo := &GeneratedKeyInfo{
		ID:                  keyID,
		Name:                fmt.Sprintf("key-%d", keyID),
		KeyData:             pubKeyHex,
		Curve:               curveLower,
		Protocol:            protocolLower,
		Threshold:           1,
		ParticipantCount:    1,
		MaxParticipantCount: 3,
		ApplicationID:       1,
		CreatedByInstanceID: req.AppInstanceID,
	}

	s.generatedKeysMutex.Lock()
	s.generatedKeys[req.AppInstanceID] = append(s.generatedKeys[req.AppInstanceID], keyInfo)
	s.generatedKeysMutex.Unlock()

	// Also update app keys (set as default for this app)
	s.appKeysMutex.Lock()
	s.appKeys[req.AppInstanceID] = &AppKeyInfo{
		PublicKey:    pubKeyHex,
		PublicKeyRaw: pubKeyRaw,
		Protocol:     protocolLower,
		Curve:        curveLower,
		ProtocolNum:  protocolNum,
		CurveNum:     curveNum,
	}
	s.appKeysMutex.Unlock()

	if s.enableLogging {
		log.Printf("Key generated: id=%d, app=%s, pubkey=%s...", keyID, req.AppInstanceID, pubKeyHex[:16])
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"message":    "Key generated successfully",
		"public_key": keyInfo,
	})
}

// handleGetAPIKey handles GET /api/apikey/:name
func (s *MockServer) handleGetAPIKey(c *gin.Context) {
	name := c.Param("name")
	appInstanceID := c.Query("app_instance_id")

	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "name is required",
		})
		return
	}

	if appInstanceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "app_instance_id query parameter is required",
		})
		return
	}

	s.apiKeysMutex.RLock()
	appAPIKeys, appExists := s.apiKeys[appInstanceID]
	if !appExists {
		s.apiKeysMutex.RUnlock()
		// Auto-create for unknown apps
		c.JSON(http.StatusOK, gin.H{
			"success":         true,
			"app_instance_id": appInstanceID,
			"name":            name,
			"api_key":         "mock_api_key_" + name + "_" + appInstanceID,
		})
		return
	}

	apiKeyInfo, exists := appAPIKeys[name]
	s.apiKeysMutex.RUnlock()

	if !exists {
		// Auto-create for unknown names
		c.JSON(http.StatusOK, gin.H{
			"success":         true,
			"app_instance_id": appInstanceID,
			"name":            name,
			"api_key":         "mock_api_key_" + name,
		})
		return
	}

	if !apiKeyInfo.HasKey {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "This API key entry does not have an API key stored (only secret)",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":         true,
		"app_instance_id": appInstanceID,
		"name":            name,
		"api_key":         apiKeyInfo.APIKey,
	})
}

// SignWithSecretRequest is the request for signing with API secret
type SignWithSecretRequest struct {
	AppInstanceID string `json:"app_instance_id" binding:"required"`
	Message       string `json:"message" binding:"required"`
}

// handleSignWithSecret handles POST /api/apikey/:name/sign
func (s *MockServer) handleSignWithSecret(c *gin.Context) {
	name := c.Param("name")

	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "name is required",
		})
		return
	}

	var req SignWithSecretRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   fmt.Sprintf("Invalid request format: %v", err),
		})
		return
	}

	// Parse message (support hex encoding)
	var messageBytes []byte
	if decoded, err := hex.DecodeString(req.Message); err == nil && len(decoded) > 0 {
		messageBytes = decoded
	} else {
		messageBytes = []byte(req.Message)
	}

	// Get or create API secret
	var secret []byte

	s.apiKeysMutex.RLock()
	appAPIKeys, appExists := s.apiKeys[req.AppInstanceID]
	if appExists {
		apiKeyInfo, exists := appAPIKeys[name]
		if exists && apiKeyInfo.HasSecret {
			secret = apiKeyInfo.APISecret
		}
	}
	s.apiKeysMutex.RUnlock()

	if secret == nil {
		// Use a default mock secret
		secret = []byte("mock_secret_" + name + "_" + req.AppInstanceID)
	}

	// Sign using HMAC-SHA256
	mac := hmac.New(sha256.New, secret)
	mac.Write(messageBytes)
	signature := mac.Sum(nil)
	signatureHex := hex.EncodeToString(signature)

	if s.enableLogging {
		log.Printf("🔐 HMAC sign: name=%s, app=%s, msg_len=%d", name, req.AppInstanceID, len(messageBytes))
	}

	c.JSON(http.StatusOK, gin.H{
		"success":         true,
		"app_instance_id": req.AppInstanceID,
		"name":            name,
		"signature":       signatureHex,
		"signature_hex":   signatureHex,
		"algorithm":       "HMAC-SHA256",
		"message_length":  len(messageBytes),
	})
}

// Key generation helpers

// extractRSFromDER extracts R and S values from a DER-encoded ECDSA signature
func extractRSFromDER(der []byte) (r, s []byte) {
	if len(der) < 8 {
		return nil, nil
	}

	// DER format: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s]
	if der[0] != 0x30 {
		return nil, nil
	}

	pos := 2 // Skip 0x30 and total length

	// Read R
	if der[pos] != 0x02 {
		return nil, nil
	}
	pos++
	rLen := int(der[pos])
	pos++
	r = der[pos : pos+rLen]
	pos += rLen

	// Read S
	if der[pos] != 0x02 {
		return nil, nil
	}
	pos++
	sLen := int(der[pos])
	pos++
	s = der[pos : pos+sLen]

	return r, s
}

// padTo32 pads a byte slice to 32 bytes (left-pad with zeros)
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		// If longer (e.g., has leading zero for sign), take last 32 bytes
		return b[len(b)-32:]
	}
	result := make([]byte, 32)
	copy(result[32-len(b):], b)
	return result
}

func generateConsistentED25519Key() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	seedString := "teenet-mock-server-ed25519-key!!"
	copy(seed, []byte(seedString))
	return ed25519.NewKeyFromSeed(seed)
}

func generateConsistentSECP256K1Key() *btcec.PrivateKey {
	seed := []byte("teenet-mock-server-secp256k1-key-12345678901234567890123456789012")
	privateKeyInt := new(big.Int).SetBytes(seed[:32])

	curve := btcec.S256()
	for privateKeyInt.Cmp(curve.N) >= 0 {
		privateKeyInt.Sub(privateKeyInt, curve.N)
	}

	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyInt.Bytes())
	return privateKey
}

func generateConsistentSECP256R1Key() *ecdsa.PrivateKey {
	seed := []byte("teenet-mock-server-secp256r1-key-12345678901234567890123456789012")
	privateKeyInt := new(big.Int).SetBytes(seed[:32])

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
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(privateKeyInt.Bytes())

	return privateKey
}

func main() {
	port := "8089"
	if p := os.Getenv("MOCK_SERVER_PORT"); p != "" {
		port = p
	}

	server := NewMockServer(port)

	log.Println("=" + strings.Repeat("=", 60))
	log.Println("  TEENet SDK Mock Consensus Server")
	log.Println("=" + strings.Repeat("=", 60))
	log.Printf("  Port: %s", port)
	log.Printf("  Time: %s", time.Now().Format(time.RFC3339))
	log.Println("=" + strings.Repeat("=", 60))

	if err := server.Start(); err != nil {
		log.Fatalf("❌ Failed to start server: %v", err)
	}
}
