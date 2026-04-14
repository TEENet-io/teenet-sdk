// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
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
	ID        uint32
	Name      string
	APIKey    string // The API key value (if stored)
	APISecret []byte // The API secret for HMAC signing (if stored)
	HasKey    bool
	HasSecret bool
}

// CacheEntry represents a voting cache entry
type CacheEntry struct {
	AppInstanceID string                  `json:"app_instance_id"`
	Hash          string                  `json:"hash"`
	Message       []byte                  `json:"message"`
	PublicKey     []byte                  `json:"public_key,omitempty"`
	Requests      map[string]*SignRequest `json:"requests"`
	RequiredVotes int                     `json:"required_votes"`
	CreatedAt     time.Time               `json:"created_at"`
	UpdatedAt     time.Time               `json:"updated_at"`
	Status        string                  `json:"status"`
	Signature     string                  `json:"signature,omitempty"`
	ErrorMessage  string                  `json:"error_message,omitempty"`
	TxID          string                  `json:"tx_id,omitempty"`
	RequestID     uint64                  `json:"request_id,omitempty"`
}

// SignRequest represents a vote from an instance
type SignRequest struct {
	AppInstanceID string    `json:"app_instance_id"`
	Timestamp     time.Time `json:"timestamp"`
	Approved      bool      `json:"approved"`
}

// VotingConfig defines per-app voting/approval settings
type VotingConfig struct {
	EnableVoting         bool     `json:"enable_voting"`
	RequiredVotes        int      `json:"required_votes"`
	TargetAppInstanceIDs []string `json:"target_app_instance_ids"`
	HasPasskeyPolicy     bool     `json:"has_passkey_policy"`
	PasskeyPolicyEnabled bool     `json:"passkey_policy_enabled"`
}

// MockPasskeyUser represents a registered passkey user
type MockPasskeyUser struct {
	ID             uint   `json:"id"`
	DisplayName    string `json:"display_name"`
	AppInstanceID  string `json:"app_instance_id,omitempty"`
	UserHandle     string `json:"user_handle,omitempty"`
	CredentialID   string `json:"credential_id,omitempty"`
	PublicKey      []byte `json:"public_key,omitempty"`
	AAGUID         string `json:"aaguid,omitempty"`
	SignCount      uint32 `json:"sign_count,omitempty"`
	BackupEligible bool   `json:"backup_eligible,omitempty"`
	BackupState    bool   `json:"backup_state,omitempty"`
	RPID           string `json:"rp_id,omitempty"`
	CreatedAt      string `json:"created_at"`
}

// MockPasskeyInvite represents a stored passkey registration invite.
type MockPasskeyInvite struct {
	Token         string     `json:"token"`
	DisplayName   string     `json:"display_name"`
	AppInstanceID string     `json:"app_instance_id,omitempty"`
	UserHandle    string     `json:"user_handle,omitempty"`
	SessionData   string     `json:"session_data,omitempty"`
	ExpiresAt     time.Time  `json:"expires_at"`
	UsedAt        *time.Time `json:"used_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// MockPasskeyLoginSession stores discoverable login session data.
type MockPasskeyLoginSession struct {
	ID          uint64     `json:"id"`
	SessionData string     `json:"session_data"`
	ExpiresAt   time.Time  `json:"expires_at"`
	UsedAt      *time.Time `json:"used_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// ApprovalTask represents an approval workflow task
type ApprovalTask struct {
	ID            uint64 `json:"id"`
	RequestID     uint64 `json:"request_id"`
	TxID          string `json:"tx_id"`
	AppInstanceID string `json:"app_instance_id"`
	PublicKeyName string `json:"public_key_name,omitempty"`
	Hash          string `json:"hash"`
	Status        string `json:"status"`
	Signature     string `json:"signature,omitempty"`
	Payload       string `json:"payload,omitempty"`
	InitiatorID   uint   `json:"requested_by_passkey_user_id,omitempty"`
	CreatedAt     string `json:"created_at"`
}

// MockAuditRecord represents an audit log entry
type MockAuditRecord struct {
	ID                 uint   `json:"id"`
	TaskID             *uint  `json:"task_id,omitempty"`
	RequestSessionID   *uint  `json:"request_session_id,omitempty"`
	EventType          string `json:"event_type"`
	Action             string `json:"action,omitempty"`
	Status             string `json:"status"`
	ActorPasskeyUserID uint   `json:"actor_passkey_user_id,omitempty"`
	ActorDisplayName   string `json:"actor_display_name,omitempty"`
	TxID               string `json:"tx_id,omitempty"`
	Hash               string `json:"hash,omitempty"`
	Signature          string `json:"signature,omitempty"`
	AppInstanceID      string `json:"app_instance_id,omitempty"`
	Details            string `json:"details,omitempty"`
	ErrorMessage       string `json:"error_message,omitempty"`
	CreatedAt          string `json:"created_at"`
}

// PermissionPolicy represents a mock permission policy
type PermissionPolicy struct {
	ID             uint          `json:"id"`
	PublicKeyName  string        `json:"public_key_name"`
	AppInstanceID  string        `json:"app_instance_id"`
	Enabled        bool          `json:"enabled"`
	TimeoutSeconds int64         `json:"timeout_seconds"`
	Levels         []PolicyLevel `json:"levels"`
}

// PolicyLevel is one level in a permission policy
type PolicyLevel struct {
	LevelIndex int    `json:"level_index"`
	Threshold  int    `json:"threshold"`
	MemberIDs  []uint `json:"member_ids"`
}

// MockServer implements a mock consensus server
type MockServer struct {
	// Default cryptographic keys (for pre-configured apps)
	ed25519Key   ed25519.PrivateKey
	secp256k1Key *btcec.PrivateKey
	secp256r1Key *ecdsa.PrivateKey

	// App ID to key mapping. Each app_instance_id can hold multiple keys
	// (different protocol/curve combinations), mirroring the real TEE-DAO
	// model where one app namespace owns many keys of arbitrary types.
	// Layout: app_instance_id -> public_key_hex -> AppKeyInfo.
	// defaultAppKey tracks the "first / primary" key per app for fallback
	// lookups when a request does not carry an explicit public_key.
	appKeys       map[string]map[string]*AppKeyInfo
	defaultAppKey map[string]string
	appKeysMutex  sync.RWMutex

	// Generated keys storage (per app) - public info only
	generatedKeys      map[string][]*GeneratedKeyInfo // app_instance_id -> list of keys
	generatedKeysMutex sync.RWMutex
	keyIDCounter       uint32

	// Stored key pairs for signing (includes private keys)
	storedKeyPairs      map[string]*StoredKeyPair // public_key_hex -> key pair
	storedKeyPairsMutex sync.RWMutex

	// API keys storage
	apiKeys         map[string]map[string]*APIKeyInfo // app_instance_id -> name -> APIKeyInfo
	apiKeysMutex    sync.RWMutex
	apiKeyIDCounter uint32

	// Voting cache
	votingCache      map[string]*CacheEntry // hash -> entry
	votingCacheMutex sync.RWMutex

	// Voting config per app
	votingConfigs      map[string]*VotingConfig // app_instance_id -> config
	votingConfigsMutex sync.RWMutex

	// Passkey users
	passkeyUsers         map[uint]*MockPasskeyUser // id -> user
	passkeyUsersMutex    sync.RWMutex
	passkeyUserIDCounter uint32
	passkeyInvites       map[string]*MockPasskeyInvite // token -> invite
	passkeyInvitesMutex  sync.RWMutex
	passkeyLoginSessions map[uint64]*MockPasskeyLoginSession // id -> login session
	passkeyLoginMutex    sync.RWMutex

	// Approval tasks
	approvalTasks           map[uint64]*ApprovalTask // task_id -> task
	approvalTasksMutex      sync.RWMutex
	approvalTaskIDCounter   uint64
	requestSessionIDCounter uint64

	// Audit records
	auditRecords         []*MockAuditRecord
	auditRecordsMutex    sync.RWMutex
	auditRecordIDCounter uint32

	// Permission policies
	policies        map[string]*PermissionPolicy // "app_instance_id:key_name" -> policy
	policiesMutex   sync.RWMutex
	policyIDCounter uint32

	// Token secret for mock approval tokens
	tokenSecret []byte

	// Login session counter
	loginSessionIDCounter uint64

	// WebAuthn service
	webAuthn *MockWebAuthnService

	// Configuration
	port          string
	enableLogging bool
}

// NewMockServer creates a new mock server
func NewMockServer(port string) *MockServer {
	// Generate token secret
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatalf("failed to generate token secret: %v", err)
	}

	webAuthn, err := NewMockWebAuthnService()
	if err != nil {
		log.Fatalf("failed to initialize webauthn service: %v", err)
	}

	s := &MockServer{
		port:                 port,
		enableLogging:        true,
		appKeys:              make(map[string]map[string]*AppKeyInfo),
		defaultAppKey:        make(map[string]string),
		generatedKeys:        make(map[string][]*GeneratedKeyInfo),
		storedKeyPairs:       make(map[string]*StoredKeyPair),
		apiKeys:              make(map[string]map[string]*APIKeyInfo),
		keyIDCounter:         1000,
		votingCache:          make(map[string]*CacheEntry),
		votingConfigs:        make(map[string]*VotingConfig),
		passkeyUsers:         make(map[uint]*MockPasskeyUser),
		passkeyInvites:       make(map[string]*MockPasskeyInvite),
		passkeyLoginSessions: make(map[uint64]*MockPasskeyLoginSession),
		approvalTasks:        make(map[uint64]*ApprovalTask),
		policies:             make(map[string]*PermissionPolicy),
		tokenSecret:          secret,
		webAuthn:             webAuthn,
	}

	// Generate consistent cryptographic keys (for default apps)
	s.ed25519Key = generateConsistentED25519Key()
	s.secp256k1Key = generateConsistentSECP256K1Key()
	s.secp256r1Key = generateConsistentSECP256R1Key()

	// Initialize default app keys
	s.initDefaultAppKeys()

	// Initialize sample API keys
	s.initSampleAPIKeys()

	// Initialize voting configs
	s.initVotingConfigs()

	// Initialize sample passkey users
	s.initSamplePasskeyUsers()

	return s
}

// setAppKey registers a key under an app_instance_id. The first key
// registered for an app becomes its default. Caller must hold appKeysMutex.
func (s *MockServer) setAppKeyLocked(appID string, info *AppKeyInfo) {
	if s.appKeys[appID] == nil {
		s.appKeys[appID] = make(map[string]*AppKeyInfo)
	}
	s.appKeys[appID][info.PublicKey] = info
	if _, hasDefault := s.defaultAppKey[appID]; !hasDefault {
		s.defaultAppKey[appID] = info.PublicKey
	}
}

// setAppKey is the thread-safe variant of setAppKeyLocked.
func (s *MockServer) setAppKey(appID string, info *AppKeyInfo) {
	s.appKeysMutex.Lock()
	defer s.appKeysMutex.Unlock()
	s.setAppKeyLocked(appID, info)
}

// lookupAppKey resolves an (appID, pubKeyHex) pair to the AppKeyInfo that
// should be used for signing. If pubKeyHex is non-empty and matches a
// registered key for the app, that key is returned. Otherwise the app's
// default key is returned. Returns (nil, false) if the app has no keys.
func (s *MockServer) lookupAppKey(appID, pubKeyHex string) (*AppKeyInfo, bool) {
	s.appKeysMutex.RLock()
	defer s.appKeysMutex.RUnlock()
	keys, ok := s.appKeys[appID]
	if !ok || len(keys) == 0 {
		return nil, false
	}
	if pubKeyHex != "" {
		if info, ok := keys[pubKeyHex]; ok {
			return info, true
		}
	}
	if def, ok := s.defaultAppKey[appID]; ok {
		if info, ok := keys[def]; ok {
			return info, true
		}
	}
	for _, info := range keys {
		return info, true
	}
	return nil, false
}

// appExists reports whether any key is registered for the given app.
func (s *MockServer) appExists(appID string) bool {
	s.appKeysMutex.RLock()
	defer s.appKeysMutex.RUnlock()
	_, ok := s.appKeys[appID]
	return ok
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
		s.setAppKey(app.appID, &AppKeyInfo{
			PublicKey:    hex.EncodeToString(app.pubKey),
			PublicKeyRaw: app.pubKey,
			Protocol:     app.protocol,
			Curve:        app.curve,
			ProtocolNum:  app.protocolNum,
			CurveNum:     app.curveNum,
		})
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

// initVotingConfigs sets up per-app voting configurations
func (s *MockServer) initVotingConfigs() {
	// Multi-party voting app: requires 2-of-3 votes
	// Uses the default secp256k1 ECDSA key
	secp256k1PubKey := s.secp256k1Key.PubKey()
	rawPubBytes := secp256k1PubKey.SerializeUncompressed()[1:] // 64 bytes, no 0x04 prefix

	// Multi-party voting group: three voter apps share the same public
	// key so that a 2-of-3 threshold can actually be reached by
	// submitting the same message from different app_instance_ids.
	votingTargets := []string{
		"test-voting-2of3",
		"test-voting-2of3-voter2",
		"test-voting-2of3-voter3",
	}
	for _, voterID := range votingTargets {
		s.votingConfigs[voterID] = &VotingConfig{
			EnableVoting:         true,
			RequiredVotes:        2,
			TargetAppInstanceIDs: votingTargets,
			HasPasskeyPolicy:     false,
			PasskeyPolicyEnabled: false,
		}
		s.setAppKey(voterID, &AppKeyInfo{
			PublicKey:    hex.EncodeToString(rawPubBytes),
			PublicKeyRaw: rawPubBytes,
			Protocol:     "ecdsa",
			Curve:        "secp256k1",
			ProtocolNum:  ProtocolECDSA,
			CurveNum:     CurveSECP256K1,
		})
	}

	// Approval-required app: needs passkey approval before signing
	s.votingConfigs["test-approval-required"] = &VotingConfig{
		EnableVoting:         false,
		RequiredVotes:        1,
		TargetAppInstanceIDs: []string{"test-approval-required"},
		HasPasskeyPolicy:     true,
		PasskeyPolicyEnabled: true,
	}
	s.setAppKey("test-approval-required", &AppKeyInfo{
		PublicKey:    hex.EncodeToString(rawPubBytes),
		PublicKeyRaw: rawPubBytes,
		Protocol:     "ecdsa",
		Curve:        "secp256k1",
		ProtocolNum:  ProtocolECDSA,
		CurveNum:     CurveSECP256K1,
	})

	// All other default test apps: direct signing (no voting)
	directApps := []string{
		"test-schnorr-ed25519",
		"test-schnorr-secp256k1",
		"test-ecdsa-secp256k1",
		"test-ecdsa-secp256r1",
		"ethereum-wallet-app",
		"secure-messaging-app",
	}
	for _, appID := range directApps {
		s.votingConfigs[appID] = &VotingConfig{
			EnableVoting:         false,
			RequiredVotes:        1,
			TargetAppInstanceIDs: []string{appID},
			HasPasskeyPolicy:     false,
			PasskeyPolicyEnabled: false,
		}
	}
}

// initSamplePasskeyUsers adds sample passkey users for testing
func (s *MockServer) initSamplePasskeyUsers() {
	now := time.Now().UTC().Format(time.RFC3339)
	s.passkeyUsers[1] = &MockPasskeyUser{
		ID:            1,
		DisplayName:   "Alice (test)",
		AppInstanceID: "test-approval-required",
		CreatedAt:     now,
	}
	s.passkeyUsers[2] = &MockPasskeyUser{
		ID:            2,
		DisplayName:   "Bob (test)",
		AppInstanceID: "test-approval-required",
		CreatedAt:     now,
	}
	startID := uint32(time.Now().Unix())
	if startID < 100 {
		startID = 100
	}
	atomic.StoreUint32(&s.passkeyUserIDCounter, startID)
}

func credentialIDFromPayload(credential interface{}) string {
	payload, ok := credential.(map[string]interface{})
	if !ok {
		return ""
	}
	if id, _ := payload["id"].(string); strings.TrimSpace(id) != "" {
		return strings.TrimSpace(id)
	}
	if rawID, _ := payload["rawId"].(string); strings.TrimSpace(rawID) != "" {
		return strings.TrimSpace(rawID)
	}
	return ""
}

func credentialJSONBytes(credential interface{}) []byte {
	if credential == nil {
		return nil
	}
	raw, err := json.Marshal(credential)
	if err != nil {
		return nil
	}
	return raw
}

func hasCredentialResponseFields(credential interface{}, fields ...string) bool {
	payload, ok := credential.(map[string]interface{})
	if !ok {
		return false
	}
	response, ok := payload["response"].(map[string]interface{})
	if !ok {
		return false
	}
	for _, field := range fields {
		value, _ := response[field].(string)
		if strings.TrimSpace(value) == "" {
			return false
		}
	}
	return true
}

func isRealRegistrationCredential(credential interface{}) bool {
	return hasCredentialResponseFields(credential, "clientDataJSON", "attestationObject")
}

func isRealLoginCredential(credential interface{}) bool {
	return hasCredentialResponseFields(credential, "clientDataJSON", "authenticatorData", "signature")
}

func (s *MockServer) getPasskeyInvite(inviteToken string) *MockPasskeyInvite {
	if strings.TrimSpace(inviteToken) == "" {
		return nil
	}
	s.passkeyInvitesMutex.RLock()
	defer s.passkeyInvitesMutex.RUnlock()
	invite := s.passkeyInvites[inviteToken]
	if invite == nil {
		return nil
	}
	copy := *invite
	return &copy
}

func (s *MockServer) getPasskeyLoginSession(sessionID uint64) *MockPasskeyLoginSession {
	if sessionID == 0 {
		return nil
	}
	s.passkeyLoginMutex.RLock()
	defer s.passkeyLoginMutex.RUnlock()
	session := s.passkeyLoginSessions[sessionID]
	if session == nil {
		return nil
	}
	copy := *session
	return &copy
}

func (s *MockServer) resolvePasskeyUserByHandleAndCredential(userHandle, credentialID string) *MockPasskeyUser {
	if strings.TrimSpace(userHandle) == "" || strings.TrimSpace(credentialID) == "" {
		return nil
	}
	s.passkeyUsersMutex.RLock()
	defer s.passkeyUsersMutex.RUnlock()
	for _, user := range s.passkeyUsers {
		if user.UserHandle == userHandle && user.CredentialID == credentialID {
			copy := *user
			return &copy
		}
	}
	return nil
}

func (s *MockServer) resolvePasskeyLoginUser(credential interface{}) *MockPasskeyUser {
	credentialID := credentialIDFromPayload(credential)

	s.passkeyUsersMutex.RLock()
	defer s.passkeyUsersMutex.RUnlock()

	if credentialID != "" {
		for _, user := range s.passkeyUsers {
			if user.CredentialID == credentialID {
				copy := *user
				return &copy
			}
		}
	}

	if user := s.passkeyUsers[1]; user != nil {
		copy := *user
		return &copy
	}
	for _, user := range s.passkeyUsers {
		copy := *user
		return &copy
	}
	return nil
}

// Start starts the mock server
func (s *MockServer) Start() error {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// Setup routes
	api := router.Group("/api")
	{
		api.GET("/health", s.handleHealth)
		api.GET("/publickeys/:app_instance_id", s.handleGetPublicKeys)
		api.POST("/submit-request", s.handleSubmitRequest)
		api.POST("/generate-key", s.handleGenerateKey)
		api.GET("/apikey/:name", s.handleGetAPIKey)
		api.POST("/apikey/:name/sign", s.handleSignWithSecret)

		// Cache endpoints
		api.GET("/cache/status", s.handleCacheStatus)
		api.GET("/cache/:hash", s.handleGetCache)
		api.DELETE("/cache/:hash", s.handleDeleteCache)
		api.GET("/config/:app_instance_id", s.handleGetConfig)

		// Approval bridge
		api.GET("/auth/passkey/options", s.handlePasskeyLoginOptions)
		api.POST("/auth/passkey/verify", s.handlePasskeyLoginVerify)
		api.POST("/auth/passkey/verify-as", s.handlePasskeyLoginVerifyAs)
		api.POST("/approvals/request/init", s.handleApprovalRequestInit)
		api.GET("/approvals/request/:requestId/challenge", s.handleApprovalRequestChallenge)
		api.POST("/approvals/request/:requestId/confirm", s.handleApprovalRequestConfirm)
		api.GET("/approvals/:taskId/challenge", s.handleApprovalActionChallenge)
		api.POST("/approvals/:taskId/action", s.handleApprovalAction)
		api.GET("/approvals/pending", s.handleApprovalPending)
		api.GET("/requests/mine", s.handleMyRequests)
		api.GET("/signature/by-tx/:txId", s.handleSignatureByTx)
		api.DELETE("/requests/:id", s.handleCancelRequest)

		// Admin bridge
		api.POST("/admin/passkey/invite", s.handleAdminInvitePasskey)
		api.GET("/admin/passkey/users", s.handleAdminListPasskeyUsers)
		api.DELETE("/admin/passkey/users/:id", s.handleAdminDeletePasskeyUser)
		api.GET("/admin/audit-records", s.handleAdminListAuditRecords)
		api.PUT("/admin/policy", s.handleAdminUpsertPolicy)
		api.GET("/admin/policy", s.handleAdminGetPolicy)
		api.DELETE("/admin/policy", s.handleAdminDeletePolicy)
		api.DELETE("/admin/publickeys/:name", s.handleAdminDeletePublicKey)
		api.POST("/admin/apikeys", s.handleAdminCreateAPIKey)
		api.DELETE("/admin/apikeys/:name", s.handleAdminDeleteAPIKey)
		api.GET("/passkey/register/options", s.handlePasskeyRegisterOptions)
		api.POST("/passkey/register/verify", s.handlePasskeyRegisterVerify)
	}

	log.Printf("Mock Consensus Server starting on port %s", s.port)
	log.Printf("Available test App IDs:")
	for appID, keys := range s.appKeys {
		for _, keyInfo := range keys {
			log.Printf("   - %s (%s/%s)", appID, keyInfo.Protocol, keyInfo.Curve)
		}
	}

	bindAddr := "127.0.0.1"
	if addr := os.Getenv("MOCK_SERVER_BIND"); addr != "" {
		bindAddr = addr
	}
	return router.Run(bindAddr + ":" + s.port)
}

// handleHealth handles GET /api/health
func (s *MockServer) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "TEENet Mock Consensus Server",
	})
}

// handleGetPublicKeys handles GET /api/publickeys/:app_instance_id
func (s *MockServer) handleGetPublicKeys(c *gin.Context) {
	appInstanceID := c.Param("app_instance_id")

	if appInstanceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "app_instance_id is required",
		})
		return
	}

	if !s.appExists(appInstanceID) {
		// Auto-create a new app with default ECDSA secp256k1 key
		secp256k1PubKey := s.secp256k1Key.PubKey().SerializeUncompressed()[1:]
		s.setAppKey(appInstanceID, &AppKeyInfo{
			PublicKey:    hex.EncodeToString(secp256k1PubKey),
			PublicKeyRaw: secp256k1PubKey,
			Protocol:     "ecdsa",
			Curve:        "secp256k1",
			ProtocolNum:  ProtocolECDSA,
			CurveNum:     CurveSECP256K1,
		})

		if s.enableLogging {
			log.Printf("Auto-created app %s with ECDSA/secp256k1", appInstanceID)
		}
	}

	// Snapshot all keys registered under this app. An app_instance_id may
	// hold multiple keys of different protocol/curve combinations; the
	// default key (first one registered) is surfaced as name="default".
	s.appKeysMutex.RLock()
	defaultPub := s.defaultAppKey[appInstanceID]
	appKeyMap := make(map[string]*AppKeyInfo, len(s.appKeys[appInstanceID]))
	for k, v := range s.appKeys[appInstanceID] {
		appKeyMap[k] = v
	}
	s.appKeysMutex.RUnlock()

	// Shape each entry to match proto PublicKeyConfig fields returned by
	// the real app-comm-consensus: id, name, key_data (plain hex, no 0x),
	// curve, protocol, application_id.
	keys := []gin.H{}
	if defaultInfo, ok := appKeyMap[defaultPub]; ok {
		keys = append(keys, gin.H{
			"id":             1,
			"name":           "default",
			"key_data":       defaultInfo.PublicKey,
			"protocol":       defaultInfo.Protocol,
			"curve":          defaultInfo.Curve,
			"application_id": 1,
		})
	}

	// Append generated keys
	s.generatedKeysMutex.RLock()
	if genKeys, ok := s.generatedKeys[appInstanceID]; ok {
		for _, gk := range genKeys {
			keys = append(keys, gin.H{
				"id":             gk.ID,
				"name":           gk.Name,
				"key_data":       gk.KeyData,
				"protocol":       gk.Protocol,
				"curve":          gk.Curve,
				"application_id": gk.ApplicationID,
			})
		}
	}
	s.generatedKeysMutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"success":         true,
		"app_instance_id": appInstanceID,
		"public_keys":     keys,
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
		log.Printf("Sign request: app_instance_id=%s, message_len=%d, hash=%s...",
			req.AppInstanceID, len(req.Message), hash[:20])
	}

	// Resolve which key to use. If the request carries a public_key, prefer
	// the matching key under this app; otherwise fall back to the app's
	// default. Supports multiple protocol/curve combinations per app.
	var reqPubKeyHex string
	if len(req.PublicKey) > 0 {
		reqPubKeyHex = hex.EncodeToString(req.PublicKey)
	}
	keyInfo, exists := s.lookupAppKey(req.AppInstanceID, reqPubKeyHex)
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": fmt.Sprintf("App instance ID not found: %s", req.AppInstanceID),
			"hash":    hash,
			"status":  "failed",
		})
		return
	}

	// Check voting config for this app
	s.votingConfigsMutex.RLock()
	votingCfg, hasCfg := s.votingConfigs[req.AppInstanceID]
	s.votingConfigsMutex.RUnlock()

	// --- Passkey approval required path ---
	if hasCfg && votingCfg.PasskeyPolicyEnabled {
		txID := fmt.Sprintf("mock-tx-%d", atomic.AddUint64(&s.requestSessionIDCounter, 1))
		requestID := atomic.AddUint64(&s.requestSessionIDCounter, 1)
		taskID := atomic.AddUint64(&s.approvalTaskIDCounter, 1)

		// Determine public key info for the task
		var pubKeyHex string
		if len(req.PublicKey) > 0 {
			pubKeyHex = hex.EncodeToString(req.PublicKey)
		} else {
			pubKeyHex = keyInfo.PublicKey
		}

		task := &ApprovalTask{
			ID:            taskID,
			RequestID:     requestID,
			TxID:          txID,
			AppInstanceID: req.AppInstanceID,
			PublicKeyName: pubKeyHex,
			Hash:          hash,
			Status:        "PENDING",
			Payload:       hex.EncodeToString(req.Message),
			CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		}
		s.approvalTasksMutex.Lock()
		s.approvalTasks[taskID] = task
		s.approvalTasksMutex.Unlock()

		// Create cache entry for tracking
		entry := &CacheEntry{
			AppInstanceID: req.AppInstanceID,
			Hash:          hash,
			Message:       req.Message,
			Requests:      make(map[string]*SignRequest),
			RequiredVotes: 1,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			Status:        "pending_approval",
			TxID:          txID,
			RequestID:     requestID,
		}
		s.votingCacheMutex.Lock()
		s.votingCache[hash] = entry
		s.votingCacheMutex.Unlock()

		s.addAuditRecord("APPROVAL_REQUEST", "SUBMIT", "PENDING", req.AppInstanceID, hash, txID, 0)

		c.JSON(http.StatusOK, gin.H{
			"success":      true,
			"message":      "Approval required",
			"status":       "pending_approval",
			"tx_id":        txID,
			"request_id":   requestID,
			"hash":         hash,
			"needs_voting": false,
		})
		return
	}

	// --- Voting path ---
	if hasCfg && votingCfg.EnableVoting {
		// Whitelist check: the voter must declare itself as a member of
		// its own voting group. This mirrors what real app-comm-consensus
		// enforces and prevents a misconfigured app from casting votes
		// toward a group it does not belong to.
		if !slices.Contains(votingCfg.TargetAppInstanceIDs, req.AppInstanceID) {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   "app_instance_id not declared in its own voting group",
				"status":  "rejected",
			})
			return
		}

		protocol := keyInfo.ProtocolNum
		curve := keyInfo.CurveNum
		var pubKeyHex string

		if len(req.PublicKey) > 0 {
			pubKeyHex = hex.EncodeToString(req.PublicKey)
			s.storedKeyPairsMutex.RLock()
			storedKeyPair, found := s.storedKeyPairs[pubKeyHex]
			s.storedKeyPairsMutex.RUnlock()
			if found {
				protocol = storedKeyPair.ProtocolNum
				curve = storedKeyPair.CurveNum
			}
		} else {
			pubKeyHex = keyInfo.PublicKey
		}

		// Register the vote and decide whether the threshold has been
		// reached. All touches of the shared entry happen inside this
		// critical section; we then snapshot the scalar values we need
		// for the response so the lock can be released before any slow
		// work (signing, logging, JSON serialization).
		s.votingCacheMutex.Lock()
		entry, entryExists := s.votingCache[hash]
		if entryExists {
			// Group-consistency check: a vote on an existing entry must
			// come from a voter whose own voting group still lists the
			// original initiator. This prevents two unrelated voting
			// groups from colliding on the same hash and cross-voting.
			if !slices.Contains(votingCfg.TargetAppInstanceIDs, entry.AppInstanceID) {
				s.votingCacheMutex.Unlock()
				c.JSON(http.StatusForbidden, gin.H{
					"success": false,
					"error":   "voting group mismatch with existing cache entry",
					"status":  "rejected",
					"hash":    hash,
				})
				return
			}
		} else {
			entry = &CacheEntry{
				AppInstanceID: req.AppInstanceID,
				Hash:          hash,
				Message:       req.Message,
				RequiredVotes: votingCfg.RequiredVotes,
				Requests:      make(map[string]*SignRequest),
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
				Status:        "pending",
			}
			s.votingCache[hash] = entry
		}
		entry.Requests[req.AppInstanceID] = &SignRequest{
			AppInstanceID: req.AppInstanceID,
			Timestamp:     time.Now(),
			Approved:      true,
		}
		entry.UpdatedAt = time.Now()

		approvedCount := 0
		for _, vote := range entry.Requests {
			if vote.Approved {
				approvedCount++
			}
		}
		requiredVotes := entry.RequiredVotes
		thresholdReached := approvedCount >= requiredVotes
		s.votingCacheMutex.Unlock()

		if !thresholdReached {
			if s.enableLogging {
				log.Printf("Voting in progress: hash=%s..., votes=%d/%d",
					hash[:20], approvedCount, requiredVotes)
			}
			c.JSON(http.StatusOK, gin.H{
				"success":        true,
				"message":        "Vote registered, waiting for threshold",
				"hash":           hash,
				"status":         "pending",
				"needs_voting":   true,
				"current_votes":  approvedCount,
				"required_votes": requiredVotes,
			})
			return
		}

		// Threshold reached — sign outside the cache lock so concurrent
		// readers/writers of the voting cache are not blocked on ECDSA.
		signature, signErr := s.signWithKey(protocol, curve, req.Message, pubKeyHex)
		if signErr != nil {
			s.votingCacheMutex.Lock()
			if cur, ok := s.votingCache[hash]; ok {
				cur.Status = "failed"
				cur.ErrorMessage = signErr.Error()
			}
			s.votingCacheMutex.Unlock()
			log.Printf("Voting signing failed: %v", signErr)
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "Signing failed: " + signErr.Error(),
				"hash":    hash,
				"status":  "failed",
			})
			return
		}

		signatureHex := hex.EncodeToString(signature)
		s.votingCacheMutex.Lock()
		if cur, ok := s.votingCache[hash]; ok {
			cur.Status = "signed"
			cur.Signature = signatureHex
		}
		s.votingCacheMutex.Unlock()

		if s.enableLogging {
			log.Printf("Voting threshold reached, signed: hash=%s..., votes=%d/%d",
				hash[:20], approvedCount, requiredVotes)
		}

		c.JSON(http.StatusOK, gin.H{
			"success":        true,
			"message":        "Voting threshold reached, signing completed",
			"hash":           hash,
			"status":         "signed",
			"signature":      signatureHex,
			"needs_voting":   false,
			"current_votes":  approvedCount,
			"required_votes": requiredVotes,
		})
		return
	}

	// --- Direct signing path (default) ---
	var protocol, curve uint32
	var pubKeyHex string

	// Always trust the app's registered protocol/curve from keyInfo.
	// The provided public_key is used only for key lookup, not type detection.
	protocol = keyInfo.ProtocolNum
	curve = keyInfo.CurveNum

	if len(req.PublicKey) > 0 {
		pubKeyHex = hex.EncodeToString(req.PublicKey)
		// Check if this is a stored/generated key pair with its own protocol/curve
		s.storedKeyPairsMutex.RLock()
		storedKeyPair, found := s.storedKeyPairs[pubKeyHex]
		s.storedKeyPairsMutex.RUnlock()
		if found {
			protocol = storedKeyPair.ProtocolNum
			curve = storedKeyPair.CurveNum
		}
	} else {
		pubKeyHex = keyInfo.PublicKey
	}

	signature, err := s.signWithKey(protocol, curve, req.Message, pubKeyHex)
	if err != nil {
		log.Printf("Signing failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success":      false,
			"message":      "Signing failed: " + err.Error(),
			"hash":         hash,
			"status":       "failed",
			"needs_voting": false,
		})
		return
	}

	signatureHex := hex.EncodeToString(signature)

	if s.enableLogging {
		log.Printf("Signed successfully: hash=%s..., sig_len=%d", hash[:20], len(signature))
	}

	c.JSON(http.StatusOK, gin.H{
		"success":        true,
		"message":        "Direct signing completed",
		"hash":           hash,
		"status":         "signed",
		"signature":      signatureHex,
		"needs_voting":   false,
		"current_votes":  0,
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
		if s.enableLogging {
			log.Printf("signWithKey: using stored key pair, protocol=%d, curve=%d", protocol, curve)
		}
		return s.signWithStoredKey(protocol, curve, message, keyPair)
	}

	// Fall back to default keys
	if s.enableLogging {
		log.Printf("signWithKey: using default keys, protocol=%d, curve=%d, pubKeyHex=%s...%s",
			protocol, curve, pubKeyHex[:16], pubKeyHex[len(pubKeyHex)-8:])
	}
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
			// btcec requires 32-byte hash; real FROST accepts variable-length.
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
			// Caller is responsible for hashing; sign the bytes directly.
			// SignCompact returns [v+27(+4 compressed)][R_32][S_32]; we
			// rearrange to Ethereum-style [R][S][v] with v in 0..3 so
			// that downstream ecrecover works correctly. Earlier code
			// derived v from the pubkey's Y parity, which is a constant
			// per key and produces invalid recovery IDs for half of
			// signatures.
			compact, err := btcecdsa.SignCompact(keyPair.SECP256K1Key, message, false)
			if err != nil {
				return nil, fmt.Errorf("SECP256K1 ECDSA signing failed: %v", err)
			}
			signature := make([]byte, 65)
			copy(signature[:32], compact[1:33])
			copy(signature[32:64], compact[33:65])
			v := compact[0] - 27
			if v >= 4 {
				v -= 4
			}
			signature[64] = v
			return signature, nil

		case CurveSECP256R1:
			if keyPair.SECP256R1Key == nil {
				return nil, fmt.Errorf("SECP256R1 key not available")
			}
			// Caller is responsible for hashing (same as secp256k1).
			r, s_sig, err := ecdsa.Sign(rand.Reader, keyPair.SECP256R1Key, message)
			if err != nil {
				return nil, fmt.Errorf("SECP256R1 ECDSA signing failed: %v", err)
			}
			// Enforce low-S
			halfOrder := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
			if s_sig.Cmp(halfOrder) > 0 {
				s_sig.Sub(elliptic.P256().Params().N, s_sig)
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
		// BIP-340 Schnorr: btcec requires 32-byte hash input.
		// The real FROST protocol accepts variable-length messages,
		// but btcec's schnorr.Sign does not. Hash here to simulate.
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
		// ECDSA on secp256k1 — caller is responsible for hashing.
		// The message bytes received are used directly as the digest.
		//
		// SignCompact returns [v+27(+4 compressed)][R_32][S_32]. We
		// rearrange to Ethereum-style [R][S][v] with v in 0..3 so that
		// downstream ecrecover works correctly.
		compact, err := btcecdsa.SignCompact(s.secp256k1Key, message, false)
		if err != nil {
			return nil, fmt.Errorf("SECP256K1 ECDSA signing failed: %v", err)
		}
		signature := make([]byte, 65)
		copy(signature[:32], compact[1:33])
		copy(signature[32:64], compact[33:65])
		v := compact[0] - 27
		if v >= 4 {
			v -= 4
		}
		signature[64] = v
		return signature, nil

	case CurveSECP256R1:
		// ECDSA on P-256 — caller is responsible for hashing (same as secp256k1).
		// TEE-DAO requires exactly 32 bytes (pre-hashed) for all ECDSA.
		r, s_sig, err := ecdsa.Sign(rand.Reader, s.secp256r1Key, message)
		if err != nil {
			return nil, fmt.Errorf("SECP256R1 ECDSA signing failed: %v", err)
		}

		// Enforce low-S (s <= n/2) for canonical signatures
		halfOrder := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
		if s_sig.Cmp(halfOrder) > 0 {
			s_sig.Sub(elliptic.P256().Params().N, s_sig)
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
		// Wallet address derivation expects a compressed secp256k1 public key
		// for both ECDSA and Schnorr flows.
		pubKeyRaw = privKey.PubKey().SerializeCompressed()
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

	// Register the generated key under the app. Multiple keys with
	// different protocol/curve combinations may coexist under the same
	// app_instance_id; the first one registered becomes the default.
	s.setAppKey(req.AppInstanceID, &AppKeyInfo{
		PublicKey:    pubKeyHex,
		PublicKeyRaw: pubKeyRaw,
		Protocol:     protocolLower,
		Curve:        curveLower,
		ProtocolNum:  protocolNum,
		CurveNum:     curveNum,
	})

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

// SignWithSecretRequest is the request for signing with API secret.
//
// Encoding rules:
//   - Default (or Encoding == "hex"): Message is hex-encoded bytes. Both
//     SDKs (Go and TypeScript) hex-encode the payload on the wire.
//   - Encoding == "raw": Message is raw UTF-8 text. Use this for direct
//     curl / test invocations.
//
// Auto-detection (try hex, fall back to raw) was removed because inputs
// like "deadbeef" are both valid hex AND valid text, producing different
// HMAC results depending on which branch happened to match.
type SignWithSecretRequest struct {
	AppInstanceID string `json:"app_instance_id" binding:"required"`
	Message       string `json:"message" binding:"required"`
	Encoding      string `json:"encoding,omitempty"`
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

	// Decode the message according to the declared encoding.
	var messageBytes []byte
	switch strings.ToLower(req.Encoding) {
	case "raw":
		messageBytes = []byte(req.Message)
	case "", "hex":
		decoded, err := hex.DecodeString(strings.TrimPrefix(req.Message, "0x"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   fmt.Sprintf("message must be hex-encoded (or set encoding=\"raw\"): %v", err),
			})
			return
		}
		messageBytes = decoded
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   fmt.Sprintf("unknown encoding %q (supported: hex, raw)", req.Encoding),
		})
		return
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
		log.Printf("HMAC sign: name=%s, app=%s, msg_len=%d", name, req.AppInstanceID, len(messageBytes))
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

// ============================================================================
// Token helpers
// ============================================================================

func (s *MockServer) generateToken(passkeyUserID uint) string {
	payload := fmt.Sprintf(`{"passkey_user_id":%d,"exp":%d,"iat":%d}`,
		passkeyUserID,
		time.Now().Add(30*time.Minute).Unix(),
		time.Now().Unix())
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, s.tokenSecret)
	mac.Write([]byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payloadB64 + "." + sigB64
}

func (s *MockServer) validateToken(token string) (uint, bool) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return 0, false
	}
	mac := hmac.New(sha256.New, s.tokenSecret)
	mac.Write([]byte(parts[0]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expected)) {
		return 0, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, false
	}
	var data struct {
		PasskeyUserID uint  `json:"passkey_user_id"`
		Exp           int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &data) != nil {
		return 0, false
	}
	if time.Now().Unix() > data.Exp {
		return 0, false
	}
	return data.PasskeyUserID, true
}

func (s *MockServer) extractToken(c *gin.Context) (uint, bool) {
	auth := c.GetHeader("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return 0, false
	}
	return s.validateToken(strings.TrimPrefix(auth, "Bearer "))
}

// ============================================================================
// Audit helper
// ============================================================================

func (s *MockServer) addAuditRecord(eventType, action, status, appInstanceID, hash, txID string, actorID uint) {
	id := atomic.AddUint32(&s.auditRecordIDCounter, 1)
	record := &MockAuditRecord{
		ID:                 uint(id),
		EventType:          eventType,
		Action:             action,
		Status:             status,
		AppInstanceID:      appInstanceID,
		Hash:               hash,
		TxID:               txID,
		ActorPasskeyUserID: actorID,
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
	}
	s.auditRecordsMutex.Lock()
	s.auditRecords = append(s.auditRecords, record)
	s.auditRecordsMutex.Unlock()
}

// ============================================================================
// Cache handlers
// ============================================================================

// cloneCacheEntry returns a detached copy of the entry safe to serialize
// after the voting cache lock has been released. Callers must hold the
// read lock while calling this.
func cloneCacheEntry(e *CacheEntry) *CacheEntry {
	if e == nil {
		return nil
	}
	copyEntry := *e
	if e.Message != nil {
		copyEntry.Message = append([]byte(nil), e.Message...)
	}
	if e.PublicKey != nil {
		copyEntry.PublicKey = append([]byte(nil), e.PublicKey...)
	}
	if e.Requests != nil {
		copyEntry.Requests = make(map[string]*SignRequest, len(e.Requests))
		for k, v := range e.Requests {
			if v == nil {
				continue
			}
			vv := *v
			copyEntry.Requests[k] = &vv
		}
	}
	return &copyEntry
}

// handleCacheStatus handles GET /api/cache/status
func (s *MockServer) handleCacheStatus(c *gin.Context) {
	s.votingCacheMutex.RLock()
	entries := make([]*CacheEntry, 0, len(s.votingCache))
	for _, e := range s.votingCache {
		entries = append(entries, cloneCacheEntry(e))
	}
	s.votingCacheMutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"total_entries": len(entries),
		"entries":       entries,
	})
}

// handleGetCache handles GET /api/cache/:hash
func (s *MockServer) handleGetCache(c *gin.Context) {
	hash := c.Param("hash")
	// Normalize: ensure 0x prefix
	if !strings.HasPrefix(hash, "0x") {
		hash = "0x" + hash
	}

	s.votingCacheMutex.RLock()
	entry, exists := s.votingCache[hash]
	var snapshot *CacheEntry
	if exists {
		snapshot = cloneCacheEntry(entry)
	}
	s.votingCacheMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"found":   false,
			"message": "cache entry not found",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"found":   true,
		"entry":   snapshot,
	})
}

// handleDeleteCache handles DELETE /api/cache/:hash
func (s *MockServer) handleDeleteCache(c *gin.Context) {
	hash := c.Param("hash")
	if !strings.HasPrefix(hash, "0x") {
		hash = "0x" + hash
	}

	s.votingCacheMutex.Lock()
	_, exists := s.votingCache[hash]
	if exists {
		delete(s.votingCache, hash)
	}
	s.votingCacheMutex.Unlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "cache entry not found",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "cache entry deleted",
	})
}

// handleGetConfig handles GET /api/config/:app_instance_id
func (s *MockServer) handleGetConfig(c *gin.Context) {
	appInstanceID := c.Param("app_instance_id")

	s.votingConfigsMutex.RLock()
	cfg, exists := s.votingConfigs[appInstanceID]
	s.votingConfigsMutex.RUnlock()

	if !exists {
		// Return default direct-signing config
		cfg = &VotingConfig{
			EnableVoting:         false,
			RequiredVotes:        1,
			TargetAppInstanceIDs: []string{appInstanceID},
			HasPasskeyPolicy:     false,
			PasskeyPolicyEnabled: false,
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"success":                 true,
		"app_instance_id":         appInstanceID,
		"enable_voting":           cfg.EnableVoting,
		"required_votes":          cfg.RequiredVotes,
		"target_app_instance_ids": cfg.TargetAppInstanceIDs,
		"has_passkey_policy":      cfg.HasPasskeyPolicy,
		"passkey_policy_enabled":  cfg.PasskeyPolicyEnabled,
	})
}

// ============================================================================
// Approval bridge handlers
// ============================================================================

// randomChallengeB64URL returns a 32-byte base64url-encoded challenge
// suitable for PublicKeyCredentialRequestOptions / CreationOptions. This
// mirrors the format a real WebAuthn relying party would emit so that
// browsers accept the options passed to navigator.credentials.get/create.
func randomChallengeB64URL() string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// prunePasskeyLoginSessions drops expired login sessions. Called
// opportunistically from handlePasskeyLoginOptions so a long-running
// mock server doesn't accumulate dead sessions indefinitely.
func (s *MockServer) prunePasskeyLoginSessions() {
	now := time.Now()
	s.passkeyLoginMutex.Lock()
	for id, session := range s.passkeyLoginSessions {
		if now.After(session.ExpiresAt) {
			delete(s.passkeyLoginSessions, id)
		}
	}
	s.passkeyLoginMutex.Unlock()
}

// handlePasskeyLoginOptions handles GET /api/auth/passkey/options.
// Returns a fully-formed PublicKeyCredentialRequestOptions so real
// browsers accept the challenge at navigator.credentials.get(). The
// mock does not validate the returned credential signature — any
// credential sent to /verify is accepted.
func (s *MockServer) handlePasskeyLoginOptions(c *gin.Context) {
	s.prunePasskeyLoginSessions()

	sessionID := atomic.AddUint64(&s.loginSessionIDCounter, 1)
	options, sessionData, err := s.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "failed to start login",
		})
		return
	}
	sessionJSON, err := EncodeSessionData(sessionData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "failed to encode login session",
		})
		return
	}
	expiresAt := time.Now().Add(5 * time.Minute)
	s.passkeyLoginMutex.Lock()
	s.passkeyLoginSessions[sessionID] = &MockPasskeyLoginSession{
		ID:          sessionID,
		SessionData: sessionJSON,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now().UTC(),
	}
	s.passkeyLoginMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"options":          options,
		"login_session_id": sessionID,
		"expires_at":       expiresAt.UTC().Format(time.RFC3339),
	})
}

// handlePasskeyLoginVerify handles POST /api/auth/passkey/verify
func (s *MockServer) handlePasskeyLoginVerify(c *gin.Context) {
	var body struct {
		LoginSessionID uint64      `json:"login_session_id"`
		Credential     interface{} `json:"credential"`
	}
	// Parse body; ignore errors — this is a mock
	_ = c.ShouldBindJSON(&body)

	if isRealLoginCredential(body.Credential) {
		loginSession := s.getPasskeyLoginSession(body.LoginSessionID)
		if loginSession == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error":   "login session not found",
			})
			return
		}
		if loginSession.UsedAt != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "login session already used",
			})
			return
		}
		if time.Now().After(loginSession.ExpiresAt) {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "login session expired",
			})
			return
		}
		sessionData, err := DecodeSessionData(loginSession.SessionData)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "invalid login session data",
			})
			return
		}

		var matchedUser *MockPasskeyUser
		handler := func(rawID, userHandle []byte) (webauthn.User, error) {
			credID := base64.RawURLEncoding.EncodeToString(rawID)
			handle := base64.RawURLEncoding.EncodeToString(userHandle)
			user := s.resolvePasskeyUserByHandleAndCredential(handle, credID)
			if user == nil {
				return nil, fmt.Errorf("passkey user not found")
			}
			webUser, err := BuildWebAuthnUserFromPasskey(user)
			if err != nil {
				return nil, err
			}
			matchedUser = user
			return webUser, nil
		}

		credential, err := s.webAuthn.FinishDiscoverableLogin(handler, sessionData, credentialJSONBytes(body.Credential))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "assertion failed",
			})
			return
		}
		if matchedUser == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "passkey user not found",
			})
			return
		}

		now := time.Now().UTC()
		s.passkeyLoginMutex.Lock()
		if stored := s.passkeyLoginSessions[body.LoginSessionID]; stored != nil && stored.UsedAt == nil {
			stored.UsedAt = &now
		}
		s.passkeyLoginMutex.Unlock()

		s.passkeyUsersMutex.Lock()
		if stored := s.passkeyUsers[matchedUser.ID]; stored != nil {
			stored.SignCount = credential.Authenticator.SignCount
			stored.BackupEligible = credential.Flags.BackupEligible
			stored.BackupState = credential.Flags.BackupState
		}
		s.passkeyUsersMutex.Unlock()

		token := s.generateToken(matchedUser.ID)
		expiresAt := time.Now().Add(30 * time.Minute).Unix()
		c.JSON(http.StatusOK, gin.H{
			"token":           token,
			"passkey_user_id": matchedUser.ID,
			"display_name":    matchedUser.DisplayName,
			"expires_at":      expiresAt,
		})
		return
	}

	user := s.resolvePasskeyLoginUser(body.Credential)
	userID := uint(1)
	displayName := ""
	if user != nil {
		userID = user.ID
		displayName = user.DisplayName
	}
	token := s.generateToken(userID)
	expiresAt := time.Now().Add(30 * time.Minute).Unix()

	c.JSON(http.StatusOK, gin.H{
		"token":           token,
		"passkey_user_id": userID,
		"display_name":    displayName,
		"expires_at":      expiresAt,
	})
}

// handlePasskeyLoginVerifyAs handles POST /api/auth/passkey/verify-as
func (s *MockServer) handlePasskeyLoginVerifyAs(c *gin.Context) {
	var body struct {
		LoginSessionID        uint64      `json:"login_session_id"`
		Credential            interface{} `json:"credential"`
		ExpectedPasskeyUserID uint        `json:"expected_passkey_user_id"`
	}
	_ = c.ShouldBindJSON(&body)

	userID := body.ExpectedPasskeyUserID
	if userID == 0 {
		userID = 1
	}

	// Check user exists
	s.passkeyUsersMutex.RLock()
	_, exists := s.passkeyUsers[userID]
	s.passkeyUsersMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error":   fmt.Sprintf("passkey user %d not found", userID),
		})
		return
	}

	token := s.generateToken(userID)
	expiresAt := time.Now().Add(30 * time.Minute).Unix()

	c.JSON(http.StatusOK, gin.H{
		"token":           token,
		"passkey_user_id": userID,
		"expires_at":      expiresAt,
	})
}

// handleApprovalRequestInit handles POST /api/approvals/request/init
func (s *MockServer) handleApprovalRequestInit(c *gin.Context) {
	userID, ok := s.extractToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error":   "unauthorized: missing or invalid token",
		})
		return
	}

	var body struct {
		AppInstanceID string      `json:"app_instance_id"`
		Payload       interface{} `json:"payload"`
		Hash          string      `json:"hash"`
		Message       []byte      `json:"message"`
	}
	_ = c.ShouldBindJSON(&body)

	requestID := atomic.AddUint64(&s.requestSessionIDCounter, 1)
	taskID := atomic.AddUint64(&s.approvalTaskIDCounter, 1)
	txID := fmt.Sprintf("mock-tx-%d", requestID)

	payloadBytes, _ := json.Marshal(body.Payload)

	task := &ApprovalTask{
		ID:            taskID,
		RequestID:     requestID,
		TxID:          txID,
		AppInstanceID: body.AppInstanceID,
		Hash:          body.Hash,
		Status:        "PENDING",
		Payload:       string(payloadBytes),
		InitiatorID:   userID,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	s.approvalTasksMutex.Lock()
	s.approvalTasks[taskID] = task
	s.approvalTasksMutex.Unlock()

	s.addAuditRecord("APPROVAL_REQUEST", "INIT", "PENDING", body.AppInstanceID, body.Hash, txID, userID)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"request_id": requestID,
			"tx_id":      txID,
			"status":     "PENDING",
		},
	})
}

// handleApprovalRequestChallenge handles GET /api/approvals/request/:requestId/challenge
func (s *MockServer) handleApprovalRequestChallenge(c *gin.Context) {
	requestIDStr := c.Param("requestId")
	sessionID := atomic.AddUint64(&s.loginSessionIDCounter, 1)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"request_id": requestIDStr,
			"options": gin.H{
				"challenge":        fmt.Sprintf("mock-challenge-confirm-%d", sessionID),
				"rp":               gin.H{"name": "TEENet Mock"},
				"login_session_id": sessionID,
			},
		},
	})
}

// handleApprovalRequestConfirm handles POST /api/approvals/request/:requestId/confirm
func (s *MockServer) handleApprovalRequestConfirm(c *gin.Context) {
	requestIDStr := c.Param("requestId")
	requestID, _ := strconv.ParseUint(requestIDStr, 10, 64)

	// Find the task with this requestID
	var foundTask *ApprovalTask
	s.approvalTasksMutex.Lock()
	for _, task := range s.approvalTasks {
		if task.RequestID == requestID {
			task.Status = "CONFIRMED"
			foundTask = task
			break
		}
	}
	s.approvalTasksMutex.Unlock()

	if foundTask == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "request not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"task_id":    foundTask.ID,
			"request_id": requestID,
			"status":     "CONFIRMED",
		},
	})
}

// handleApprovalActionChallenge handles GET /api/approvals/:taskId/challenge
func (s *MockServer) handleApprovalActionChallenge(c *gin.Context) {
	taskIDStr := c.Param("taskId")
	sessionID := atomic.AddUint64(&s.loginSessionIDCounter, 1)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"task_id": taskIDStr,
			"options": gin.H{
				"challenge":        fmt.Sprintf("mock-challenge-action-%d", sessionID),
				"rp":               gin.H{"name": "TEENet Mock"},
				"login_session_id": sessionID,
			},
		},
	})
}

// handleApprovalAction handles POST /api/approvals/:taskId/action
func (s *MockServer) handleApprovalAction(c *gin.Context) {
	taskIDStr := c.Param("taskId")
	taskID, err := strconv.ParseUint(taskIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "invalid task_id",
		})
		return
	}

	userID, ok := s.extractToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error":   "unauthorized",
		})
		return
	}

	var body struct {
		Action     string      `json:"action"` // "APPROVE" or "REJECT"
		Credential interface{} `json:"credential"`
	}
	_ = c.ShouldBindJSON(&body)

	action := strings.ToUpper(body.Action)
	if action != "APPROVE" && action != "REJECT" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "action must be APPROVE or REJECT",
		})
		return
	}

	// Snapshot the task fields we need. We release approvalTasksMutex
	// before doing any slow work (cache lookup, ECDSA signing) so the
	// lock is never held across an operation that also grabs another
	// mutex — eliminating the previous approvalTasks → votingCache
	// lock-order hazard.
	s.approvalTasksMutex.RLock()
	task, exists := s.approvalTasks[taskID]
	var taskHash, taskApp, taskTxID, taskPubKeyName string
	if exists {
		taskHash = task.Hash
		taskApp = task.AppInstanceID
		taskTxID = task.TxID
		taskPubKeyName = task.PublicKeyName
	}
	s.approvalTasksMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "task not found",
		})
		return
	}

	var signatureHex string
	finalStatus := "REJECTED"

	if action == "APPROVE" {
		finalStatus = "APPROVED"
		// Pull the message bytes for signing without holding any lock
		// across the sign call.
		var message []byte
		if taskHash != "" {
			s.votingCacheMutex.RLock()
			if cacheEntry, cacheExists := s.votingCache[taskHash]; cacheExists && len(cacheEntry.Message) > 0 {
				message = append([]byte(nil), cacheEntry.Message...)
			}
			s.votingCacheMutex.RUnlock()
		}

		if message != nil {
			// Resolve the key bound to the approval task. PublicKeyName
			// holds the pubkey hex captured at submit time; we look it
			// up explicitly so the correct protocol/curve is used when
			// the app has multiple keys.
			if appKey, appKeyExists := s.lookupAppKey(taskApp, taskPubKeyName); appKeyExists {
				if sig, sigErr := s.signWithKey(appKey.ProtocolNum, appKey.CurveNum, message, appKey.PublicKey); sigErr == nil {
					signatureHex = hex.EncodeToString(sig)
					// Write the signature back to the cache entry
					// under the cache lock alone.
					s.votingCacheMutex.Lock()
					if cur, ok := s.votingCache[taskHash]; ok {
						cur.Status = "signed"
						cur.Signature = signatureHex
					}
					s.votingCacheMutex.Unlock()
				}
			}
		}
	}

	// Finally, write the updated task status back under the approval
	// tasks lock alone.
	s.approvalTasksMutex.Lock()
	if cur, ok := s.approvalTasks[taskID]; ok {
		cur.Status = finalStatus
		cur.Signature = signatureHex
	}
	s.approvalTasksMutex.Unlock()

	s.addAuditRecord("APPROVAL_ACTION", action, finalStatus, taskApp, taskHash, taskTxID, userID)

	resp := gin.H{
		"success": true,
		"data": gin.H{
			"task_id": taskID,
			"status":  finalStatus,
			"action":  action,
		},
	}
	if signatureHex != "" {
		resp["signature"] = signatureHex
	}
	c.JSON(http.StatusOK, resp)
}

// handleApprovalPending handles GET /api/approvals/pending
func (s *MockServer) handleApprovalPending(c *gin.Context) {
	appFilter := c.Query("app_instance_id")

	s.approvalTasksMutex.RLock()
	pending := make([]*ApprovalTask, 0)
	for _, task := range s.approvalTasks {
		if task.Status == "PENDING" {
			if appFilter == "" || task.AppInstanceID == appFilter {
				pending = append(pending, task)
			}
		}
	}
	s.approvalTasksMutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"tasks": pending,
			"total": len(pending),
		},
	})
}

// handleMyRequests handles GET /api/requests/mine
func (s *MockServer) handleMyRequests(c *gin.Context) {
	userID, ok := s.extractToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error":   "unauthorized",
		})
		return
	}

	s.approvalTasksMutex.RLock()
	tasks := make([]*ApprovalTask, 0)
	for _, task := range s.approvalTasks {
		if task.InitiatorID == userID {
			tasks = append(tasks, task)
		}
	}
	s.approvalTasksMutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    tasks,
		"count":   len(tasks),
	})
}

// handleSignatureByTx handles GET /api/signature/by-tx/:txId
func (s *MockServer) handleSignatureByTx(c *gin.Context) {
	txID := c.Param("txId")

	s.approvalTasksMutex.RLock()
	var foundTask *ApprovalTask
	for _, task := range s.approvalTasks {
		if task.TxID == txID {
			foundTask = task
			break
		}
	}
	s.approvalTasksMutex.RUnlock()

	if foundTask == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "task not found for tx_id",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"tx_id":     txID,
		"status":    foundTask.Status,
		"signature": foundTask.Signature,
		"hash":      foundTask.Hash,
	})
}

// handleCancelRequest handles DELETE /api/requests/:id
func (s *MockServer) handleCancelRequest(c *gin.Context) {
	idStr := c.Param("id")
	requestType := c.Query("type") // "session" or "task"

	s.approvalTasksMutex.Lock()
	defer s.approvalTasksMutex.Unlock()

	if requestType == "session" {
		// Find by requestID (session)
		rid, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
			return
		}
		for _, task := range s.approvalTasks {
			if task.RequestID == rid {
				task.Status = "CANCELLED"
				c.JSON(http.StatusOK, gin.H{"success": true, "message": "request cancelled"})
				return
			}
		}
	} else {
		// Find by task ID
		tid, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
			return
		}
		if task, exists := s.approvalTasks[tid]; exists {
			task.Status = "CANCELLED"
			c.JSON(http.StatusOK, gin.H{"success": true, "message": "request cancelled"})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "request not found"})
}

// ============================================================================
// Admin bridge handlers
// ============================================================================

// handleAdminInvitePasskey handles POST /api/admin/passkey/invite
func (s *MockServer) handleAdminInvitePasskey(c *gin.Context) {
	var body struct {
		DisplayName   string `json:"display_name"`
		AppInstanceID string `json:"app_instance_id"`
	}
	_ = c.ShouldBindJSON(&body)

	inviteToken := fmt.Sprintf("mock-invite-%d", atomic.AddUint64(&s.loginSessionIDCounter, 1))
	userHandle, err := RandomBase64(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to generate user_handle"})
		return
	}
	now := time.Now().UTC()
	expiresAt := now.Add(24 * time.Hour)
	registerURL := fmt.Sprintf("http://localhost:%s/register?token=%s", s.port, inviteToken)

	s.passkeyInvitesMutex.Lock()
	s.passkeyInvites[inviteToken] = &MockPasskeyInvite{
		Token:         inviteToken,
		DisplayName:   strings.TrimSpace(body.DisplayName),
		AppInstanceID: strings.TrimSpace(body.AppInstanceID),
		UserHandle:    userHandle,
		ExpiresAt:     expiresAt,
		CreatedAt:     now,
	}
	s.passkeyInvitesMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"invite_token": inviteToken,
		"register_url": registerURL,
		"display_name": body.DisplayName,
		"expires_at":   expiresAt.Format(time.RFC3339),
	})
}

// handleAdminListPasskeyUsers handles GET /api/admin/passkey/users
func (s *MockServer) handleAdminListPasskeyUsers(c *gin.Context) {
	pageStr := c.DefaultQuery("page", "1")
	limitStr := c.DefaultQuery("limit", "20")
	page, _ := strconv.Atoi(pageStr)
	limit, _ := strconv.Atoi(limitStr)
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 20
	}

	s.passkeyUsersMutex.RLock()
	users := make([]*MockPasskeyUser, 0, len(s.passkeyUsers))
	for _, u := range s.passkeyUsers {
		users = append(users, u)
	}
	s.passkeyUsersMutex.RUnlock()

	total := len(users)
	start := (page - 1) * limit
	end := start + limit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users[start:end],
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

// handleAdminDeletePasskeyUser handles DELETE /api/admin/passkey/users/:id
func (s *MockServer) handleAdminDeletePasskeyUser(c *gin.Context) {
	idStr := c.Param("id")
	id64, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	userID := uint(id64)

	s.passkeyUsersMutex.Lock()
	_, exists := s.passkeyUsers[userID]
	if exists {
		delete(s.passkeyUsers, userID)
	}
	s.passkeyUsersMutex.Unlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "user deleted"})
}

// handleAdminListAuditRecords handles GET /api/admin/audit-records
func (s *MockServer) handleAdminListAuditRecords(c *gin.Context) {
	pageStr := c.DefaultQuery("page", "1")
	limitStr := c.DefaultQuery("limit", "20")
	page, _ := strconv.Atoi(pageStr)
	limit, _ := strconv.Atoi(limitStr)
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 20
	}

	s.auditRecordsMutex.RLock()
	records := make([]*MockAuditRecord, len(s.auditRecords))
	copy(records, s.auditRecords)
	s.auditRecordsMutex.RUnlock()

	total := len(records)
	start := (page - 1) * limit
	end := start + limit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	c.JSON(http.StatusOK, gin.H{
		"records": records[start:end],
		"total":   total,
		"page":    page,
		"limit":   limit,
	})
}

// handleAdminUpsertPolicy handles PUT /api/admin/policy
func (s *MockServer) handleAdminUpsertPolicy(c *gin.Context) {
	var policy PermissionPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	key := policy.AppInstanceID + ":" + policy.PublicKeyName

	s.policiesMutex.Lock()
	if existing, exists := s.policies[key]; exists {
		policy.ID = existing.ID
	} else {
		policy.ID = uint(atomic.AddUint32(&s.policyIDCounter, 1))
	}
	s.policies[key] = &policy
	s.policiesMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    policy,
	})
}

// handleAdminGetPolicy handles GET /api/admin/policy
func (s *MockServer) handleAdminGetPolicy(c *gin.Context) {
	appInstanceID := c.Query("app_instance_id")
	publicKeyName := c.Query("public_key_name")
	key := appInstanceID + ":" + publicKeyName

	s.policiesMutex.RLock()
	policy, exists := s.policies[key]
	s.policiesMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "policy not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"policy": policy})
}

// handleAdminDeletePolicy handles DELETE /api/admin/policy
func (s *MockServer) handleAdminDeletePolicy(c *gin.Context) {
	appInstanceID := c.Query("app_instance_id")
	publicKeyName := c.Query("public_key_name")
	key := appInstanceID + ":" + publicKeyName

	s.policiesMutex.Lock()
	_, exists := s.policies[key]
	if exists {
		delete(s.policies, key)
	}
	s.policiesMutex.Unlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "policy not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "policy deleted"})
}

// handleAdminDeletePublicKey handles DELETE /api/admin/publickeys/:name
func (s *MockServer) handleAdminDeletePublicKey(c *gin.Context) {
	name := c.Param("name")
	appInstanceID := c.Query("app_instance_id")

	deleted := false

	// Remove from appKeys if it matches. Delete by key name requires
	// cross-referencing generatedKeys to find the matching pubkey hex,
	// then unregistering just that entry while preserving other keys
	// under the same app.
	if appInstanceID != "" {
		var toDelete []string
		s.generatedKeysMutex.RLock()
		for _, gk := range s.generatedKeys[appInstanceID] {
			if gk.Name == name {
				toDelete = append(toDelete, gk.KeyData)
			}
		}
		s.generatedKeysMutex.RUnlock()

		s.appKeysMutex.Lock()
		keys := s.appKeys[appInstanceID]
		for _, pubHex := range toDelete {
			if _, ok := keys[pubHex]; ok {
				delete(keys, pubHex)
				deleted = true
			}
			if s.defaultAppKey[appInstanceID] == pubHex {
				delete(s.defaultAppKey, appInstanceID)
				for remaining := range keys {
					s.defaultAppKey[appInstanceID] = remaining
					break
				}
			}
		}
		if len(keys) == 0 {
			delete(s.appKeys, appInstanceID)
			delete(s.defaultAppKey, appInstanceID)
		}
		s.appKeysMutex.Unlock()
	}

	// Remove from generatedKeys by name
	s.generatedKeysMutex.Lock()
	for appID, keys := range s.generatedKeys {
		filtered := make([]*GeneratedKeyInfo, 0, len(keys))
		for _, k := range keys {
			if k.Name != name {
				filtered = append(filtered, k)
			} else {
				deleted = true
			}
		}
		s.generatedKeys[appID] = filtered
	}
	s.generatedKeysMutex.Unlock()

	if !deleted {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "public key not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "public key deleted", "name": name})
}

// AdminCreateAPIKeyRequest is the request body for creating an API key via admin
type AdminCreateAPIKeyRequest struct {
	AppInstanceID string `json:"app_instance_id" binding:"required"`
	Name          string `json:"name" binding:"required"`
	Description   string `json:"description"`
	APIKey        string `json:"api_key"`
	APISecret     string `json:"api_secret"`
}

// handleAdminCreateAPIKey handles POST /api/admin/apikeys
func (s *MockServer) handleAdminCreateAPIKey(c *gin.Context) {
	var req AdminCreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	id := atomic.AddUint32(&s.apiKeyIDCounter, 1)
	hasKey := req.APIKey != ""
	hasSecret := req.APISecret != ""
	keyInfo := &APIKeyInfo{
		ID:        id,
		Name:      req.Name,
		HasKey:    hasKey,
		HasSecret: hasSecret,
	}
	if hasKey {
		keyInfo.APIKey = req.APIKey
	}
	if hasSecret {
		keyInfo.APISecret = []byte(req.APISecret)
	}

	s.apiKeysMutex.Lock()
	if s.apiKeys[req.AppInstanceID] == nil {
		s.apiKeys[req.AppInstanceID] = make(map[string]*APIKeyInfo)
	}
	s.apiKeys[req.AppInstanceID][req.Name] = keyInfo
	s.apiKeysMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"id":              id,
		"name":            req.Name,
		"app_instance_id": req.AppInstanceID,
		"has_api_key":     hasKey,
		"has_api_secret":  hasSecret,
	})
}

// handleAdminDeleteAPIKey handles DELETE /api/admin/apikeys/:name
func (s *MockServer) handleAdminDeleteAPIKey(c *gin.Context) {
	name := c.Param("name")
	appInstanceID := c.Query("app_instance_id")

	s.apiKeysMutex.Lock()
	appKeys, appExists := s.apiKeys[appInstanceID]
	if appExists {
		_, keyExists := appKeys[name]
		if keyExists {
			delete(appKeys, name)
			s.apiKeysMutex.Unlock()
			c.JSON(http.StatusOK, gin.H{"success": true, "message": "API key deleted"})
			return
		}
	}
	s.apiKeysMutex.Unlock()

	c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "API key not found"})
}

// handlePasskeyRegisterOptions handles GET /api/passkey/register/options.
// Returns a fully-formed PublicKeyCredentialCreationOptions so real
// browsers accept the options at navigator.credentials.create(). Minimum
// fields required by the WebAuthn spec: challenge, rp.name, user{id,
// name, displayName}, pubKeyCredParams. The mock does not validate the
// attestation on /verify — any credential is accepted.
func (s *MockServer) handlePasskeyRegisterOptions(c *gin.Context) {
	inviteToken := c.Query("invite_token")
	if inviteToken == "" {
		inviteToken = c.Query("token")
	}
	invite := s.getPasskeyInvite(inviteToken)
	if invite == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "invite not found",
		})
		return
	}
	if invite.UsedAt != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "invite already used",
		})
		return
	}
	if time.Now().After(invite.ExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "invite expired",
		})
		return
	}

	webUser, err := BuildWebAuthnUserFromInvite(invite)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "failed to build webauthn user",
		})
		return
	}
	options, sessionData, err := s.webAuthn.BeginRegistration(webUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "failed to begin registration",
		})
		return
	}
	sessionJSON, err := EncodeSessionData(sessionData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "failed to encode registration session",
		})
		return
	}

	s.passkeyInvitesMutex.Lock()
	if stored := s.passkeyInvites[inviteToken]; stored != nil {
		stored.SessionData = sessionJSON
	}
	s.passkeyInvitesMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"options":      options,
		"invite_token": inviteToken,
		"expires_at":   invite.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// handlePasskeyRegisterVerify handles POST /api/passkey/register/verify
func (s *MockServer) handlePasskeyRegisterVerify(c *gin.Context) {
	var body struct {
		InviteToken   string      `json:"invite_token"`
		Credential    interface{} `json:"credential"`
		DisplayName   string      `json:"display_name"`
		AppInstanceID string      `json:"app_instance_id"`
	}
	_ = c.ShouldBindJSON(&body)

	if isRealRegistrationCredential(body.Credential) {
		invite := s.getPasskeyInvite(body.InviteToken)
		if invite == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error":   "invite not found",
			})
			return
		}
		if invite.UsedAt != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "invite already used",
			})
			return
		}
		if time.Now().After(invite.ExpiresAt) {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "invite expired",
			})
			return
		}
		if invite.SessionData == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "registration not started",
			})
			return
		}

		sessionData, err := DecodeSessionData(invite.SessionData)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "invalid registration session",
			})
			return
		}
		webUser, err := BuildWebAuthnUserFromInvite(invite)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "failed to build webauthn user",
			})
			return
		}
		credential, err := s.webAuthn.FinishRegistration(webUser, sessionData, credentialJSONBytes(body.Credential))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "registration failed: " + err.Error(),
			})
			return
		}

		credID := base64.RawURLEncoding.EncodeToString(credential.ID)
		aaguid := hex.EncodeToString(credential.Authenticator.AAGUID)
		newID := uint(atomic.AddUint32(&s.passkeyUserIDCounter, 1))
		now := time.Now().UTC()

		displayName := strings.TrimSpace(invite.DisplayName)
		if displayName == "" {
			displayName = fmt.Sprintf("User %d", newID)
		}

		user := &MockPasskeyUser{
			ID:             newID,
			DisplayName:    displayName,
			AppInstanceID:  invite.AppInstanceID,
			UserHandle:     invite.UserHandle,
			CredentialID:   credID,
			PublicKey:      credential.PublicKey,
			AAGUID:         aaguid,
			SignCount:      credential.Authenticator.SignCount,
			BackupEligible: credential.Flags.BackupEligible,
			BackupState:    credential.Flags.BackupState,
			RPID:           s.webAuthn.rpID,
			CreatedAt:      now.Format(time.RFC3339),
		}

		s.passkeyUsersMutex.Lock()
		s.passkeyUsers[newID] = user
		s.passkeyUsersMutex.Unlock()

		s.passkeyInvitesMutex.Lock()
		if stored := s.passkeyInvites[body.InviteToken]; stored != nil {
			stored.UsedAt = &now
		}
		s.passkeyInvitesMutex.Unlock()

		c.JSON(http.StatusOK, gin.H{
			"passkey_user_id": newID,
			"display_name":    displayName,
		})
		return
	}

	newID := uint(atomic.AddUint32(&s.passkeyUserIDCounter, 1))
	invite := s.getPasskeyInvite(body.InviteToken)
	displayName := strings.TrimSpace(body.DisplayName)
	if displayName == "" && invite != nil {
		displayName = strings.TrimSpace(invite.DisplayName)
	}
	if displayName == "" {
		displayName = fmt.Sprintf("User %d", newID)
	}
	appInstanceID := strings.TrimSpace(body.AppInstanceID)
	if appInstanceID == "" && invite != nil {
		appInstanceID = strings.TrimSpace(invite.AppInstanceID)
	}

	user := &MockPasskeyUser{
		ID:            newID,
		DisplayName:   displayName,
		AppInstanceID: appInstanceID,
		UserHandle:    "",
		CredentialID:  credentialIDFromPayload(body.Credential),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	s.passkeyUsersMutex.Lock()
	s.passkeyUsers[newID] = user
	s.passkeyUsersMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"passkey_user_id": newID,
		"display_name":    displayName,
	})
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
		log.Fatalf("Failed to start server: %v", err)
	}
}
