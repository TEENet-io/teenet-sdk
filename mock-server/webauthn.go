package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// MockWebAuthnService wraps go-webauthn for the mock server's passkey flows.
type MockWebAuthnService struct {
	wa            *webauthn.WebAuthn
	rpID          string
	rpDisplayName string
	rpOrigins     []string
	requireUV     bool
	platformOnly  bool
}

func NewMockWebAuthnService() (*MockWebAuthnService, error) {
	rpID := strings.TrimSpace(os.Getenv("PASSKEY_RP_ID"))
	rpOrigin := strings.TrimSpace(os.Getenv("PASSKEY_RP_ORIGIN"))
	if rpID == "" || rpOrigin == "" {
		return nil, errors.New("PASSKEY_RP_ID and PASSKEY_RP_ORIGIN must be set")
	}

	rpName := strings.TrimSpace(os.Getenv("PASSKEY_RP_NAME"))
	if rpName == "" {
		rpName = "TEENet Mock"
	}

	requireUV := readBoolEnv("PASSKEY_REQUIRE_UV", true)
	platformOnly := readBoolEnv("PASSKEY_PLATFORM_ONLY", false)

	origins := strings.Split(rpOrigin, ",")
	for i := range origins {
		origins[i] = strings.TrimSpace(origins[i])
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: rpName,
		RPID:          rpID,
		RPOrigins:     origins,
	})
	if err != nil {
		return nil, err
	}

	return &MockWebAuthnService{
		wa:            wa,
		rpID:          rpID,
		rpDisplayName: rpName,
		rpOrigins:     origins,
		requireUV:     requireUV,
		platformOnly:  platformOnly,
	}, nil
}

func readBoolEnv(name string, defaultValue bool) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return defaultValue
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return defaultValue
	}
	return v
}

func (s *MockWebAuthnService) BeginRegistration(user webauthn.User) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	opts := make([]webauthn.RegistrationOption, 0, 1)
	selection := protocol.AuthenticatorSelection{
		ResidentKey: protocol.ResidentKeyRequirementRequired,
	}
	if s.requireUV {
		selection.UserVerification = protocol.VerificationRequired
	}
	if s.platformOnly {
		selection.AuthenticatorAttachment = protocol.Platform
	}
	opts = append(opts, webauthn.WithAuthenticatorSelection(selection))
	return s.wa.BeginRegistration(user, opts...)
}

func (s *MockWebAuthnService) FinishRegistration(user webauthn.User, sessionData *webauthn.SessionData, credentialJSON []byte) (*webauthn.Credential, error) {
	req := httptest.NewRequest(http.MethodPost, "/webauthn/registration", bytes.NewReader(credentialJSON))
	req.Header.Set("Content-Type", "application/json")
	return s.wa.FinishRegistration(user, *sessionData, req)
}

func (s *MockWebAuthnService) BeginDiscoverableLogin() (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	opts := make([]webauthn.LoginOption, 0, 1)
	if s.requireUV {
		opts = append(opts, webauthn.WithUserVerification(protocol.VerificationRequired))
	}
	return s.wa.BeginDiscoverableLogin(opts...)
}

func (s *MockWebAuthnService) FinishDiscoverableLogin(handler webauthn.DiscoverableUserHandler, sessionData *webauthn.SessionData, credentialJSON []byte) (*webauthn.Credential, error) {
	req := httptest.NewRequest(http.MethodPost, "/webauthn/discoverable-login", bytes.NewReader(credentialJSON))
	req.Header.Set("Content-Type", "application/json")
	return s.wa.FinishDiscoverableLogin(handler, *sessionData, req)
}

func EncodeSessionData(sessionData *webauthn.SessionData) (string, error) {
	raw, err := json.Marshal(sessionData)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func DecodeSessionData(raw string) (*webauthn.SessionData, error) {
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(raw), &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func RandomBase64(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// MockWebAuthnUser is a minimal webauthn.User implementation for the mock server.
type MockWebAuthnUser struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

func (u MockWebAuthnUser) WebAuthnID() []byte {
	return u.ID
}

func (u MockWebAuthnUser) WebAuthnName() string {
	return u.Name
}

func (u MockWebAuthnUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u MockWebAuthnUser) WebAuthnIcon() string {
	return ""
}

func (u MockWebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func BuildWebAuthnUserFromInvite(invite *MockPasskeyInvite) (MockWebAuthnUser, error) {
	if invite == nil || invite.UserHandle == "" {
		return MockWebAuthnUser{}, fmt.Errorf("invite user_handle missing")
	}

	userID, err := base64.RawURLEncoding.DecodeString(invite.UserHandle)
	if err != nil {
		return MockWebAuthnUser{}, err
	}

	name := strings.TrimSpace(invite.DisplayName)
	if name == "" {
		name = "passkey-user"
	}

	return MockWebAuthnUser{
		ID:          userID,
		Name:        name,
		DisplayName: name,
	}, nil
}

func BuildWebAuthnUserFromPasskey(user *MockPasskeyUser) (MockWebAuthnUser, error) {
	if user == nil {
		return MockWebAuthnUser{}, fmt.Errorf("passkey user missing")
	}

	userID, err := base64.RawURLEncoding.DecodeString(user.UserHandle)
	if err != nil {
		return MockWebAuthnUser{}, err
	}

	credID, err := base64.RawURLEncoding.DecodeString(user.CredentialID)
	if err != nil {
		return MockWebAuthnUser{}, err
	}

	var aaguid []byte
	if user.AAGUID != "" {
		aaguid, _ = hex.DecodeString(user.AAGUID)
	}

	credential := webauthn.Credential{
		ID:        credID,
		PublicKey: user.PublicKey,
		Flags: webauthn.CredentialFlags{
			BackupEligible: user.BackupEligible,
			BackupState:    user.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:    aaguid,
			SignCount: user.SignCount,
		},
	}

	return MockWebAuthnUser{
		ID:          userID,
		Name:        user.DisplayName,
		DisplayName: user.DisplayName,
		Credentials: []webauthn.Credential{credential},
	}, nil
}
