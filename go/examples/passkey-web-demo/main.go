// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	sdk "github.com/TEENet-io/teenet-sdk/go"
)

type sessionState struct {
	ApprovalToken string
}

type server struct {
	serviceURL   string
	appInstanceID  string
	frontendDir    string
	bootstrapToken string
	sdkClient      *sdk.Client

	mu          sync.RWMutex
	sessions    map[string]*sessionState
	sdkClientMu sync.Mutex
}

type voteStatusResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Found         bool   `json:"found"`
		Hash          string `json:"hash"`
		Status        string `json:"status"`
		RequiredVotes int    `json:"required_votes"`
		Signature     string `json:"signature"`
		ErrorMessage  string `json:"error_message"`
	} `json:"data"`
}

var demoSessionPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{12,128}$`)

func main() {
	serviceURL := strings.TrimSpace(os.Getenv("SERVICE_URL"))
	if serviceURL == "" {
		serviceURL = "http://127.0.0.1:8089"
	}
	host := strings.TrimSpace(os.Getenv("DEMO_HOST"))
	if host == "" {
		host = "127.0.0.1"
	}
	port := strings.TrimSpace(os.Getenv("DEMO_PORT"))
	if port == "" {
		port = "18090"
	}
	bootstrapToken := strings.TrimSpace(os.Getenv("APPROVAL_TOKEN"))

	// SDK reads APP_INSTANCE_ID from environment automatically.
	s := &server{
		serviceURL:     serviceURL,
		appInstanceID:  strings.TrimSpace(os.Getenv("APP_INSTANCE_ID")),
		bootstrapToken: bootstrapToken,
		frontendDir:    detectFrontendDir(),
		sdkClient:      sdk.NewClient(serviceURL),
		sessions:       make(map[string]*sessionState),
	}
	defer s.sdkClient.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)

	addr := host + ":" + port
	log.Printf("[go-passkey-web-demo] http://%s", addr)
	log.Printf("[go-passkey-web-demo] SERVICE_URL=%s", serviceURL)
	if s.appInstanceID == "" {
		log.Printf("[go-passkey-web-demo] APP_INSTANCE_ID=(missing)")
	} else {
		log.Printf("[go-passkey-web-demo] APP_INSTANCE_ID=%s", s.appInstanceID)
	}

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func (s *server) handle(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		s.handleAPI(w, r)
		return
	}
	s.serveStatic(w, r)
}

func (s *server) handleAPI(w http.ResponseWriter, r *http.Request) {
	sid := s.ensureSessionID(w, r)
	state := s.getSession(sid)
	withClient := func(token string, fn func(client *sdk.Client, approvalToken string) error) error {
		s.sdkClientMu.Lock()
		defer s.sdkClientMu.Unlock()
		return fn(s.sdkClient, token)
	}

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/sign":
		if s.appInstanceID == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "APP_INSTANCE_ID is not configured"})
			return
		}
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		publicKeyName := strings.TrimSpace(toString(body["public_key_name"]))
		if publicKeyName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "public_key_name is required"})
			return
		}
		message, err := buildSignMessageBytes(body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		signerToken := s.sessionToken(state)
		var signRes *sdk.SignResult
		callErr := withClient(signerToken, func(client *sdk.Client, approvalToken string) error {
			client.SetDefaultAppInstanceID(s.appInstanceID)
			var innerErr error
			signRes, innerErr = client.Sign(r.Context(), message, publicKeyName, approvalToken)
			return innerErr
		})
		// APPROVAL_PENDING comes back as (signRes populated, callErr=ErrApprovalPending).
		// Fall through whenever signRes is populated so error_code / voting_info
		// get forwarded; otherwise frontend sees the error without error_code and
		// renders it as a failure.
		if signRes == nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{
				"success": false,
				"error": func() string {
					if callErr != nil {
						return callErr.Error()
					}
					return "empty sign response"
				}(),
			})
			return
		}

		data := map[string]interface{}{
			"app_instance_id": s.appInstanceID,
			"public_key_name": publicKeyName,
			"sign_success":    signRes.Success,
			"error":           signRes.Error,
			"error_code":      signRes.ErrorCode,
		}
		if signRes.VotingInfo != nil {
			data["status"] = signRes.VotingInfo.Status
			data["hash"] = signRes.VotingInfo.Hash
			data["request_id"] = signRes.VotingInfo.RequestID
			data["tx_id"] = signRes.VotingInfo.TxID
			data["needs_voting"] = signRes.VotingInfo.NeedsVoting
		}
		if signRes.Success && len(signRes.Signature) > 0 {
			data["signature"] = "0x" + hex.EncodeToString(signRes.Signature)
		}
		if _, ok := data["status"]; !ok {
			if signRes.Success {
				data["status"] = "signed"
			} else {
				data["status"] = "failed"
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    data,
		})
		return

	case r.Method == http.MethodGet && r.URL.Path == "/api/login/options":
		var res *sdk.ApprovalResult
		err := withClient("", func(client *sdk.Client, _ string) error {
			var callErr error
			res, callErr = client.PasskeyLoginOptions(r.Context())
			return callErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return

	case r.Method == http.MethodPost && r.URL.Path == "/api/login/verify":
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		loginID, _ := toUint64(body["login_session_id"])
		credentialBytes, err := marshalAny(body["credential"])
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid credential payload"})
			return
		}
		var res *sdk.ApprovalResult
		callErr := withClient("", func(client *sdk.Client, _ string) error {
			var err error
			res, err = client.PasskeyLoginVerify(r.Context(), loginID, credentialBytes)
			return err
		})
		if callErr != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": callErr.Error()})
			return
		}
		if res.Success {
			if token, _ := stringValue(res.Data["token"]); token != "" {
				s.mu.Lock()
				state.ApprovalToken = token
				s.mu.Unlock()
			}
		}
		writeJSON(w, http.StatusOK, res)
		return

	case r.Method == http.MethodGet && r.URL.Path == "/api/approvals/pending":
		token := s.sessionToken(state)
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "not logged in for this browser session"})
			return
		}
		query := r.URL.Query()
		appInstanceID := strings.TrimSpace(query.Get("app_instance_id"))
		if appInstanceID == "" {
			appInstanceID = s.appInstanceID
		}
		publicKeyName := strings.TrimSpace(query.Get("public_key_name"))
		var res *sdk.ApprovalResult
		err := withClient(token, func(client *sdk.Client, approvalToken string) error {
			var callErr error
			res, callErr = client.ApprovalPending(r.Context(), approvalToken, nil)
			return callErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		filterPendingApprovalsResult(res, appInstanceID, publicKeyName)
		writeJSON(w, http.StatusOK, res)
		return

	}

	if r.Method == http.MethodGet {
		if reqID, ok := matchUintPath(r.URL.Path, "/api/approvals/request/", "/challenge"); ok {
			token := s.sessionToken(state)
			if token == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "not logged in for this browser session"})
				return
			}
			var res *sdk.ApprovalResult
			err := withClient(token, func(client *sdk.Client, approvalToken string) error {
				var callErr error
				res, callErr = client.ApprovalRequestChallenge(r.Context(), reqID, approvalToken)
				return callErr
			})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, res)
			return
		}
		if taskID, ok := matchUintPath(r.URL.Path, "/api/approvals/", "/challenge"); ok {
			token := s.sessionToken(state)
			if token == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "not logged in for this browser session"})
				return
			}
			var res *sdk.ApprovalResult
			err := withClient(token, func(client *sdk.Client, approvalToken string) error {
				var callErr error
				res, callErr = client.ApprovalActionChallenge(r.Context(), taskID, approvalToken)
				return callErr
			})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, res)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/signature/by-tx/") {
			token := s.sessionToken(state)
			if token == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "not logged in for this browser session"})
				return
			}
			txID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/signature/by-tx/"))
			txID, _ = url.QueryUnescape(txID)
			if txID == "" {
				writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "tx_id is required"})
				return
			}
			byTx, err := getRequestByTxFromService(s.serviceURL, token, txID)
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
				return
			}
			resp := map[string]interface{}{
				"success": true,
				"data":    byTx,
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
	}

	if r.Method == http.MethodPost {
		if reqID, ok := matchUintPath(r.URL.Path, "/api/approvals/request/", "/confirm"); ok {
			token := s.sessionToken(state)
			if token == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "not logged in for this browser session"})
				return
			}
			var body map[string]interface{}
			if err := decodeJSON(r.Body, &body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
				return
			}
			payloadBytes, _ := json.Marshal(body)
			var res *sdk.ApprovalResult
			err := withClient(token, func(client *sdk.Client, approvalToken string) error {
				var callErr error
				res, callErr = client.ApprovalRequestConfirm(r.Context(), reqID, payloadBytes, approvalToken)
				return callErr
			})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, res)
			return
		}
		if taskID, ok := matchUintPath(r.URL.Path, "/api/approvals/", "/action"); ok {
			token := s.sessionToken(state)
			if token == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "not logged in for this browser session"})
				return
			}
			var body map[string]interface{}
			if err := decodeJSON(r.Body, &body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
				return
			}
			payloadBytes, _ := json.Marshal(body)
			var res *sdk.ApprovalResult
			err := withClient(token, func(client *sdk.Client, approvalToken string) error {
				var callErr error
				res, callErr = client.ApprovalAction(r.Context(), taskID, payloadBytes, approvalToken)
				return callErr
			})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, res)
			return
		}
	}

	// ── Admin: invite a passkey user ──────────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/admin/passkey/invite" {
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		req := sdk.PasskeyInviteRequest{DisplayName: strings.TrimSpace(toString(body["display_name"]))}
		if exp, ok := toUint64(body["expires_in_seconds"]); ok {
			req.ExpiresInSeconds = int(exp)
		}
		var res *sdk.PasskeyInviteResult
		err := withClient("", func(client *sdk.Client, _ string) error {
			var innerErr error
			res, innerErr = client.InvitePasskeyUser(r.Context(), req)
			return innerErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	// ── Admin: list passkey users ─────────────────────────────────────────────
	if r.Method == http.MethodGet && r.URL.Path == "/api/admin/passkey/users" {
		query := r.URL.Query()
		page, _ := strconv.Atoi(query.Get("page"))
		limit, _ := strconv.Atoi(query.Get("limit"))
		var res *sdk.PasskeyUsersResult
		err := withClient("", func(client *sdk.Client, _ string) error {
			var innerErr error
			res, innerErr = client.ListPasskeyUsers(r.Context(), page, limit)
			return innerErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	// ── Passkey registration: options + verify (proxy invite flow) ────────────
	if r.Method == http.MethodGet && r.URL.Path == "/api/passkey/register/options" {
		token := strings.TrimSpace(r.URL.Query().Get("token"))
		if token == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "token is required"})
			return
		}
		var res *sdk.PasskeyRegistrationOptionsResult
		err := withClient("", func(client *sdk.Client, _ string) error {
			var innerErr error
			res, innerErr = client.PasskeyRegistrationOptions(r.Context(), token)
			return innerErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/passkey/register/verify" {
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		token := toString(body["invite_token"])
		if token == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invite_token is required"})
			return
		}
		var res *sdk.PasskeyRegistrationVerifyResult
		err := withClient("", func(client *sdk.Client, _ string) error {
			var innerErr error
			res, innerErr = client.PasskeyRegistrationVerify(r.Context(), token, body["credential"])
			return innerErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	// ── Admin: get / upsert permission policy ────────────────────────────────
	if r.Method == http.MethodGet && r.URL.Path == "/api/admin/policy" {
		keyName := strings.TrimSpace(r.URL.Query().Get("public_key_name"))
		if keyName == "" {
			keyName = "default"
		}
		var res *sdk.PolicyResult
		err := withClient("", func(client *sdk.Client, _ string) error {
			var innerErr error
			res, innerErr = client.GetPermissionPolicy(r.Context(), keyName)
			return innerErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}
	if r.Method == http.MethodPut && r.URL.Path == "/api/admin/policy" {
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		req := sdk.PolicyRequest{
			PublicKeyName: strings.TrimSpace(toString(body["public_key_name"])),
			Enabled:       true,
		}
		if req.PublicKeyName == "" {
			req.PublicKeyName = "default"
		}
		if enabled, ok := body["enabled"].(bool); ok {
			req.Enabled = enabled
		}
		if to, ok := toUint64(body["timeout_seconds"]); ok {
			req.TimeoutSeconds = int(to)
		}
		if rawLevels, ok := body["levels"].([]interface{}); ok {
			for _, lv := range rawLevels {
				m, _ := lv.(map[string]interface{})
				if m == nil {
					continue
				}
				lvl := sdk.PolicyLevel{}
				if li, ok := toUint64(m["level_index"]); ok {
					lvl.LevelIndex = int(li)
				}
				if th, ok := toUint64(m["threshold"]); ok {
					lvl.Threshold = int(th)
				}
				if rawMembers, ok := m["member_ids"].([]interface{}); ok {
					for _, mid := range rawMembers {
						if id, ok := toUint64(mid); ok {
							lvl.MemberIDs = append(lvl.MemberIDs, uint(id))
						}
					}
				}
				req.Levels = append(req.Levels, lvl)
			}
		}
		var res *sdk.AdminResult
		err := withClient("", func(client *sdk.Client, _ string) error {
			var innerErr error
			res, innerErr = client.UpsertPermissionPolicy(r.Context(), req)
			return innerErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	if r.Method == http.MethodGet && r.URL.Path == "/api/requests/mine" {
		token := s.sessionToken(state)
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "not logged in for this browser session"})
			return
		}
		mine, err := getMyRequestsFromService(s.serviceURL, token)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"requests": mine,
			},
		})
		return
	}

	writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "API endpoint not found"})
}

func (s *server) sessionToken(state *sessionState) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if state != nil && strings.TrimSpace(state.ApprovalToken) != "" {
		return strings.TrimSpace(state.ApprovalToken)
	}
	return s.bootstrapToken
}

func (s *server) ensureSessionID(w http.ResponseWriter, r *http.Request) string {
	rawHeader := strings.TrimSpace(r.Header.Get("X-Demo-Session"))
	if rawHeader != "" && demoSessionPattern.MatchString(rawHeader) {
		s.mu.Lock()
		if _, ok := s.sessions[rawHeader]; !ok {
			s.sessions[rawHeader] = &sessionState{ApprovalToken: s.bootstrapToken}
		}
		s.mu.Unlock()
		return rawHeader
	}

	if c, err := r.Cookie("demo_sid"); err == nil {
		sid := strings.TrimSpace(c.Value)
		if sid != "" {
			s.mu.Lock()
			if _, ok := s.sessions[sid]; !ok {
				s.sessions[sid] = &sessionState{ApprovalToken: s.bootstrapToken}
			}
			s.mu.Unlock()
			return sid
		}
	}

	sid := randomSessionID()
	http.SetCookie(w, &http.Cookie{
		Name:     "demo_sid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400,
		SameSite: http.SameSiteLaxMode,
	})
	s.mu.Lock()
	s.sessions[sid] = &sessionState{ApprovalToken: s.bootstrapToken}
	s.mu.Unlock()
	return sid
}

func (s *server) getSession(sid string) *sessionState {
	s.mu.RLock()
	state := s.sessions[sid]
	s.mu.RUnlock()
	if state != nil {
		return state
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[sid] == nil {
		s.sessions[sid] = &sessionState{ApprovalToken: s.bootstrapToken}
	}
	return s.sessions[sid]
}

func (s *server) serveStatic(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Path
	if target == "/" {
		target = "/index.html"
	}
	clean := filepath.Clean(strings.TrimPrefix(target, "/"))
	full := filepath.Join(s.frontendDir, clean)
	if !strings.HasPrefix(full, s.frontendDir) {
		http.NotFound(w, r)
		return
	}
	if st, err := os.Stat(full); err == nil && !st.IsDir() {
		http.ServeFile(w, r, full)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.frontendDir, "index.html"))
}

func detectFrontendDir() string {
	if custom := strings.TrimSpace(os.Getenv("DEMO_FRONTEND_DIR")); custom != "" {
		return custom
	}
	candidates := []string{
		filepath.Join(".", "passkey-web-demo", "frontend"),
		filepath.Join(".", "frontend"),
	}
	for _, dir := range candidates {
		if st, err := os.Stat(filepath.Join(dir, "index.html")); err == nil && !st.IsDir() {
			return dir
		}
	}
	return filepath.Join(".", "passkey-web-demo", "frontend")
}

func writeJSON(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func decodeJSON(body io.ReadCloser, out interface{}) error {
	defer body.Close()
	dec := json.NewDecoder(body)
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return err
	}
	return nil
}

func buildSignMessageBytes(body map[string]interface{}) ([]byte, error) {
	if rawPayload, ok := body["payload"]; ok && rawPayload != nil {
		switch payload := rawPayload.(type) {
		case string:
			payload = strings.TrimSpace(payload)
			if payload == "" {
				return nil, fmt.Errorf("payload is empty")
			}
			return []byte(payload), nil
		default:
			out, err := json.Marshal(payload)
			if err != nil {
				return nil, fmt.Errorf("invalid payload")
			}
			return out, nil
		}
	}

	message := strings.TrimSpace(toString(body["message"]))
	if message == "" {
		return nil, fmt.Errorf("payload or message is required")
	}
	return []byte(message), nil
}

func extractHashFromApprovalRecord(row map[string]interface{}) string {
	hash := normalizeHash(toString(row["hash"]))
	if hash != "" {
		return hash
	}
	hash = normalizeHash(toString(row["message_hash"]))
	if hash != "" {
		return hash
	}
	hash = normalizeHash(toString(row["digest"]))
	if hash != "" {
		return hash
	}

	payload := row["payload"]
	if m, ok := payload.(map[string]interface{}); ok {
		hash = normalizeHash(toString(m["hash"]))
		if hash == "" {
			hash = normalizeHash(toString(m["message_hash"]))
		}
		if hash == "" {
			hash = normalizeHash(toString(m["digest"]))
		}
		if hash != "" {
			return hash
		}
	}
	if raw, ok := payload.(string); ok && strings.TrimSpace(raw) != "" {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &m); err == nil {
			hash = normalizeHash(toString(m["hash"]))
			if hash == "" {
				hash = normalizeHash(toString(m["message_hash"]))
			}
			if hash == "" {
				hash = normalizeHash(toString(m["digest"]))
			}
			if hash != "" {
				return hash
			}
		}
	}
	return ""
}

func normalizeHash(v string) string {
	s := strings.TrimSpace(strings.ToLower(v))
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 64 {
		return ""
	}
	for _, ch := range s {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return ""
		}
	}
	return "0x" + s
}

func matchUintPath(path, prefix, suffix string) (uint64, bool) {
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return 0, false
	}
	mid := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	if mid == "" || strings.Contains(mid, "/") {
		return 0, false
	}
	v, err := strconv.ParseUint(mid, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func marshalAny(v interface{}) ([]byte, error) {
	if v == nil {
		return []byte(`{}`), nil
	}
	return json.Marshal(v)
}

func toUint64(v interface{}) (uint64, bool) {
	switch n := v.(type) {
	case float64:
		if n <= 0 || math.IsNaN(n) || math.IsInf(n, 0) {
			return 0, false
		}
		return uint64(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil || i <= 0 {
			return 0, false
		}
		return uint64(i), true
	case int:
		if n <= 0 {
			return 0, false
		}
		return uint64(n), true
	case int64:
		if n <= 0 {
			return 0, false
		}
		return uint64(n), true
	case uint64:
		if n == 0 {
			return 0, false
		}
		return n, true
	case string:
		u, err := strconv.ParseUint(strings.TrimSpace(n), 10, 64)
		if err != nil || u == 0 {
			return 0, false
		}
		return u, true
	default:
		return 0, false
	}
}

func toString(v interface{}) string {
	s, _ := stringValue(v)
	return s
}

func stringValue(v interface{}) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	return strings.TrimSpace(s), true
}

func randomSessionID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func getMyRequestsFromService(serviceURL, token string) ([]map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(serviceURL, "/")+"/api/requests/mine", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := toString(body["error"])
		if msg == "" {
			msg = toString(body["message"])
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, errors.New(msg)
	}

	if requests, ok := asSliceMap(getNested(body, "data", "requests")); ok {
		return requests, nil
	}
	if requests, ok := asSliceMap(body["requests"]); ok {
		return requests, nil
	}
	if approvals, ok := asSliceMap(body["approvals"]); ok {
		return approvals, nil
	}
	return []map[string]interface{}{}, nil
}

func getRequestByTxFromService(serviceURL, token, txID string) (map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(serviceURL, "/")+"/api/signature/by-tx/"+url.PathEscape(strings.TrimSpace(txID)), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := toString(body["error"])
		if msg == "" {
			msg = toString(body["message"])
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, errors.New(msg)
	}

	if data, ok := body["data"].(map[string]interface{}); ok {
		return data, nil
	}
	return body, nil
}

func getNested(data map[string]interface{}, k1, k2 string) interface{} {
	first, ok := data[k1].(map[string]interface{})
	if !ok {
		return nil
	}
	return first[k2]
}

func asSliceMap(v interface{}) ([]map[string]interface{}, bool) {
	arr, ok := v.([]interface{})
	if !ok {
		return nil, false
	}
	out := make([]map[string]interface{}, 0, len(arr))
	for _, it := range arr {
		m, ok := it.(map[string]interface{})
		if ok {
			out = append(out, m)
		}
	}
	return out, true
}

func filterPendingApprovalsResult(res *sdk.ApprovalResult, appInstanceID, publicKeyName string) {
	if res == nil || !res.Success || res.Data == nil {
		return
	}
	appInstanceID = strings.TrimSpace(appInstanceID)
	publicKeyName = strings.TrimSpace(publicKeyName)
	if appInstanceID == "" && publicKeyName == "" {
		return
	}
	approvals, ok := asSliceMap(res.Data["approvals"])
	if !ok {
		return
	}

	filtered := make([]map[string]interface{}, 0, len(approvals))
	taskIDs := make(map[string]struct{}, len(approvals))
	for _, item := range approvals {
		if appInstanceID != "" {
			itemAppInstanceID := toString(item["app_instance_id"])
			if itemAppInstanceID != appInstanceID {
				continue
			}
		}
		if publicKeyName != "" {
			itemKeyName := toString(item["public_key_name"])
			if itemKeyName == "" {
				itemKeyName = toString(item["key_name"])
			}
			if itemKeyName != publicKeyName {
				continue
			}
		}
		filtered = append(filtered, item)
		if id, ok := toUint64(item["id"]); ok {
			taskIDs[strconv.FormatUint(id, 10)] = struct{}{}
		}
	}
	res.Data["approvals"] = filtered
	res.Data["total"] = len(filtered)

	if levelProgress, ok := res.Data["level_progress"].(map[string]interface{}); ok {
		pruned := make(map[string]interface{}, len(filtered))
		for taskID := range taskIDs {
			if progress, exists := levelProgress[taskID]; exists {
				pruned[taskID] = progress
			}
		}
		res.Data["level_progress"] = pruned
	}
}
