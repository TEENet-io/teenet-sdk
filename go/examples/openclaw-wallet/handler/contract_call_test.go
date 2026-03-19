package handler_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openclaw-wallet/handler"
	"openclaw-wallet/model"
)

// contractCallRouter wires a minimal gin router for ContractCall tests.
func contractCallRouter(db *gorm.DB, userID uint, authMode string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := handler.NewContractCallHandler(db, nil, "http://localhost")
	injectUser := func(c *gin.Context) {
		c.Set("userID", userID)
		c.Set("authMode", authMode)
		c.Next()
	}
	r.Use(injectUser)
	r.POST("/wallets/:id/contract-call", h.ContractCall)
	return r
}

// seedWalletWithContract creates a user, an ethereum wallet, and a whitelisted contract.
func seedWalletWithContract(t *testing.T, db *gorm.DB, allowedMethods string, autoApprove bool) (model.User, model.Wallet, model.AllowedContract) {
	t.Helper()
	user, wallet := seedWallet(t, db)
	contract := model.AllowedContract{
		WalletID:        wallet.ID,
		ContractAddress: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		Symbol:          "USDC",
		Decimals:        6,
		AllowedMethods:  allowedMethods,
		AutoApprove:     autoApprove,
	}
	if err := db.Create(&contract).Error; err != nil {
		t.Fatalf("seed contract: %v", err)
	}
	return user, wallet, contract
}

// ─── TestContractCall_NotWhitelisted ─────────────────────────────────────────

func TestContractCall_NotWhitelisted(t *testing.T) {
	db := testDB(t)
	user, wallet := seedWallet(t, db)
	// No AllowedContract record created — contract is NOT whitelisted.

	r := contractCallRouter(db, user.ID, "passkey")
	body := jsonBody(map[string]interface{}{
		"contract": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		"func_sig": "transfer(address,uint256)",
		"args":     []interface{}{"0x1234567890123456789012345678901234567890", "1000"},
	})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/wallets/%d/contract-call", wallet.ID), body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-whitelisted contract, got %d: %s", w.Code, w.Body.String())
	}
}

// ─── TestContractCall_MethodNotAllowed ────────────────────────────────────────

func TestContractCall_MethodNotAllowed(t *testing.T) {
	db := testDB(t)
	// Contract is whitelisted but only allows "transfer".
	user, wallet, _ := seedWalletWithContract(t, db, "transfer", true)

	r := contractCallRouter(db, user.ID, "passkey")
	body := jsonBody(map[string]interface{}{
		"contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		"func_sig": "approve(address,uint256)",
		"args":     []interface{}{"0x1234567890123456789012345678901234567890", "1000"},
	})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/wallets/%d/contract-call", wallet.ID), body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed method, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] == nil {
		t.Error("expected error message in response")
	}
}

// ─── TestContractCall_HighRiskForceApproval_APIKey ────────────────────────────

func TestContractCall_HighRiskForceApproval_APIKey(t *testing.T) {
	db := testDB(t)
	// AutoApprove=true but method is high-risk → must still require approval via API Key.
	user, wallet, _ := seedWalletWithContract(t, db, "", true /* autoApprove */)

	r := contractCallRouter(db, user.ID, "apikey") // API key auth
	body := jsonBody(map[string]interface{}{
		"contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		"func_sig": "approve(address,uint256)",
		"args":     []interface{}{"0x1234567890123456789012345678901234567890", "1000000"},
	})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/wallets/%d/contract-call", wallet.ID), body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 pending approval for high-risk method via API Key, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "pending_approval" {
		t.Errorf("expected status=pending_approval, got %v", resp["status"])
	}
	if resp["approval_id"] == nil {
		t.Error("expected approval_id in response")
	}

	// Verify an ApprovalRequest was created in the DB.
	var count int64
	db.Model(&model.ApprovalRequest{}).Where("wallet_id = ? AND approval_type = ?", wallet.ID, "contract_call").Count(&count)
	if count != 1 {
		t.Errorf("expected 1 approval request in DB, got %d", count)
	}
}

// ─── TestContractCall_AutoApproveFalse_APIKey ─────────────────────────────────

func TestContractCall_AutoApproveFalse_APIKey(t *testing.T) {
	db := testDB(t)
	// Non-high-risk method but AutoApprove=false → API Key should get 202.
	user, wallet, _ := seedWalletWithContract(t, db, "", false /* autoApprove */)

	r := contractCallRouter(db, user.ID, "apikey")
	body := jsonBody(map[string]interface{}{
		"contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		"func_sig": "transfer(address,uint256)",
		"args":     []interface{}{"0x1234567890123456789012345678901234567890", "1000"},
	})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/wallets/%d/contract-call", wallet.ID), body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 pending approval when AutoApprove=false via API Key, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "pending_approval" {
		t.Errorf("expected status=pending_approval, got %v", resp["status"])
	}
}

// ─── TestContractCall_SolanaNotSupported ──────────────────────────────────────

func TestContractCall_SolanaNotSupported(t *testing.T) {
	db := testDB(t)
	n := dbCounter // use current counter for a unique key name
	_ = n
	user := model.User{Username: "soluser-cc"}
	db.Create(&user)
	wallet := model.Wallet{
		UserID:  user.ID,
		Chain:   "solana",
		KeyName: fmt.Sprintf("k-sol-cc-%d", n),
		Status:  "ready",
	}
	db.Create(&wallet)

	r := contractCallRouter(db, user.ID, "passkey")
	body := jsonBody(map[string]interface{}{
		"contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		"func_sig": "transfer(address,uint256)",
		"args":     []interface{}{"0x1234567890123456789012345678901234567890", "1000"},
	})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/wallets/%d/contract-call", wallet.ID), body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for Solana chain, got %d: %s", w.Code, w.Body.String())
	}
}

// ─── TestContractCall_WalletNotReady ──────────────────────────────────────────

func TestContractCall_WalletNotReady(t *testing.T) {
	db := testDB(t)
	user := model.User{Username: "notready-cc"}
	db.Create(&user)
	wallet := model.Wallet{
		UserID:  user.ID,
		Chain:   "ethereum",
		KeyName: "k-notready-cc",
		Status:  "creating",
	}
	db.Create(&wallet)

	r := contractCallRouter(db, user.ID, "passkey")
	body := jsonBody(map[string]interface{}{
		"contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		"func_sig": "transfer(address,uint256)",
		"args":     []interface{}{"0x1234567890123456789012345678901234567890", "1000"},
	})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/wallets/%d/contract-call", wallet.ID), body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-ready wallet, got %d: %s", w.Code, w.Body.String())
	}
}

// ─── TestContractCall_InvalidFuncSig ─────────────────────────────────────────

func TestContractCall_InvalidFuncSig(t *testing.T) {
	db := testDB(t)
	// Whitelist the contract first so we pass layer 1.
	user, wallet, _ := seedWalletWithContract(t, db, "", true)

	r := contractCallRouter(db, user.ID, "passkey")
	body := jsonBody(map[string]interface{}{
		"contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		"func_sig": "notavalidsignature", // missing parentheses
		"args":     []interface{}{},
	})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/wallets/%d/contract-call", wallet.ID), body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid func_sig, got %d: %s", w.Code, w.Body.String())
	}
}
