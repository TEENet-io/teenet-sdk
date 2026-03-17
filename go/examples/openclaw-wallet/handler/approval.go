package handler

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	sdk "github.com/TEENet-io/teenet-sdk/go"
	"gorm.io/gorm"

	"openclaw-wallet/chain"
	"openclaw-wallet/model"
)

// ApprovalHandler handles approval request lifecycle.
type ApprovalHandler struct {
	db  *gorm.DB
	sdk *sdk.Client
}

func NewApprovalHandler(db *gorm.DB, sdkClient *sdk.Client) *ApprovalHandler {
	return &ApprovalHandler{db: db, sdk: sdkClient}
}

// ListPending returns all pending approval requests for the current user.
// GET /api/approvals/pending
func (h *ApprovalHandler) ListPending(c *gin.Context) {
	userID := mustUserID(c)
	// Batch-expire all stale pending requests for this user in a single UPDATE.
	h.db.Model(&model.ApprovalRequest{}).
		Where("user_id = ? AND status = ? AND expires_at < ?", userID, "pending", time.Now()).
		Update("status", "expired")

	var pending []model.ApprovalRequest
	if err := h.db.Where("user_id = ? AND status = ?", userID, "pending").
		Order("created_at desc").Find(&pending).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "approvals": pending})
}

// GetApproval returns details and status of a single approval request.
// GET /api/approvals/:id
func (h *ApprovalHandler) GetApproval(c *gin.Context) {
	approval, ok := h.loadUserApproval(c)
	if !ok {
		return
	}
	// Auto-expire if needed.
	if approval.Status == "pending" && time.Now().After(approval.ExpiresAt) {
		h.db.Model(&approval).Update("status", "expired")
		approval.Status = "expired"
	}

	var txCtx interface{}
	_ = json.Unmarshal([]byte(approval.TxContext), &txCtx)

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"approval":   approval,
		"tx_context": txCtx,
	})
}

// Approve approves an approval request (Passkey session only).
// Requires a fresh WebAuthn assertion in the request body alongside the session token,
// so a stolen session token alone cannot approve a transaction.
// POST /api/approvals/:id/approve
func (h *ApprovalHandler) Approve(c *gin.Context) {
	// Verify a fresh passkey credential before doing anything sensitive.
	if !verifyFreshPasskey(h.sdk, c) {
		return
	}

	approval, ok := h.loadUserApproval(c)
	if !ok {
		return
	}
	if approval.Status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "approval is not pending (status: " + approval.Status + ")"})
		return
	}
	if time.Now().After(approval.ExpiresAt) {
		h.db.Model(&approval).Update("status", "expired")
		c.JSON(http.StatusBadRequest, gin.H{"error": "approval has expired"})
		return
	}

	// Contract whitelist approvals: add the contract and finish.
	if approval.ApprovalType == "contract_add" {
		var proposed model.AllowedContract
		if err := json.Unmarshal([]byte(approval.PolicyData), &proposed); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid contract data"})
			return
		}
		proposed.ID = 0 // let DB assign a new ID
		if err := h.db.Create(&proposed).Error; err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				// Already whitelisted — treat as success.
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add contract"})
				return
			}
		}
		approverPasskeyID := passkeyUserIDFromCtx(c)
		h.db.Model(&approval).Updates(map[string]interface{}{"status": "approved", "approved_by": approverPasskeyID})
		writeAuditCtx(h.db, c, "approval_approve", "success", &approval.WalletID, map[string]interface{}{
			"approval_id": approval.ID, "type": "contract_add", "contract": proposed.ContractAddress,
		})
		c.JSON(http.StatusOK, gin.H{"success": true, "status": "approved", "contract": proposed})
		return
	}

	// Policy change approvals: apply the proposed policy and finish.
	if approval.ApprovalType == "policy_change" {
		var proposed model.ApprovalPolicy
		if err := json.Unmarshal([]byte(approval.PolicyData), &proposed); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid policy data"})
			return
		}
		var policy model.ApprovalPolicy
		if h.db.Where("wallet_id = ? AND currency = ?", approval.WalletID, proposed.Currency).First(&policy).Error != nil {
			policy = model.ApprovalPolicy{WalletID: approval.WalletID, Currency: proposed.Currency}
		}
		policy.ThresholdAmount = proposed.ThresholdAmount
		policy.Enabled = proposed.Enabled
		policy.DailyLimit = proposed.DailyLimit
		if err := h.db.Save(&policy).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to apply policy"})
			return
		}
		approverPasskeyID := passkeyUserIDFromCtx(c)
		updates := map[string]interface{}{"status": "approved", "approved_by": approverPasskeyID}
		h.db.Model(&approval).Updates(updates)
		writeAuditCtx(h.db, c, "approval_approve", "success", &approval.WalletID, map[string]interface{}{
			"approval_id": approval.ID, "type": "policy_change",
			"currency": proposed.Currency, "threshold": proposed.ThresholdAmount,
		})
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"status":  "approved",
			"policy":  policy,
		})
		return
	}

	// Load wallet to get the key name.
	var wallet model.Wallet
	if err := h.db.First(&wallet, approval.WalletID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "wallet not found"})
		return
	}

	// Decode the original message.
	msgBytes, err := decodeMessage(approval.Message, "hex")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid stored message: " + err.Error()})
		return
	}

	// Rebuild the transaction with fresh chain state before signing.
	// - Solana: blockhash expires in ~60s
	// - ETH: nonce may have advanced since the approval was created (e.g. another tx was sent)
	txParamsToUse := approval.TxParams
	cfg, cfgOk := model.Chains[wallet.Chain]
	if cfgOk && approval.TxParams != "" {
		switch cfg.Family {
		case "solana":
			var solParams chain.SOLTxParams
			if jsonErr := json.Unmarshal([]byte(approval.TxParams), &solParams); jsonErr == nil {
				amountSOL := float64(solParams.Lamports) / 1e9
				if freshTx, buildErr := chain.BuildSOLTx(cfg.RPCURL, solParams.From, solParams.To, amountSOL); buildErr == nil {
					msgBytes = freshTx.MessageBytes
					if freshJSON, mErr := json.Marshal(freshTx.Params); mErr == nil {
						txParamsToUse = string(freshJSON)
					}
				}
			}
		case "evm":
			var ethParams chain.ETHTxParams
			if jsonErr := json.Unmarshal([]byte(approval.TxParams), &ethParams); jsonErr == nil {
				if freshTx, buildErr := chain.RebuildETHTx(cfg.RPCURL, ethParams); buildErr == nil {
					msgBytes = freshTx.SigningHash
					if freshJSON, mErr := json.Marshal(freshTx.Params); mErr == nil {
						txParamsToUse = string(freshJSON)
					}
				} else {
					log.Printf("[approve] ETH tx rebuild failed approval_id=%d: %v", approval.ID, buildErr)
				}
			}
		}
	}

	// Execute TEE signing now that approval is granted.
	result, signErr := h.sdk.Sign(c.Request.Context(), msgBytes, wallet.KeyName)
	if signErr != nil || !result.Success {
		errMsg := "signing failed"
		if signErr != nil {
			errMsg = signErr.Error()
		} else if result != nil {
			errMsg = result.Error
		}
		log.Printf("[approve] TEE signing failed approval_id=%d wallet_id=%d key=%s err=%s",
			approval.ID, wallet.ID, wallet.KeyName, errMsg)
		c.JSON(http.StatusBadGateway, gin.H{"error": "signing failed: " + errMsg})
		return
	}

	sig := "0x" + hex.EncodeToString(result.Signature)
	approverPasskeyID := passkeyUserIDFromCtx(c)

	// If TxParams is set, this was a /transfer approval: assemble and broadcast.
	var txHash string
	if txParamsToUse != "" {
		var broadcastErr error
		txHash, broadcastErr = broadcastSigned(wallet, txParamsToUse, result.Signature)
		if broadcastErr != nil {
			log.Printf("[approve] broadcast failed approval_id=%d wallet=%d addr=%s err=%v",
				approval.ID, wallet.ID, wallet.Address, broadcastErr)
			respondBroadcastError(c, broadcastErr)
			return
		}
	}

	updates := map[string]interface{}{
		"status":      "approved",
		"signature":   sig,
		"approved_by": approverPasskeyID,
	}
	if txHash != "" {
		updates["tx_hash"] = txHash
	}
	if err := h.db.Model(&approval).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update approval failed"})
		return
	}
	auditDetails := map[string]interface{}{"approval_id": approval.ID, "type": approval.ApprovalType}
	if txHash != "" {
		auditDetails["tx_hash"] = txHash
	}
	// Parse TxContext once; reuse for audit enrichment and daily-limit update below.
	var txCtx map[string]interface{}
	_ = json.Unmarshal([]byte(approval.TxContext), &txCtx)
	if txCtx != nil {
		if to, ok := txCtx["to"].(string); ok && to != "" {
			auditDetails["to"] = to
		}
		if amount, currency := extractAmountCurrency(txCtx); amount != "" {
			auditDetails["amount"] = amount
			auditDetails["currency"] = currency
		}
	}
	writeAuditCtx(h.db, c, "approval_approve", "success", &approval.WalletID, auditDetails)

	// Update daily spent counter for /transfer approvals that were successfully broadcast.
	if txHash != "" && txCtx != nil {
		amount, currency := extractAmountCurrency(txCtx)
		if amount != "" && currency != "" {
			var pol model.ApprovalPolicy
			if h.db.Where("wallet_id = ? AND currency = ? AND enabled = ?", approval.WalletID, currency, true).First(&pol).Error == nil {
				if pol.DailyLimit != "" {
					addDailySpent(h.db, &pol, amount)
				}
			}
		}
	}

	resp := gin.H{
		"success":        true,
		"status":         "approved",
		"signature":      sig,
		"wallet_address": wallet.Address,
		"chain":          wallet.Chain,
	}
	if txHash != "" {
		resp["tx_hash"] = txHash
	}
	c.JSON(http.StatusOK, resp)
}

// Reject rejects an approval request (Passkey session only).
// Also requires a fresh WebAuthn assertion to prevent session-token-only attacks.
// POST /api/approvals/:id/reject
func (h *ApprovalHandler) Reject(c *gin.Context) {
	if !verifyFreshPasskey(h.sdk, c) {
		return
	}

	approval, ok := h.loadUserApproval(c)
	if !ok {
		return
	}
	if approval.Status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "approval is not pending"})
		return
	}
	if err := h.db.Model(&approval).Update("status", "rejected").Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	writeAuditCtx(h.db, c, "approval_reject", "success", &approval.WalletID, map[string]interface{}{
		"approval_id": approval.ID, "type": approval.ApprovalType,
	})
	c.JSON(http.StatusOK, gin.H{"success": true, "status": "rejected"})
}

func (h *ApprovalHandler) loadUserApproval(c *gin.Context) (model.ApprovalRequest, bool) {
	userID := mustUserID(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid approval id"})
		return model.ApprovalRequest{}, false
	}
	var approval model.ApprovalRequest
	if err := h.db.First(&approval, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "approval not found"})
		return model.ApprovalRequest{}, false
	}
	if approval.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return model.ApprovalRequest{}, false
	}
	return approval, true
}

// verifyFreshPasskey reads {login_session_id, credential} from the request body and
// calls PasskeyLoginVerify to confirm a live hardware key assertion.
// Returns true if verification passes (c is NOT written to). Returns false and writes a
// 401/400 response if verification fails (caller must return immediately).
// When sdkClient is nil the check is skipped (test / offline mode only).
func verifyFreshPasskey(sdkClient *sdk.Client, c *gin.Context) bool {
	if sdkClient == nil {
		return true
	}
	var body struct {
		LoginSessionID uint64      `json:"login_session_id"`
		Credential     interface{} `json:"credential"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.LoginSessionID == 0 || body.Credential == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "login_session_id and credential are required for this action"})
		return false
	}
	return verifyFreshPasskeyParsed(sdkClient, c, body.LoginSessionID, body.Credential)
}

// verifyFreshPasskeyParsed verifies an already-parsed credential.
// Used by endpoints that carry both business fields and credential in a single JSON body.
// When sdkClient is nil the check is skipped (test / offline mode only).
func verifyFreshPasskeyParsed(sdkClient *sdk.Client, c *gin.Context, loginSessionID uint64, credential interface{}) bool {
	if sdkClient == nil {
		return true
	}
	if loginSessionID == 0 || credential == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "login_session_id and credential are required for this action"})
		return false
	}
	credBytes, err := json.Marshal(credential)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid credential"})
		return false
	}
	res, err := sdkClient.PasskeyLoginVerify(c.Request.Context(), loginSessionID, credBytes)
	if err != nil || !res.Success {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "passkey verification failed — please authenticate with your hardware key"})
		return false
	}
	return true
}

// passkeyUserIDFromCtx retrieves the PasskeyUserID from session context.
// This is stored when the passkey session was created in PasskeyVerify.
func passkeyUserIDFromCtx(c *gin.Context) *uint {
	v, exists := c.Get("userID")
	if !exists {
		return nil
	}
	userID, _ := v.(uint)
	return &userID
}
