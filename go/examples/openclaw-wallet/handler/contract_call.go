package handler

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	sdk "github.com/TEENet-io/teenet-sdk/go"
	"gorm.io/gorm"

	"openclaw-wallet/chain"
	"openclaw-wallet/model"
)

// highRiskMethods always require Passkey approval, even when AutoApprove=true on the contract.
var highRiskMethods = map[string]bool{
	"approve":           true,
	"increaseallowance": true,
	"setapprovalforall": true,
	"transferfrom":      true,
	"safetransferfrom":  true,
}

// ContractCallHandler handles general-purpose smart contract calls.
type ContractCallHandler struct {
	db      *gorm.DB
	sdk     *sdk.Client
	baseURL string
}

func NewContractCallHandler(db *gorm.DB, sdkClient *sdk.Client, baseURL string) *ContractCallHandler {
	return &ContractCallHandler{db: db, sdk: sdkClient, baseURL: baseURL}
}

// ContractCallRequest is the body for POST /api/wallets/:id/contract-call.
type ContractCallRequest struct {
	Contract string        `json:"contract" binding:"required"`
	FuncSig  string        `json:"func_sig" binding:"required"`
	Args     []interface{} `json:"args"`
	Value    string        `json:"value"` // ETH to send (optional, in ETH units)
	Memo     string        `json:"memo"`
}

// ContractCall executes a smart contract call with three-layer security:
//  1. Contract address whitelist
//  2. Per-contract method restriction
//  3. Approval policy / high-risk method gate
//
// POST /api/wallets/:id/contract-call
func (h *ContractCallHandler) ContractCall(c *gin.Context) {
	// Load and validate wallet.
	wallet, ok := loadUserWallet(c, h.db)
	if !ok {
		return
	}
	if wallet.Status != "ready" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "wallet is not ready (status: " + wallet.Status + ")"})
		return
	}

	chainCfg, cfgOk := model.Chains[wallet.Chain]
	if !cfgOk || chainCfg.Family != "evm" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract calls are only supported on EVM chains"})
		return
	}

	var req ContractCallRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Normalize contract address.
	contractAddr, addrErr := normalizeEVMAddress(req.Contract)
	if addrErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract: " + addrErr.Error()})
		return
	}

	// Layer 1: Whitelist check.
	var allowed model.AllowedContract
	if err := h.db.Where("wallet_id = ? AND contract_address = ?", wallet.ID, contractAddr).First(&allowed).Error; err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "contract not whitelisted: " + contractAddr})
		return
	}

	// Extract method name from func_sig (everything before the first "(").
	methodName := extractMethodName(req.FuncSig)
	methodNameLower := strings.ToLower(methodName)

	// Layer 2: Method restriction — if AllowedMethods is set, method must be in the list.
	if allowed.AllowedMethods != "" {
		methodAllowed := false
		for _, m := range strings.Split(allowed.AllowedMethods, ",") {
			if strings.TrimSpace(strings.ToLower(m)) == methodNameLower {
				methodAllowed = true
				break
			}
		}
		if !methodAllowed {
			c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("method %q is not in the allowed methods list for this contract", methodName)})
			return
		}
	}

	// Encode calldata (validation only — no RPC yet).
	calldata, encErr := chain.EncodeCall(req.FuncSig, req.Args)
	if encErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "encode calldata: " + encErr.Error()})
		return
	}

	// Parse optional ETH value (ETH → Wei).
	var valueWei *big.Int
	if req.Value != "" {
		ethVal, ok2 := new(big.Float).SetString(req.Value)
		if !ok2 || ethVal.Sign() < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid value: must be a non-negative number in ETH"})
			return
		}
		if ethVal.Sign() > 0 {
			// 1 ETH = 1e18 Wei
			weiPerEth := new(big.Float).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
			weiF := new(big.Float).Mul(ethVal, weiPerEth)
			valueWei, _ = weiF.Int(nil)
		}
	}

	// Layer 3: Security decision (before RPC call to avoid unnecessary network round-trips).
	// Passkey auth: human is already present — proceed directly.
	// API Key auth: check high-risk methods and AutoApprove flag.
	needsApproval := false
	var approvalReason string

	if !isPasskeyAuth(c) {
		// API Key path.
		if highRiskMethods[methodNameLower] {
			needsApproval = true
			approvalReason = fmt.Sprintf("method %q is high-risk and requires passkey approval", methodName)
		} else if !allowed.AutoApprove {
			needsApproval = true
			approvalReason = "contract does not have auto-approve enabled; passkey approval required"
		}
	}

	// Also check value-based approval policy for payable calls carrying ETH.
	if !needsApproval && valueWei != nil && valueWei.Sign() > 0 && req.Value != "" {
		currency := chainCfg.Currency
		var policy model.ApprovalPolicy
		if h.db.Where("wallet_id = ? AND currency = ? AND enabled = ?", wallet.ID, currency, true).First(&policy).Error == nil {
			if exceedsThreshold(req.Value, policy.ThresholdAmount) {
				needsApproval = true
				approvalReason = fmt.Sprintf("value %s %s exceeds approval threshold %s", req.Value, currency, policy.ThresholdAmount)
			}
		}
	}

	// Build display context for both approval and direct paths.
	txContext := map[string]interface{}{
		"type":     "contract_call",
		"from":     wallet.Address,
		"contract": contractAddr,
		"method":   methodName,
		"func_sig": req.FuncSig,
		"memo":     req.Memo,
	}
	if req.Value != "" {
		txContext["value_eth"] = req.Value
	}

	if needsApproval {
		// For approval: store calldata hex and context; the approve endpoint will rebuild
		// the tx with fresh on-chain state (nonce) before signing, similar to /transfer.
		calldataHex := hex.EncodeToString(calldata)
		txContextJSON, _ := json.Marshal(txContext)

		// Store enough information in TxParams to allow the approve handler to reconstruct the tx.
		txParamsPreview, _ := json.Marshal(map[string]interface{}{
			"from":          wallet.Address,
			"contract":      contractAddr,
			"calldata_hex":  calldataHex,
			"value_wei":     func() string {
				if valueWei != nil {
					return valueWei.String()
				}
				return "0"
			}(),
			"rpc_url": chainCfg.RPCURL,
		})

		userID := mustUserID(c)
		approval := model.ApprovalRequest{
			WalletID:     wallet.ID,
			UserID:       userID,
			ApprovalType: "contract_call",
			Message:      calldataHex, // stored for reference; tx hash computed fresh on approve
			TxContext:    string(txContextJSON),
			TxParams:     string(txParamsPreview),
			Status:       "pending",
			CreatedAt:    time.Now(),
			ExpiresAt:    time.Now().Add(30 * time.Minute),
		}
		if err := h.db.Create(&approval).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "create approval request failed"})
			return
		}
		approvalURL := fmt.Sprintf("%s/#/approve/%d", requestBaseURL(c, h.baseURL), approval.ID)
		writeAuditCtx(h.db, c, "contract_call", "pending", &wallet.ID, map[string]interface{}{
			"contract": contractAddr, "method": methodName, "approval_id": approval.ID,
		})
		c.JSON(http.StatusAccepted, gin.H{
			"status":       "pending_approval",
			"approval_id":  approval.ID,
			"message":      approvalReason,
			"tx_context":   txContext,
			"approval_url": approvalURL,
		})
		return
	}

	// Direct path: build tx (hits RPC), sign via TEE, and broadcast.
	txData, buildErr := chain.BuildETHContractCallTx(chainCfg.RPCURL, wallet.Address, contractAddr, calldata, valueWei)
	if buildErr != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "build contract tx: " + buildErr.Error()})
		return
	}

	txParamsJSON, marshalErr := json.Marshal(txData.Params)
	if marshalErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "marshal tx params failed"})
		return
	}

	signingMsg := txData.SigningHash

	result, signErr := h.sdk.Sign(c.Request.Context(), signingMsg, wallet.KeyName)
	if signErr != nil || !result.Success {
		errMsg := "signing failed"
		if signErr != nil {
			errMsg = signErr.Error()
		} else if result != nil {
			errMsg = result.Error
		}
		c.JSON(http.StatusBadGateway, gin.H{"error": "signing failed: " + errMsg})
		return
	}

	txHash, broadcastErr := broadcastSigned(wallet, string(txParamsJSON), result.Signature)
	if broadcastErr != nil {
		respondBroadcastError(c, broadcastErr)
		return
	}

	writeAuditCtx(h.db, c, "contract_call", "success", &wallet.ID, map[string]interface{}{
		"contract": contractAddr, "method": methodName, "tx_hash": txHash,
	})
	c.JSON(http.StatusOK, gin.H{
		"status":         "completed",
		"tx_hash":        txHash,
		"chain":          wallet.Chain,
		"from":           wallet.Address,
		"contract":       contractAddr,
		"method":         methodName,
		"wallet_address": wallet.Address,
	})
}

// extractMethodName returns the function name portion of a Solidity func_sig.
// e.g. "transfer(address,uint256)" → "transfer"
func extractMethodName(funcSig string) string {
	idx := strings.Index(funcSig, "(")
	if idx <= 0 {
		return ""
	}
	return strings.TrimSpace(funcSig[:idx])
}
