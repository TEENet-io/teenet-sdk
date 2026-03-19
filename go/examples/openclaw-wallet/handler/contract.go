package handler

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	sdk "github.com/TEENet-io/teenet-sdk/go"
	"gorm.io/gorm"

	"openclaw-wallet/model"
)

// ContractHandler manages the per-wallet ERC-20 contract whitelist.
type ContractHandler struct {
	db  *gorm.DB
	sdk *sdk.Client
}

func NewContractHandler(db *gorm.DB, sdkClient *sdk.Client) *ContractHandler {
	return &ContractHandler{db: db, sdk: sdkClient}
}

// AddContract whitelists a contract address for a wallet.
// Passkey: applied immediately.
// API key: creates a pending approval for the passkey owner to review.
// POST /api/wallets/:id/contracts  (dual auth)
func (h *ContractHandler) AddContract(c *gin.Context) {
	wallet, ok := loadUserWallet(c, h.db)
	if !ok {
		return
	}

	var req struct {
		LoginSessionID  uint64      `json:"login_session_id"`
		Credential      interface{} `json:"credential"`
		ContractAddress string      `json:"contract_address" binding:"required"`
		Label           string      `json:"label"`
		Symbol          string      `json:"symbol"`
		Decimals        int         `json:"decimals"`
		AllowedMethods  string      `json:"allowed_methods"`
		AutoApprove     bool        `json:"auto_approve"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Normalize and validate address.
	addr, addrErr := normalizeEVMAddress(req.ContractAddress)
	if addrErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract_address " + addrErr.Error()})
		return
	}
	if addr == "0x"+strings.Repeat("0", 40) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "zero address is not a valid contract"})
		return
	}

	proposed := model.AllowedContract{
		WalletID:        wallet.ID,
		ContractAddress: addr,
		Label:           req.Label,
		Symbol:          strings.ToUpper(strings.TrimSpace(req.Symbol)),
		Decimals:        req.Decimals,
		AllowedMethods:  strings.ToLower(strings.TrimSpace(req.AllowedMethods)),
		AutoApprove:     req.AutoApprove,
	}

	// API key path: create approval request.
	if !isPasskeyAuth(c) {
		approval, created := createPendingApproval(h.db, c, wallet.ID, "contract_add", proposed)
		if !created {
			return
		}
		writeAuditCtx(h.db, c, "contract_add", "pending", &wallet.ID, map[string]interface{}{
			"contract": addr, "symbol": proposed.Symbol, "approval_id": approval.ID,
		})
		c.JSON(http.StatusAccepted, gin.H{
			"success":     true,
			"pending":     true,
			"approval_id": approval.ID,
			"message":     "Contract whitelist request submitted for approval",
		})
		return
	}

	// Passkey path: require a fresh hardware assertion before applying.
	if !verifyFreshPasskeyParsed(h.sdk, c, req.LoginSessionID, req.Credential) {
		return
	}

	if err := h.db.Create(&proposed).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(err.Error(), "UNIQUE") {
			c.JSON(http.StatusConflict, gin.H{"error": "contract already whitelisted for this wallet"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	writeAuditCtx(h.db, c, "contract_add", "success", &wallet.ID, map[string]interface{}{
		"contract": addr, "symbol": proposed.Symbol,
	})
	c.JSON(http.StatusOK, gin.H{"success": true, "contract": proposed})
}

// ListContracts returns all whitelisted contracts for a wallet.
// GET /api/wallets/:id/contracts  (dual auth)
func (h *ContractHandler) ListContracts(c *gin.Context) {
	wallet, ok := loadUserWallet(c, h.db)
	if !ok {
		return
	}

	var contracts []model.AllowedContract
	if err := h.db.Where("wallet_id = ?", wallet.ID).Order("created_at asc").Find(&contracts).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "contracts": contracts})
}

// DeleteContract removes a whitelisted contract.
// DELETE /api/wallets/:id/contracts/:cid  (Passkey only)
func (h *ContractHandler) DeleteContract(c *gin.Context) {
	if !verifyFreshPasskey(h.sdk, c) {
		return
	}
	wallet, ok := loadUserWallet(c, h.db)
	if !ok {
		return
	}

	cid, err := strconv.ParseUint(c.Param("cid"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid contract id"})
		return
	}

	var contract model.AllowedContract
	if err := h.db.Where("id = ? AND wallet_id = ?", cid, wallet.ID).First(&contract).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	if err := h.db.Delete(&contract).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

