package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openclaw-wallet/chain"
	"openclaw-wallet/model"
)

// BalanceHandler handles on-chain balance queries.
type BalanceHandler struct {
	db *gorm.DB
}

func NewBalanceHandler(db *gorm.DB) *BalanceHandler {
	return &BalanceHandler{db: db}
}

// GetBalance queries the chain RPC for the wallet's current balance.
// GET /api/wallets/:id/balance
func (h *BalanceHandler) GetBalance(c *gin.Context) {
	wallet, ok := loadUserWallet(c, h.db)
	if !ok {
		return
	}
	if wallet.Status != "ready" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "wallet not ready"})
		return
	}

	cfg, ok2 := model.Chains[wallet.Chain]
	if !ok2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported chain: " + wallet.Chain})
		return
	}

	result, balErr := chain.GetBalance(cfg.Family, wallet.Address, cfg.RPCURL)
	if balErr != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": balErr.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": result})
}
