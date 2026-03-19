package handler

import (
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"

	"openclaw-wallet/chain"
	"openclaw-wallet/model"
)

// CallReadRequest is the body for POST /api/wallets/:id/call-read.
type CallReadRequest struct {
	Contract string        `json:"contract" binding:"required"`
	FuncSig  string        `json:"func_sig" binding:"required"`
	Args     []interface{} `json:"args"`
}

// CallRead performs a read-only eth_call against a contract.
// No signing, no transaction, no approval needed.
// POST /api/wallets/:id/call-read
func (h *ContractCallHandler) CallRead(c *gin.Context) {
	wallet, ok := loadUserWallet(c, h.db)
	if !ok {
		return
	}

	chainCfg, cfgOk := model.Chains[wallet.Chain]
	if !cfgOk || chainCfg.Family != "evm" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "call-read is only supported on EVM chains"})
		return
	}

	var req CallReadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	contractAddr, addrErr := normalizeEVMAddress(req.Contract)
	if addrErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract: " + addrErr.Error()})
		return
	}

	calldata, encErr := chain.EncodeCall(req.FuncSig, req.Args)
	if encErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "encode calldata: " + encErr.Error()})
		return
	}

	result, callErr := chain.ETHCall(chainCfg.RPCURL, wallet.Address, contractAddr, calldata)
	if callErr != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "eth_call: " + callErr.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"result":   "0x" + hex.EncodeToString(result),
		"contract": contractAddr,
		"method":   extractMethodName(req.FuncSig),
	})
}
