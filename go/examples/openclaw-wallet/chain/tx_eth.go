package chain

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const ethDefaultGasLimit = uint64(21000)

// encodeAddrAmountCalldata is the shared body of EncodeERC20Transfer and EncodeERC20Approve.
// It builds 4-byte selector ++ ABI-encoded (address, uint256) calldata.
func encodeAddrAmountCalldata(funcSig string, targetAddr string, amount *big.Int) []byte {
	selector := crypto.Keccak256([]byte(funcSig))[:4]

	addr := common.HexToAddress(targetAddr)
	paddedAddr := make([]byte, 32)
	copy(paddedAddr[12:], addr.Bytes())

	paddedAmount := make([]byte, 32)
	amountBytes := amount.Bytes()
	copy(paddedAmount[32-len(amountBytes):], amountBytes)

	calldata := make([]byte, 0, 4+32+32)
	calldata = append(calldata, selector...)
	calldata = append(calldata, paddedAddr...)
	calldata = append(calldata, paddedAmount...)
	return calldata
}

// EncodeERC20Transfer encodes a ERC-20 transfer(address,uint256) call.
// Returns the ABI-encoded calldata without any 0x prefix.
func EncodeERC20Transfer(toAddr string, amount *big.Int) []byte {
	return encodeAddrAmountCalldata("transfer(address,uint256)", toAddr, amount)
}

// EncodeERC20Approve encodes a ERC-20 approve(address,uint256) call.
func EncodeERC20Approve(spenderAddr string, amount *big.Int) []byte {
	return encodeAddrAmountCalldata("approve(address,uint256)", spenderAddr, amount)
}

// ETHTxParams contains all fields needed to reconstruct and broadcast an ETH transaction after signing.
type ETHTxParams struct {
	Nonce    uint64 `json:"nonce"`
	GasPrice string `json:"gas_price"` // Wei, decimal string
	GasLimit uint64 `json:"gas_limit"`
	ChainID  string `json:"chain_id"`  // decimal string
	From     string `json:"from"`
	To       string `json:"to"`
	Value    string `json:"value"`          // Wei, decimal string
	Data     string `json:"data,omitempty"` // hex-encoded calldata (optional, e.g. ERC-20)
}

// ETHTxData is returned by BuildETHTx.
type ETHTxData struct {
	Params      ETHTxParams
	SigningHash []byte // 32-byte EIP-155 signing hash
}

// ethChainParams holds common chain parameters fetched before building a transaction.
type ethChainParams struct {
	nonce    uint64
	gasPrice *big.Int
	chainID  *big.Int
}

// fetchETHChainParams queries nonce, gas price, and chain ID in three sequential RPC calls.
// All three results are validated — any unexpected response type returns an error.
func fetchETHChainParams(rpcURL, fromAddr string) (*ethChainParams, error) {
	// Query nonce.
	nonceRaw, err := jsonRPC(rpcURL, map[string]interface{}{
		"jsonrpc": "2.0", "method": "eth_getTransactionCount",
		"params": []interface{}{fromAddr, "pending"}, "id": 1,
	})
	if err != nil {
		return nil, fmt.Errorf("get nonce: %w", err)
	}
	nonceHex, ok := nonceRaw["result"].(string)
	if !ok || nonceHex == "" {
		return nil, fmt.Errorf("unexpected nonce response: %v", nonceRaw["result"])
	}
	nonceInt := new(big.Int)
	nonceInt.SetString(strings.TrimPrefix(nonceHex, "0x"), 16)

	// Query gas price.
	gasPriceRaw, err := jsonRPC(rpcURL, map[string]interface{}{
		"jsonrpc": "2.0", "method": "eth_gasPrice", "params": []interface{}{}, "id": 1,
	})
	if err != nil {
		return nil, fmt.Errorf("get gas price: %w", err)
	}
	gasPriceHex, ok := gasPriceRaw["result"].(string)
	if !ok || gasPriceHex == "" {
		return nil, fmt.Errorf("unexpected gas price response: %v", gasPriceRaw["result"])
	}
	gasPrice := new(big.Int)
	gasPrice.SetString(strings.TrimPrefix(gasPriceHex, "0x"), 16)

	// Query chain ID.
	chainIDRaw, err := jsonRPC(rpcURL, map[string]interface{}{
		"jsonrpc": "2.0", "method": "eth_chainId", "params": []interface{}{}, "id": 1,
	})
	if err != nil {
		return nil, fmt.Errorf("get chain id: %w", err)
	}
	chainIDHex, ok := chainIDRaw["result"].(string)
	if !ok || chainIDHex == "" {
		return nil, fmt.Errorf("unexpected chain id response: %v", chainIDRaw["result"])
	}
	chainID := new(big.Int)
	chainID.SetString(strings.TrimPrefix(chainIDHex, "0x"), 16)

	return &ethChainParams{
		nonce:    nonceInt.Uint64(),
		gasPrice: gasPrice,
		chainID:  chainID,
	}, nil
}

// BuildETHTx queries the chain and constructs a legacy ETH transfer transaction.
// Returns the signing hash and all parameters needed to assemble the signed tx later.
func BuildETHTx(rpcURL, fromAddr, toAddr string, amountETH *big.Float) (*ETHTxData, error) {
	if rpcURL == "" {
		return nil, fmt.Errorf("ETH_RPC_URL is not configured")
	}

	// Convert ETH → Wei.
	e18 := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	weiF := new(big.Float).SetPrec(256).Mul(amountETH, new(big.Float).SetInt(e18))
	wei, _ := weiF.Int(nil)
	if wei.Sign() <= 0 {
		return nil, fmt.Errorf("amount must be positive")
	}

	cp, err := fetchETHChainParams(rpcURL, fromAddr)
	if err != nil {
		return nil, err
	}

	toAddress := common.HexToAddress(toAddr)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    cp.nonce,
		GasPrice: cp.gasPrice,
		Gas:      ethDefaultGasLimit,
		To:       &toAddress,
		Value:    wei,
	})

	signer := types.NewEIP155Signer(cp.chainID)
	sigHash := signer.Hash(tx)

	return &ETHTxData{
		Params: ETHTxParams{
			Nonce:    cp.nonce,
			GasPrice: cp.gasPrice.String(),
			GasLimit: ethDefaultGasLimit,
			ChainID:  cp.chainID.String(),
			From:     fromAddr,
			To:       toAddr,
			Value:    wei.String(),
		},
		SigningHash: sigHash[:],
	}, nil
}

// RebuildETHTx refreshes the nonce and gas price of a previously-built ETH transaction.
// All other fields (To, Value, GasLimit, Data, ChainID) are preserved from params.
// Used at approval time to avoid stale-nonce broadcast failures.
func RebuildETHTx(rpcURL string, params ETHTxParams) (*ETHTxData, error) {
	if rpcURL == "" {
		return nil, fmt.Errorf("ETH_RPC_URL is not configured")
	}
	cp, err := fetchETHChainParams(rpcURL, params.From)
	if err != nil {
		return nil, fmt.Errorf("refresh chain params: %w", err)
	}

	chainID, _ := new(big.Int).SetString(params.ChainID, 10)
	value, _ := new(big.Int).SetString(params.Value, 10)

	var txData []byte
	if params.Data != "" {
		txData, _ = hex.DecodeString(strings.TrimPrefix(params.Data, "0x"))
	}

	toAddr := common.HexToAddress(params.To)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    cp.nonce,
		GasPrice: cp.gasPrice,
		Gas:      params.GasLimit,
		To:       &toAddr,
		Value:    value,
		Data:     txData,
	})

	signer := types.NewEIP155Signer(chainID)
	sigHash := signer.Hash(tx)

	return &ETHTxData{
		Params: ETHTxParams{
			Nonce:    cp.nonce,
			GasPrice: cp.gasPrice.String(),
			GasLimit: params.GasLimit,
			ChainID:  params.ChainID,
			From:     params.From,
			To:       params.To,
			Value:    params.Value,
			Data:     params.Data,
		},
		SigningHash: sigHash[:],
	}, nil
}

// AssembleAndBroadcastETH applies a TEE ECDSA signature to an ETH transaction and broadcasts it.
// sig must be at least 64 bytes (r||s). The recovery id v is determined by trying both 0 and 1
// and checking which recovers the expected fromAddr.
func AssembleAndBroadcastETH(rpcURL string, params ETHTxParams, sig []byte, fromAddr string) (string, error) {
	if len(sig) < 64 {
		return "", fmt.Errorf("signature too short: %d bytes (need 64)", len(sig))
	}

	gasPrice, _ := new(big.Int).SetString(params.GasPrice, 10)
	chainID, _ := new(big.Int).SetString(params.ChainID, 10)
	value, _ := new(big.Int).SetString(params.Value, 10)

	toAddr := common.HexToAddress(params.To)
	fromAddress := common.HexToAddress(fromAddr)

	var txData []byte
	if params.Data != "" {
		var decodeErr error
		txData, decodeErr = hex.DecodeString(strings.TrimPrefix(params.Data, "0x"))
		if decodeErr != nil {
			return "", fmt.Errorf("invalid calldata hex in tx params: %w", decodeErr)
		}
	}

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    params.Nonce,
		GasPrice: gasPrice,
		Gas:      params.GasLimit,
		To:       &toAddr,
		Value:    value,
		Data:     txData,
	})

	signer := types.NewEIP155Signer(chainID)
	sigHash := signer.Hash(tx)

	// Try both recovery values to find the one matching fromAddr.
	var signedTx *types.Transaction
	for v := byte(0); v <= 1; v++ {
		sig65 := make([]byte, 65)
		copy(sig65, sig[:64])
		sig65[64] = v
		pub, err := crypto.SigToPub(sigHash[:], sig65)
		if err != nil {
			continue
		}
		if crypto.PubkeyToAddress(*pub) == fromAddress {
			signedTx, err = tx.WithSignature(signer, sig65)
			if err != nil {
				return "", fmt.Errorf("apply signature: %w", err)
			}
			break
		}
	}
	if signedTx == nil {
		return "", fmt.Errorf("could not determine valid recovery id for address %s", fromAddr)
	}

	rawBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("marshal tx: %w", err)
	}

	result, err := jsonRPC(rpcURL, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_sendRawTransaction",
		"params":  []interface{}{"0x" + hex.EncodeToString(rawBytes)},
		"id":      1,
	})
	if err != nil {
		return "", fmt.Errorf("broadcast: %w", err)
	}
	txHash, _ := result["result"].(string)
	return txHash, nil
}

// BuildETHContractCallTx builds a contract call transaction (e.g. ERC-20 transfer).
// value is optional (nil = 0), callData is the ABI-encoded call.
// Gas limit is estimated via eth_estimateGas with a 20% buffer.
func BuildETHContractCallTx(rpcURL, fromAddr, contractAddr string, callData []byte, value *big.Int) (*ETHTxData, error) {
	if rpcURL == "" {
		return nil, fmt.Errorf("ETH_RPC_URL is not configured")
	}
	if value == nil {
		value = big.NewInt(0)
	}

	cp, err := fetchETHChainParams(rpcURL, fromAddr)
	if err != nil {
		return nil, err
	}

	// Estimate gas via eth_estimateGas.
	estimateRaw, err := jsonRPC(rpcURL, map[string]interface{}{
		"jsonrpc": "2.0", "method": "eth_estimateGas",
		"params": []interface{}{map[string]interface{}{
			"from":  fromAddr,
			"to":    contractAddr,
			"value": "0x" + value.Text(16),
			"data":  "0x" + hex.EncodeToString(callData),
		}},
		"id": 1,
	})
	if err != nil {
		return nil, fmt.Errorf("estimate gas: %w", err)
	}
	estimateHex, ok := estimateRaw["result"].(string)
	if !ok || estimateHex == "" {
		return nil, fmt.Errorf("unexpected gas estimate response: %v", estimateRaw["result"])
	}
	estimatedGas := new(big.Int)
	estimatedGas.SetString(strings.TrimPrefix(estimateHex, "0x"), 16)
	// Add 20% buffer.
	gasLimit := new(big.Int).Mul(estimatedGas, big.NewInt(120))
	gasLimit.Div(gasLimit, big.NewInt(100))

	toAddress := common.HexToAddress(contractAddr)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    cp.nonce,
		GasPrice: cp.gasPrice,
		Gas:      gasLimit.Uint64(),
		To:       &toAddress,
		Value:    value,
		Data:     callData,
	})

	signer := types.NewEIP155Signer(cp.chainID)
	sigHash := signer.Hash(tx)

	return &ETHTxData{
		Params: ETHTxParams{
			Nonce:    cp.nonce,
			GasPrice: cp.gasPrice.String(),
			GasLimit: gasLimit.Uint64(),
			ChainID:  cp.chainID.String(),
			From:     fromAddr,
			To:       contractAddr,
			Value:    value.String(),
			Data:     hex.EncodeToString(callData),
		},
		SigningHash: sigHash[:],
	}, nil
}
