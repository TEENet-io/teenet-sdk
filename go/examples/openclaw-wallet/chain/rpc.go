package chain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

// BalanceResult holds a balance query response.
type BalanceResult struct {
	Chain    string `json:"chain"`
	Address  string `json:"address"`
	Balance  string `json:"balance"`  // human-readable, e.g. "1.234"
	Currency string `json:"currency"` // "ETH", "SOL"
	Raw      string `json:"raw"`      // raw smallest unit value
}

// GetBalance queries the on-chain balance for the given chain and address.
func GetBalance(family, address, rpcURL string) (*BalanceResult, error) {
	switch family {
	case "evm":
		return getETHBalance(address, rpcURL)
	case "solana":
		return getSOLBalance(address, rpcURL)
	default:
		return nil, fmt.Errorf("unsupported chain family: %s", family)
	}
}

func getETHBalance(address, rpcURL string) (*BalanceResult, error) {
	if rpcURL == "" {
		return nil, fmt.Errorf("ETH_RPC_URL is not configured")
	}
	body := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_getBalance",
		"params":  []interface{}{address, "latest"},
		"id":      1,
	}
	raw, err := jsonRPC(rpcURL, body)
	if err != nil {
		return nil, err
	}
	hexVal, ok := raw["result"].(string)
	if !ok {
		return nil, fmt.Errorf("unexpected eth_getBalance response: %v", raw["result"])
	}
	hexVal = strings.TrimPrefix(hexVal, "0x")
	wei := new(big.Int)
	wei.SetString(hexVal, 16)

	// Convert Wei → ETH (divide by 1e18)
	eth := new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(1e18))
	return &BalanceResult{
		Chain:    "ethereum",
		Address:  address,
		Balance:  eth.Text('f', 8),
		Currency: "ETH",
		Raw:      wei.String(),
	}, nil
}

func getSOLBalance(address, rpcURL string) (*BalanceResult, error) {
	if rpcURL == "" {
		rpcURL = "https://api.mainnet-beta.solana.com"
	}
	body := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "getBalance",
		"params":  []interface{}{address},
		"id":      1,
	}
	raw, err := jsonRPC(rpcURL, body)
	if err != nil {
		return nil, err
	}
	resultMap, ok := raw["result"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected getBalance response")
	}
	lamportF, ok := resultMap["value"].(float64)
	if !ok {
		return nil, fmt.Errorf("unexpected lamport value type")
	}
	lamports := int64(lamportF)
	sol := float64(lamports) / 1e9
	return &BalanceResult{
		Chain:    "solana",
		Address:  address,
		Balance:  fmt.Sprintf("%.9f", sol),
		Currency: "SOL",
		Raw:      fmt.Sprintf("%d", lamports),
	}, nil
}

func jsonRPC(url string, payload interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("rpc request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("rpc http error: status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("rpc decode failed: %w", err)
	}
	if errField, ok := result["error"]; ok && errField != nil {
		return nil, fmt.Errorf("rpc error: %v", errField)
	}
	return result, nil
}
