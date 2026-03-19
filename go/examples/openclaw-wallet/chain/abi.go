package chain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// EncodeCall encodes a Solidity function call into raw EVM calldata.
// funcSig is the canonical signature, e.g. "transfer(address,uint256)".
// args are the values for each parameter.
//
// Supported types: address, uint256, int256, bool, bytes32.
func EncodeCall(funcSig string, args []interface{}) ([]byte, error) {
	paramTypes, err := parseParamTypes(funcSig)
	if err != nil {
		return nil, err
	}
	if len(paramTypes) != len(args) {
		return nil, fmt.Errorf("arg count mismatch: signature has %d params but %d args provided", len(paramTypes), len(args))
	}

	selector := crypto.Keccak256([]byte(funcSig))[:4]

	calldata := make([]byte, 0, 4+32*len(args))
	calldata = append(calldata, selector...)

	for i, typ := range paramTypes {
		word, err := encodeArg(typ, args[i])
		if err != nil {
			return nil, fmt.Errorf("arg %d (%s): %w", i, typ, err)
		}
		calldata = append(calldata, word...)
	}
	return calldata, nil
}

// parseParamTypes extracts parameter type strings from a function signature.
// "transfer(address,uint256)" -> ["address", "uint256"]
// "pause()" -> []
func parseParamTypes(funcSig string) ([]string, error) {
	openParen := strings.Index(funcSig, "(")
	closeParen := strings.LastIndex(funcSig, ")")
	if openParen < 0 || closeParen < 0 || closeParen <= openParen {
		return nil, fmt.Errorf("invalid function signature: %s", funcSig)
	}
	inner := funcSig[openParen+1 : closeParen]
	if inner == "" {
		return nil, nil
	}
	parts := strings.Split(inner, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts, nil
}

// encodeArg encodes a single argument as a 32-byte ABI word.
func encodeArg(typ string, arg interface{}) ([]byte, error) {
	switch typ {
	case "address":
		s, ok := arg.(string)
		if !ok {
			return nil, fmt.Errorf("address requires string, got %T", arg)
		}
		addr := common.HexToAddress(s)
		word := make([]byte, 32)
		copy(word[12:], addr.Bytes())
		return word, nil

	case "uint256":
		v, err := toBigInt(arg)
		if err != nil {
			return nil, fmt.Errorf("uint256: %w", err)
		}
		if v.Sign() < 0 {
			return nil, fmt.Errorf("uint256 cannot be negative")
		}
		word := make([]byte, 32)
		b := v.Bytes()
		if len(b) > 32 {
			return nil, fmt.Errorf("uint256 overflow")
		}
		copy(word[32-len(b):], b)
		return word, nil

	case "int256":
		v, err := toBigInt(arg)
		if err != nil {
			return nil, fmt.Errorf("int256: %w", err)
		}
		return encodeInt256(v)

	case "bool":
		b, ok := arg.(bool)
		if !ok {
			return nil, fmt.Errorf("bool requires bool, got %T", arg)
		}
		word := make([]byte, 32)
		if b {
			word[31] = 1
		}
		return word, nil

	case "bytes32":
		s, ok := arg.(string)
		if !ok {
			return nil, fmt.Errorf("bytes32 requires hex string, got %T", arg)
		}
		s = strings.TrimPrefix(s, "0x")
		decoded, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("bytes32 hex decode: %w", err)
		}
		if len(decoded) != 32 {
			return nil, fmt.Errorf("bytes32 requires exactly 32 bytes, got %d", len(decoded))
		}
		word := make([]byte, 32)
		copy(word, decoded)
		return word, nil

	default:
		return nil, fmt.Errorf("unsupported type: %s", typ)
	}
}

// toBigInt converts various numeric types to *big.Int.
func toBigInt(v interface{}) (*big.Int, error) {
	switch val := v.(type) {
	case *big.Int:
		return new(big.Int).Set(val), nil
	case string:
		n := new(big.Int)
		if _, ok := n.SetString(val, 10); !ok {
			return nil, fmt.Errorf("cannot parse %q as decimal integer", val)
		}
		return n, nil
	case float64:
		return big.NewInt(int64(val)), nil
	case int:
		return big.NewInt(int64(val)), nil
	case int64:
		return big.NewInt(val), nil
	case json.Number:
		n := new(big.Int)
		if _, ok := n.SetString(val.String(), 10); !ok {
			return nil, fmt.Errorf("cannot parse json.Number %q as integer", val.String())
		}
		return n, nil
	default:
		return nil, fmt.Errorf("unsupported numeric type %T", v)
	}
}

// encodeInt256 encodes a signed integer as a 32-byte two's complement word.
func encodeInt256(v *big.Int) ([]byte, error) {
	// Check range: -2^255 <= v < 2^255
	limit := new(big.Int).Lsh(big.NewInt(1), 255)
	if v.Cmp(limit) >= 0 {
		return nil, fmt.Errorf("int256 overflow")
	}
	negLimit := new(big.Int).Neg(limit)
	if v.Cmp(negLimit) < 0 {
		return nil, fmt.Errorf("int256 underflow")
	}

	if v.Sign() >= 0 {
		word := make([]byte, 32)
		b := v.Bytes()
		copy(word[32-len(b):], b)
		return word, nil
	}

	// Two's complement for negative: add 2^256
	modulus := new(big.Int).Lsh(big.NewInt(1), 256)
	tc := new(big.Int).Add(modulus, v)
	word := make([]byte, 32)
	b := tc.Bytes()
	copy(word[32-len(b):], b)
	return word, nil
}
