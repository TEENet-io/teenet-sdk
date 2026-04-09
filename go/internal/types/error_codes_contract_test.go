// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

package types

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type errorCodeContract struct {
	SignErrorCodes []string `json:"sign_error_codes"`
}

func TestSignErrorCodeContract(t *testing.T) {
	contractPath := filepath.Clean(filepath.Join("..", "..", "..", "docs", "error-codes.contract.json"))
	data, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("failed to read contract file %s: %v", contractPath, err)
	}

	var contract errorCodeContract
	if err := json.Unmarshal(data, &contract); err != nil {
		t.Fatalf("failed to parse contract file: %v", err)
	}

	actual := []string{
		ErrorCodeInvalidInput,
		ErrorCodeSignRequestFailed,
		ErrorCodeSignRequestRejected,
		ErrorCodeSignatureDecode,
		ErrorCodeUnexpectedStatus,
		ErrorCodeMissingHash,
		ErrorCodeStatusQueryFailed,
		ErrorCodeSignFailed,
		ErrorCodeThresholdTimeout,
		ErrorCodeApprovalPending,
	}

	if !reflect.DeepEqual(actual, contract.SignErrorCodes) {
		t.Fatalf("sign error code contract mismatch\nexpected=%v\nactual=%v", contract.SignErrorCodes, actual)
	}
}
