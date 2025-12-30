// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited. All Rights Reserved.
// -----------------------------------------------------------------------------

package util

import (
	"bytes"
	"testing"
)

func TestDecodeHexSignature(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
		wantErr  bool
	}{
		{
			name:     "with 0x prefix",
			input:    "0x1234abcd",
			expected: []byte{0x12, 0x34, 0xab, 0xcd},
			wantErr:  false,
		},
		{
			name:     "without 0x prefix",
			input:    "1234abcd",
			expected: []byte{0x12, 0x34, 0xab, 0xcd},
			wantErr:  false,
		},
		{
			name:     "uppercase hex",
			input:    "0xABCDEF",
			expected: []byte{0xab, 0xcd, 0xef},
			wantErr:  false,
		},
		{
			name:     "mixed case",
			input:    "AbCdEf",
			expected: []byte{0xab, 0xcd, 0xef},
			wantErr:  false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: []byte{},
			wantErr:  false,
		},
		{
			name:     "just 0x prefix",
			input:    "0x",
			expected: []byte{},
			wantErr:  false,
		},
		{
			name:     "full signature (64 bytes)",
			input:    "0x" + "aa" + "bb" + "cc" + "dd" + "ee" + "ff" + "00" + "11",
			expected: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11},
			wantErr:  false,
		},
		{
			name:    "invalid hex characters",
			input:   "0xGGGG",
			wantErr: true,
		},
		{
			name:    "odd length hex",
			input:   "0x123",
			wantErr: true,
		},
		{
			name:    "invalid characters without prefix",
			input:   "xyz123",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DecodeHexSignature(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("DecodeHexSignature(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("DecodeHexSignature(%q) unexpected error: %v", tt.input, err)
				return
			}
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("DecodeHexSignature(%q) = %x, expected %x", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDecodeHexSignature_RealSignatures(t *testing.T) {
	// Test with real-world signature lengths
	tests := []struct {
		name   string
		length int
	}{
		{"ED25519 signature", 64},
		{"ECDSA DER signature", 70},
		{"Schnorr signature", 64},
		{"Ethereum signature", 65},
		{"Public key compressed", 33},
		{"Public key uncompressed", 65},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a hex string of the specified byte length
			hexStr := make([]byte, tt.length*2)
			for i := range hexStr {
				hexStr[i] = "0123456789abcdef"[i%16]
			}
			input := "0x" + string(hexStr)

			result, err := DecodeHexSignature(input)
			if err != nil {
				t.Errorf("Failed to decode %d-byte hex: %v", tt.length, err)
				return
			}
			if len(result) != tt.length {
				t.Errorf("Expected %d bytes, got %d", tt.length, len(result))
			}
		})
	}
}

func BenchmarkDecodeHexSignature_WithPrefix(b *testing.B) {
	input := "0x" + "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" +
		"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeHexSignature(input)
	}
}

func BenchmarkDecodeHexSignature_WithoutPrefix(b *testing.B) {
	input := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" +
		"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeHexSignature(input)
	}
}
