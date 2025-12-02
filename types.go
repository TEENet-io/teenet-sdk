// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited. All Rights Reserved.
//
// This software and its associated documentation files (the "Software") are
// the proprietary and confidential information of TEENet Technology (Hong Kong) Limited.
// Unauthorized copying of this file, via any medium, is strictly prohibited.
//
// No license, express or implied, is hereby granted, except by written agreement
// with TEENet Technology (Hong Kong) Limited. Use of this software without permission
// is a violation of applicable laws.
//
// -----------------------------------------------------------------------------

package sdk

import (
	"github.com/TEENet-io/teenet-sdk/internal/crypto"
	"github.com/TEENet-io/teenet-sdk/internal/types"
)

// Re-export all types from internal/types for public API.

type (
	ClientOptions   = types.ClientOptions
	SignOptions     = types.SignOptions
	SignResult      = types.SignResult
	VotingInfo      = types.VotingInfo
	CallbackPayload = types.CallbackPayload
)

// Re-export constants from internal/crypto.
const (
	ProtocolECDSA   = crypto.ProtocolECDSA
	ProtocolSchnorr = crypto.ProtocolSchnorr
	CurveED25519    = crypto.CurveED25519
	CurveSECP256K1  = crypto.CurveSECP256K1
	CurveSECP256R1  = crypto.CurveSECP256R1
)

// Re-export functions from internal/crypto.
var (
	ParseProtocol = crypto.ParseProtocol
	ParseCurve    = crypto.ParseCurve
)
