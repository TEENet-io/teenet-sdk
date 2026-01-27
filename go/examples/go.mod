module mock-test

go 1.24.0

toolchain go1.24.11

require (
	github.com/TEENet-io/teenet-sdk/go v0.0.0
	github.com/ethereum/go-ethereum v1.16.8
)

require (
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20251001021608-1fe7b43fc4d6 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.6 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.0.1 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
)

replace github.com/TEENet-io/teenet-sdk/go => ..
