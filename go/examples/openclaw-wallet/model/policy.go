package model

import "time"

// ApprovalPolicy defines when a signing request requires human approval.
// One policy per (wallet, currency) pair — each currency gets its own threshold and daily limit.
type ApprovalPolicy struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	WalletID        uint      `json:"wallet_id" gorm:"not null;uniqueIndex:idx_wallet_currency"`
	ThresholdAmount string    `json:"threshold_amount" gorm:"not null"` // single-tx threshold, e.g. "0.1"
	Currency        string    `json:"currency" gorm:"not null;uniqueIndex:idx_wallet_currency"` // "ETH", "USDC", "SOL", …
	Enabled         bool      `json:"enabled" gorm:"default:true"`
	DailyLimit      string    `json:"daily_limit"`                     // optional: max total spend per UTC day, e.g. "1000"
	DailySpent      string    `json:"daily_spent" gorm:"default:'0'"` // cumulative spend in the current UTC day
	DailyResetAt    time.Time `json:"daily_reset_at"`                  // start of the day DailySpent was last reset/updated
	CreatedAt       time.Time `json:"created_at"`
}

// ApprovalRequest is created when a sign/transfer request exceeds the policy threshold,
// or when an API key requests a policy change that requires passkey confirmation.
type ApprovalRequest struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	WalletID     uint      `json:"wallet_id" gorm:"not null;index"`
	UserID       uint      `json:"user_id" gorm:"not null"`
	ApprovalType string    `json:"approval_type" gorm:"default:'sign'"` // "sign", "transfer", "policy_change"
	Message      string    `json:"message" gorm:"type:text"`            // hex signing hash (ETH) or message bytes (SOL); empty for policy_change
	TxContext    string    `json:"tx_context" gorm:"type:text"`         // JSON display info for sign/transfer
	TxParams     string    `json:"tx_params" gorm:"type:text"`          // JSON chain params for broadcast (transfer only)
	PolicyData   string    `json:"policy_data" gorm:"type:text"`        // JSON proposed ApprovalPolicy (policy_change only)
	TxHash       string    `json:"tx_hash" gorm:"type:text"`            // filled after approval + broadcast
	Status       string    `json:"status" gorm:"default:'pending'"`
	Signature    string    `json:"signature" gorm:"type:text"` // filled after sign/transfer approval
	ApprovedBy   *uint     `json:"approved_by"`                // PasskeyUserID of approver
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}
