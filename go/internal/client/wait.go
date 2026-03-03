package client

import (
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/TEENet-io/teenet-sdk/go/internal/types"
)

const (
	defaultSignAndWaitTimeout = 60 * time.Second
	maxPollInterval           = 5 * time.Second
)

// SignAndWait submits a sign request and blocks until it is finalized or timeout.
func (c *Client) SignAndWait(message []byte, timeout time.Duration, publicKey ...[]byte) (*types.SignResult, error) {
	result, err := c.Sign(message, publicKey...)
	if err != nil || result == nil || result.VotingInfo == nil || result.VotingInfo.Status != "pending" {
		return result, err
	}

	hash := result.VotingInfo.Hash
	if hash == "" {
		msg := "missing hash in pending signing response"
		return signFailure(types.ErrorCodeMissingHash, msg, nil), errors.New(msg)
	}

	return c.WaitForSignResult(hash, timeout)
}

// WaitForSignResult polls voting status until signing is finalized or timeout.
func (c *Client) WaitForSignResult(hash string, timeout time.Duration) (*types.SignResult, error) {
	if hash == "" {
		return nil, fmt.Errorf("hash is required")
	}
	waitTimeout := timeout
	if waitTimeout <= 0 {
		waitTimeout = defaultSignAndWaitTimeout
	}

	deadline := time.Now().Add(waitTimeout)
	start := time.Now()
	lastVotes := 0
	lastRequired := 0
	attempt := 0

	for {
		attempt++
		status, err := c.GetStatus(hash)
		if err != nil {
			return signFailure(
				types.ErrorCodeStatusQueryFailed,
				fmt.Sprintf("failed to query voting status: %v", err),
				&types.VotingInfo{
					NeedsVoting:   true,
					CurrentVotes:  lastVotes,
					RequiredVotes: lastRequired,
					Status:        "pending",
					Hash:          hash,
				},
			), err
		}

		if status != nil {
			lastVotes = status.CurrentVotes
			lastRequired = status.RequiredVotes
			c.debugf("sign.poll hash=%s attempt=%d elapsed_ms=%d status=%s votes=%d/%d",
				hash, attempt, time.Since(start).Milliseconds(), status.Status, status.CurrentVotes, status.RequiredVotes)

			if status.Found {
				if status.Status == "signed" && len(status.Signature) > 0 {
					return &types.SignResult{
						Success:   true,
						Signature: status.Signature,
						VotingInfo: &types.VotingInfo{
							NeedsVoting:   true,
							CurrentVotes:  status.CurrentVotes,
							RequiredVotes: status.RequiredVotes,
							Status:        "signed",
							Hash:          hash,
						},
					}, nil
				}
				if status.Status == "failed" {
					errMsg := status.ErrorMessage
					if errMsg == "" {
						errMsg = "signing failed"
					}
					return signFailure(
						types.ErrorCodeSignFailed,
						errMsg,
						&types.VotingInfo{
							NeedsVoting:   true,
							CurrentVotes:  status.CurrentVotes,
							RequiredVotes: status.RequiredVotes,
							Status:        "failed",
							Hash:          hash,
						},
					), fmt.Errorf("%s", errMsg)
				}
			}
		}

		if time.Now().After(deadline) {
			break
		}

		sleepFor := nextPollInterval(attempt)
		remaining := time.Until(deadline)
		if sleepFor > remaining {
			sleepFor = remaining
		}
		if sleepFor > 0 {
			time.Sleep(sleepFor)
		}
	}

	timeoutMsg := fmt.Sprintf("threshold not met before timeout for hash %s: votes %d/%d",
		hash, lastVotes, lastRequired)
	return signFailure(
		types.ErrorCodeThresholdTimeout,
		timeoutMsg,
		&types.VotingInfo{
			NeedsVoting:   true,
			CurrentVotes:  lastVotes,
			RequiredVotes: lastRequired,
			Status:        "pending",
			Hash:          hash,
		},
	), fmt.Errorf("%s", timeoutMsg)
}

func nextPollInterval(attempt int) time.Duration {
	base := defaultStatusPollInterval
	if attempt < 1 {
		attempt = 1
	}

	shift := attempt - 1
	if shift > 4 {
		shift = 4
	}
	interval := base << shift
	if interval > maxPollInterval {
		interval = maxPollInterval
	}

	// jitter in [-20%, +20%]
	jitterFactor := 0.8 + rand.Float64()*0.4
	jittered := time.Duration(float64(interval) * jitterFactor)
	if jittered < 10*time.Millisecond {
		return 10 * time.Millisecond
	}
	return jittered
}
