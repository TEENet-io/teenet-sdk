package client

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/TEENet-io/teenet-sdk/go/internal/types"
)

const (
	maxPollInterval = 5 * time.Second
)

// waitForSignResult polls voting status until signing is finalized or timeout.
func (c *Client) waitForSignResult(ctx context.Context, hash string, timeout time.Duration) (*types.SignResult, error) {
	if hash == "" {
		return nil, fmt.Errorf("hash is required")
	}
	waitTimeout := timeout
	if waitTimeout <= 0 {
		waitTimeout = c.pendingWaitTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, waitTimeout)
	defer cancel()

	deadline := time.Now().Add(waitTimeout)
	start := time.Now()
	lastVotes := 0
	lastRequired := 0
	attempt := 0

	for {
		// Check if context is already done before each attempt
		select {
		case <-ctx.Done():
			return thresholdTimeoutResult(hash, lastVotes, lastRequired)
		default:
		}

		attempt++
		status, err := c.GetStatus(ctx, hash)
		if err != nil {
			// If the context itself timed out or was cancelled during the HTTP call,
			// surface a clean threshold-timeout result rather than a raw network error.
			if ctx.Err() != nil {
				return thresholdTimeoutResult(hash, lastVotes, lastRequired)
			}
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
					), errors.New(errMsg)
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
			timer := time.NewTimer(sleepFor)
			select {
			case <-ctx.Done():
				timer.Stop()
				return thresholdTimeoutResult(hash, lastVotes, lastRequired)
			case <-timer.C:
			}
		}
	}

	return thresholdTimeoutResult(hash, lastVotes, lastRequired)
}

func thresholdTimeoutResult(hash string, lastVotes, lastRequired int) (*types.SignResult, error) {
	msg := fmt.Sprintf("threshold not met before timeout for hash %s: votes %d/%d",
		hash, lastVotes, lastRequired)
	return signFailure(
		types.ErrorCodeThresholdTimeout,
		msg,
		&types.VotingInfo{
			NeedsVoting:   true,
			CurrentVotes:  lastVotes,
			RequiredVotes: lastRequired,
			Status:        "pending",
			Hash:          hash,
		},
	), errors.New(msg)
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
