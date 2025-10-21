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

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	client "github.com/TEENet-io/teenet-sdk/go"
	"github.com/gin-gonic/gin"
)

var teeClient *client.Client
var defaultAppID string

func main() {
	// Get configuration from environment variables
	configAddr := os.Getenv("TEE_CONFIG_ADDR")
	if configAddr == "" {
		configAddr = "localhost:50052" // Default TEE configuration server address
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port
	}

	// Get App ID from environment variable
	defaultAppID = os.Getenv("APP_ID")
	if defaultAppID == "" {
		log.Fatalf("APP_ID environment variable is required")
	}

	// Frontend path
	frontendPath := os.Getenv("FRONTEND_PATH")
	if frontendPath == "" {
		frontendPath = "./frontend" // Default frontend path
	}

	// Initialize TEE client
	teeClient = client.NewClient(configAddr)
	if err := teeClient.Init(); err != nil {
		log.Fatalf("Failed to initialize TEE client: %v", err)
	}
	defer teeClient.Close()

	log.Printf("TEE client initialized successfully for app ID: %s", defaultAppID)

	// Setup Gin router
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// Enable CORS
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Add static file handler for frontend
	router.Use(staticFileHandler(frontendPath))

	// API endpoints
	api := router.Group("/api")

	// Health check
	api.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "TEENet Signature Tool",
		})
	})

	// Configuration endpoint for frontend
	api.GET("/config", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"app_id": defaultAppID,
		})
	})

	// Get public key (uses default app ID)
	api.POST("/get-public-key", func(c *gin.Context) {
		publicKey, protocol, curve, err := teeClient.GetPublicKey()
		if err != nil {
			log.Printf("Failed to get public key: %v", err)
			c.JSON(http.StatusInternalServerError, GetPublicKeyResponse{
				Success: false,
				AppID:   defaultAppID,
				Error:   err.Error(),
			})
			return
		}

		log.Printf("Successfully retrieved public key for app ID %s", defaultAppID)
		c.JSON(http.StatusOK, GetPublicKeyResponse{
			Success:   true,
			AppID:     defaultAppID,
			PublicKey: publicKey,
			Protocol:  protocol,
			Curve:     curve,
		})
	})

	// Sign message (uses default app ID)
	api.POST("/sign-with-appid", func(c *gin.Context) {
		var req SignWithAppIDRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, SignWithAppIDResponse{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		// Use Sign API (voting is automatically determined based on App ID configuration)
		signResult, err := teeClient.Sign([]byte(req.Message))
		if err != nil || !signResult.Success {
			errorMsg := "Failed to sign message"
			if err != nil {
				errorMsg = err.Error()
			} else if signResult.Error != "" {
				errorMsg = signResult.Error
			}
			log.Printf("Failed to sign message: %s", errorMsg)
			c.JSON(http.StatusInternalServerError, SignWithAppIDResponse{
				Success: false,
				Message: req.Message,
				AppID:   defaultAppID,
				Error:   errorMsg,
			})
			return
		}

		signatureHex := hex.EncodeToString(signResult.Signature)
		log.Printf("Successfully signed message with app ID %s", defaultAppID)
		c.JSON(http.StatusOK, SignWithAppIDResponse{
			Success:   true,
			Message:   req.Message,
			AppID:     defaultAppID,
			Signature: signatureHex,
		})
	})

	// Verify signature (uses default app ID)
	api.POST("/verify-with-appid", func(c *gin.Context) {
		var req VerifyWithAppIDRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, VerifyWithAppIDResponse{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		// Get public key info (for response)
		publicKey, protocol, curve, err := teeClient.GetPublicKey()
		if err != nil {
			log.Printf("Failed to get public key: %v", err)
			c.JSON(http.StatusInternalServerError, VerifyWithAppIDResponse{
				Success: false,
				AppID:   defaultAppID,
				Error:   err.Error(),
			})
			return
		}

		// Decode signature from hex
		signatureBytes, err := hex.DecodeString(req.Signature)
		if err != nil {
			c.JSON(http.StatusBadRequest, VerifyWithAppIDResponse{
				Success: false,
				Error:   "Invalid signature format (must be hex): " + err.Error(),
			})
			return
		}

		// Verify the signature using the SDK's Verify method
		valid, err := teeClient.Verify([]byte(req.Message), signatureBytes)
		if err != nil {
			log.Printf("Failed to verify signature: %v", err)
			c.JSON(http.StatusInternalServerError, VerifyWithAppIDResponse{
				Success: false,
				Message: req.Message,
				AppID:   defaultAppID,
				Error:   err.Error(),
			})
			return
		}

		log.Printf("Signature verification completed for app ID %s: valid=%t", defaultAppID, valid)
		c.JSON(http.StatusOK, VerifyWithAppIDResponse{
			Success:   true,
			Valid:     valid,
			Message:   req.Message,
			Signature: req.Signature,
			AppID:     defaultAppID,
			PublicKey: publicKey,
			Protocol:  protocol,
			Curve:     curve,
		})
	})

	// Voting endpoint - make decision and run VotingSign
	api.POST("/vote", func(c *gin.Context) {
		// Read raw request body
		requestBody, err := c.GetRawData()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
			return
		}

		var req IncomingVoteRequest
		if err := json.Unmarshal(requestBody, &req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		log.Printf("🗳️  [%s] Received vote request", defaultAppID)

		// Decode message
		messageBytes, err := base64.StdEncoding.DecodeString(req.Message)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid message encoding"})
			return
		}

		// Make vote decision: approve if message contains "test"
		messageStr := string(messageBytes)
		localApproval := strings.Contains(strings.ToLower(messageStr), "test")

		log.Printf("📝 [%s] Local vote decision for message '%s': %t", defaultAppID, messageStr, localApproval)

		// Restore request body for VotingSign to read
		c.Request.Body = io.NopCloser(bytes.NewBuffer(requestBody))

		// Use Sign API (voting is automatically determined based on App ID configuration)
		signResult, err := teeClient.Sign(messageBytes, &client.SignOptions{
			LocalApproval: localApproval,
			HTTPRequest:   c.Request,
		})
		if err != nil {
			log.Printf("❌ [%s] VotingSign failed: %v", defaultAppID, err)

			// Check if we have partial voting results
			if signResult != nil && signResult.VotingInfo != nil {
				c.JSON(http.StatusOK, gin.H{
					"success":  true,
					"approved": false,
					"app_id":   defaultAppID,
					"message":  fmt.Sprintf("VotingSign failed: %v", err),
					"voting_results": gin.H{
						"voting_complete":  signResult.Success,
						"successful_votes": signResult.VotingInfo.SuccessfulVotes,
						"required_votes":   signResult.VotingInfo.RequiredVotes,
						"total_targets":    signResult.VotingInfo.TotalTargets,
						"final_result":     signResult.Error,
						"vote_details":     signResult.VotingInfo.VoteDetails,
						"error":            err.Error(),
					},
					"signature": "",
					"timestamp": time.Now().Format(time.RFC3339),
				})
			} else {
				// No voting results at all
				c.JSON(http.StatusOK, gin.H{
					"success":  true,
					"approved": false,
					"app_id":   defaultAppID,
					"message":  fmt.Sprintf("VotingSign failed: %v", err),
					"voting_results": gin.H{
						"voting_complete":  false,
						"successful_votes": 0,
						"required_votes":   0,
						"total_targets":    0,
						"final_result":     "ERROR",
						"vote_details":     []interface{}{},
						"error":            err.Error(),
					},
					"signature": "",
					"timestamp": time.Now().Format(time.RFC3339),
				})
			}
			return
		}

		finalApproval := signResult.Success
		log.Printf("✅ [%s] VotingSign result: %t", defaultAppID, finalApproval)

		// Convert signature to hex string if available
		var signatureHex string
		if signResult.Signature != nil && len(signResult.Signature) > 0 {
			signatureHex = hex.EncodeToString(signResult.Signature)
		}

		// Prepare voting results response
		votingResults := gin.H{
			"voting_complete":  signResult.Success,
			"successful_votes": 0,
			"required_votes":   0,
			"total_targets":    0,
			"final_result":     "DIRECT_SIGN",
			"vote_details":     []interface{}{},
		}

		if signResult.VotingInfo != nil {
			votingResults = gin.H{
				"voting_complete":  signResult.Success,
				"successful_votes": signResult.VotingInfo.SuccessfulVotes,
				"required_votes":   signResult.VotingInfo.RequiredVotes,
				"total_targets":    signResult.VotingInfo.TotalTargets,
				"final_result": func() string {
					if signResult.Success {
						return "APPROVED"
					}
					return "REJECTED"
				}(),
				"vote_details": signResult.VotingInfo.VoteDetails,
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"success":  true,
			"approved": finalApproval,
			"app_id":   defaultAppID,
			"message": func() string {
				if signResult.Success {
					return "APPROVED"
				}
				if signResult.Error != "" {
					return signResult.Error
				}
				return "REJECTED"
			}(),
			"voting_results": votingResults,
			"signature":      signatureHex,
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
		})
	})

	log.Printf("Starting TEENet Signature Tool on port %s...", port)
	log.Printf("TEE Configuration Server: %s", configAddr)
	log.Printf("Default App ID: %s", defaultAppID)
	log.Printf("Frontend Path: %s", frontendPath)
	log.Printf("Web interface available at: http://localhost:%s", port)

	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
