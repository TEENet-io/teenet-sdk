// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited.
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
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	sdk "github.com/TEENet-io/teenet-sdk/go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/sha3"
)

var (
	sdkClient    *sdk.Client
	appID        string
	consensusURL string
)

func getPrimaryKeyName() (string, error) {
	keys, err := sdkClient.GetPublicKeys()
	if err != nil {
		return "", err
	}
	if len(keys) == 0 {
		return "", fmt.Errorf("no bound public keys found")
	}
	return keys[0].Name, nil
}

func main() {
	// Setup logging to file
	logDir := os.Getenv("LOG_DIR")
	if logDir == "" {
		logDir = "/var/log/voting-demo" // Default log directory
	}

	// Create log directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Printf("Warning: Failed to create log directory %s: %v, using stdout only", logDir, err)
	} else {
		logFile, err := os.OpenFile(filepath.Join(logDir, "app.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Printf("Warning: Failed to open log file: %v, using stdout only", err)
		} else {
			// Write to both stdout and log file
			multiWriter := io.MultiWriter(os.Stdout, logFile)
			log.SetOutput(multiWriter)
			log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
		}
	}

	// Load configuration from environment variables
	appID = os.Getenv("APP_INSTANCE_ID")
	if appID == "" {
		log.Fatal("❌ APP_INSTANCE_ID environment variable is required")
	}

	consensusURL = os.Getenv("CONSENSUS_URL")
	if consensusURL == "" {
		consensusURL = "http://localhost:8089" // Default
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default
	}

	// Initialize SDK client for this app instance
	sdkClient = sdk.NewClient(consensusURL)
	sdkClient.SetDefaultAppID(appID)

	log.Printf("🗳️  Voting Demo App Starting...")
	log.Printf("📋 App ID: %s", appID)
	log.Printf("🔗 Consensus URL: %s", consensusURL)
	log.Printf("🌐 Port: %s", port)

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

	// Serve static files (frontend)
	router.Use(staticFileHandler("./frontend"))

	// API routes
	api := router.Group("/api")
	{
		api.GET("/health", handleHealth)
		api.GET("/config", handleConfig)
		api.POST("/sign", handleSign)
		api.POST("/vote", handleVote)
		api.POST("/verify", handleVerify)
		api.POST("/apikey/get", handleGetAPIKey)
		api.POST("/apikey/sign", handleSignWithSecret)
	}

	log.Printf("✅ Server ready at http://localhost:%s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("❌ Failed to start server: %v", err)
	}
}

// handleHealth returns the health status of the app
func handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, HealthResponse{
		Status:        "healthy",
		Service:       "Voting Demo App",
		AppInstanceID: appID,
	})
}

// handleConfig returns the configuration for the current app instance
func handleConfig(c *gin.Context) {
	c.JSON(http.StatusOK, ConfigResponse{
		AppInstanceID: appID,
		ConsensusURL:  consensusURL,
	})
}

// keccak256Hash computes the Keccak-256 hash of the message (Ethereum-style)
// This function uses the legacy Keccak-256 algorithm, which is the same as Ethereum's hash function
func keccak256Hash(message []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(message)
	return hash.Sum(nil)
}

// handleSign handles direct signing requests (without voting)
func handleSign(c *gin.Context) {
	var req SignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, SignResponse{
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	if req.Message == "" {
		c.JSON(http.StatusBadRequest, SignResponse{
			Success: false,
			Error:   "Message is required",
		})
		return
	}

	log.Printf("🔐 [%s] Direct signing message: %s", appID[:8], req.Message)

	// Hash the message using Keccak-256 (Ethereum-style) before signing
	messageBytes := []byte(req.Message)
	hashedMessage := keccak256Hash(messageBytes)
	log.Printf("🔐 [%s] Message hash (Keccak-256): %s", appID[:8], hex.EncodeToString(hashedMessage))

	keyName, err := getPrimaryKeyName()
	if err != nil {
		c.JSON(http.StatusBadRequest, SignResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	// Call SDK Sign method - single signing interface for both direct and voting apps.
	result, err := sdkClient.Sign(hashedMessage, keyName)
	if err != nil {
		log.Printf("❌ [%s] Sign failed: %v", appID[:8], err)
		c.JSON(http.StatusInternalServerError, SignResponse{
			Success:       false,
			AppInstanceID: appID,
			Error:         err.Error(),
		})
		return
	}

	if !result.Success {
		log.Printf("❌ [%s] Sign failed: %s", appID[:8], result.Error)
		c.JSON(http.StatusOK, SignResponse{
			Success:       false,
			AppInstanceID: appID,
			Error:         result.Error,
		})
		return
	}

	// Return signature
	signatureHex := hex.EncodeToString(result.Signature)
	shortSig := signatureHex
	if len(shortSig) > 16 {
		shortSig = shortSig[:16]
	}
	log.Printf("✅ [%s] Sign succeeded: %s...", appID[:8], shortSig)

	c.JSON(http.StatusOK, SignResponse{
		Success:       true,
		AppInstanceID: appID,
		Message:       req.Message,
		Signature:     signatureHex,
		VotingInfo:    result.VotingInfo,
	})
}

// handleVote handles voting requests from the frontend
func handleVote(c *gin.Context) {
	var req VoteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, VoteResponse{
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	if req.Message == "" {
		c.JSON(http.StatusBadRequest, VoteResponse{
			Success: false,
			Error:   "Message is required",
		})
		return
	}

	log.Printf("🗳️  [%s] Submitting vote for message: %s", appID[:8], req.Message)

	// Hash the message using Keccak-256 (Ethereum-style) before signing
	messageBytes := []byte(req.Message)
	hashedMessage := keccak256Hash(messageBytes)
	log.Printf("🗳️  [%s] Message hash (Keccak-256): %s", appID[:8], hex.EncodeToString(hashedMessage))

	keyName, err := getPrimaryKeyName()
	if err != nil {
		c.JSON(http.StatusBadRequest, VoteResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	// Call SDK Sign method - this will handle voting automatically
	// with internal status polling until final result.
	result, err := sdkClient.Sign(hashedMessage, keyName)
	if err != nil {
		log.Printf("❌ [%s] Vote failed: %v", appID[:8], err)
		c.JSON(http.StatusInternalServerError, VoteResponse{
			Success:       false,
			AppInstanceID: appID,
			Error:         err.Error(),
		})
		return
	}

	// Prepare response
	response := VoteResponse{
		Success:       result.Success,
		AppInstanceID: appID,
		VotingInfo:    result.VotingInfo,
	}

	if !result.Success {
		response.Error = result.Error
		log.Printf("❌ [%s] Vote failed: %s", appID[:8], result.Error)
	} else {
		response.Message = "Vote submitted successfully"

		// Sign() now returns finalized result for voting flows.
		response.Signature = hex.EncodeToString(result.Signature)
		log.Printf("✅ [%s] Vote succeeded with signature: %s...", appID[:8], response.Signature[:16])
	}

	c.JSON(http.StatusOK, response)
}

// handleVerify handles signature verification requests
func handleVerify(c *gin.Context) {
	var req VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, VerifyResponse{
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	if req.Message == "" || req.Signature == "" {
		c.JSON(http.StatusBadRequest, VerifyResponse{
			Success: false,
			Error:   "Message and signature are required",
		})
		return
	}

	log.Printf("🔍 [%s] Verifying signature for message: %s", appID[:8], req.Message)

	// Decode signature from hex
	signatureBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		log.Printf("❌ [%s] Invalid signature format: %v", appID[:8], err)
		c.JSON(http.StatusBadRequest, VerifyResponse{
			Success: false,
			Error:   "Invalid signature format (must be hex): " + err.Error(),
		})
		return
	}

	// Hash the message using Keccak-256 (Ethereum-style) before verification
	messageBytes := []byte(req.Message)
	hashedMessage := keccak256Hash(messageBytes)
	log.Printf("🔍 [%s] Message hash (Keccak-256): %s", appID[:8], hex.EncodeToString(hashedMessage))

	// Get bound public keys for this app
	keys, err := sdkClient.GetPublicKeys()
	if err != nil {
		log.Printf("❌ [%s] Failed to get public keys: %v", appID[:8], err)
		c.JSON(http.StatusInternalServerError, VerifyResponse{
			Success: false,
			Error:   "Failed to get public keys: " + err.Error(),
		})
		return
	}
	if len(keys) == 0 {
		c.JSON(http.StatusBadRequest, VerifyResponse{
			Success: false,
			Error:   "No bound public keys found",
		})
		return
	}
	selected := keys[0]
	publicKey := selected.KeyData
	protocol := selected.Protocol
	curve := selected.Curve
	// Verify the signature using selected key name
	valid, err := sdkClient.Verify(hashedMessage, signatureBytes, selected.Name)
	if err != nil {
		log.Printf("❌ [%s] Verification error: %v", appID[:8], err)
		c.JSON(http.StatusInternalServerError, VerifyResponse{
			Success: false,
			Error:   "Verification error: " + err.Error(),
		})
		return
	}

	log.Printf("✅ [%s] Signature verification result: %t", appID[:8], valid)

	c.JSON(http.StatusOK, VerifyResponse{
		Success:   true,
		Valid:     valid,
		PublicKey: publicKey,
		Protocol:  protocol,
		Curve:     curve,
	})
}

// staticFileHandler serves static files from the frontend directory
func staticFileHandler(frontendPath string) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// Skip API routes
		if strings.HasPrefix(path, "/api/") {
			c.Next()
			return
		}

		// Default to index.html for root
		if path == "/" {
			path = "/index.html"
		}

		// Build file path
		relativePath := strings.TrimPrefix(path, "/")

		// Security: prevent directory traversal
		if strings.Contains(relativePath, "..") {
			c.String(http.StatusBadRequest, "Invalid path")
			c.Abort()
			return
		}

		filePath := filepath.Join(frontendPath, relativePath)

		// Check if file exists
		ext := filepath.Ext(path)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			// For non-asset requests, serve index.html (SPA routing)
			if ext != ".css" && ext != ".js" && ext != ".png" && ext != ".jpg" && ext != ".gif" && ext != ".ico" {
				filePath = filepath.Join(frontendPath, "index.html")
			} else {
				c.String(http.StatusNotFound, "File not found")
				c.Abort()
				return
			}
		}

		// Set appropriate content type
		switch ext {
		case ".html":
			c.Header("Content-Type", "text/html")
		case ".css":
			c.Header("Content-Type", "text/css")
		case ".js":
			c.Header("Content-Type", "application/javascript")
		case ".png":
			c.Header("Content-Type", "image/png")
		case ".jpg", ".jpeg":
			c.Header("Content-Type", "image/jpeg")
		case ".gif":
			c.Header("Content-Type", "image/gif")
		case ".ico":
			c.Header("Content-Type", "image/x-icon")
		}

		// Serve the file
		c.File(filePath)
		c.Abort()
	}
}

// handleGetAPIKey handles API key retrieval requests
func handleGetAPIKey(c *gin.Context) {
	var req GetAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, GetAPIKeyResponse{
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	if req.Name == "" {
		c.JSON(http.StatusBadRequest, GetAPIKeyResponse{
			Success: false,
			Error:   "API key name is required",
		})
		return
	}

	log.Printf("🔑 [%s] Retrieving API key: %s", appID[:8], req.Name)

	// Call SDK GetAPIKey method
	result, err := sdkClient.GetAPIKey(req.Name)
	if err != nil {
		log.Printf("❌ [%s] GetAPIKey failed: %v", appID[:8], err)
		c.JSON(http.StatusInternalServerError, GetAPIKeyResponse{
			Success: false,
			Name:    req.Name,
			Error:   err.Error(),
		})
		return
	}

	if !result.Success {
		log.Printf("❌ [%s] GetAPIKey failed: %s", appID[:8], result.Error)
		c.JSON(http.StatusOK, GetAPIKeyResponse{
			Success: false,
			Name:    req.Name,
			Error:   result.Error,
		})
		return
	}

	log.Printf("✅ [%s] API key retrieved successfully: %s", appID[:8], req.Name)

	c.JSON(http.StatusOK, GetAPIKeyResponse{
		Success: true,
		Name:    req.Name,
		APIKey:  result.APIKey,
	})
}

// handleSignWithSecret handles signing requests using API secret
func handleSignWithSecret(c *gin.Context) {
	var req SignWithSecretRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, SignWithSecretResponse{
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	if req.Name == "" || req.Message == "" {
		c.JSON(http.StatusBadRequest, SignWithSecretResponse{
			Success: false,
			Error:   "API key name and message are required",
		})
		return
	}

	log.Printf("🔐 [%s] Signing with API secret: %s, message: %s", appID[:8], req.Name, req.Message)

	// Hash the message using Keccak-256 (Ethereum-style) before signing
	messageBytes := []byte(req.Message)
	hashedMessage := keccak256Hash(messageBytes)
	log.Printf("🔐 [%s] Message hash (Keccak-256): %s", appID[:8], hex.EncodeToString(hashedMessage))

	// Call SDK SignWithAPISecret method
	result, err := sdkClient.SignWithAPISecret(req.Name, hashedMessage)
	if err != nil {
		log.Printf("❌ [%s] SignWithAPISecret failed: %v", appID[:8], err)
		c.JSON(http.StatusInternalServerError, SignWithSecretResponse{
			Success: false,
			Name:    req.Name,
			Message: req.Message,
			Error:   err.Error(),
		})
		return
	}

	if !result.Success {
		log.Printf("❌ [%s] SignWithAPISecret failed: %s", appID[:8], result.Error)
		c.JSON(http.StatusOK, SignWithSecretResponse{
			Success: false,
			Name:    req.Name,
			Message: req.Message,
			Error:   result.Error,
		})
		return
	}

	log.Printf("✅ [%s] Signed successfully with API secret: %s", appID[:8], req.Name)

	c.JSON(http.StatusOK, SignWithSecretResponse{
		Success:       true,
		Name:          req.Name,
		Message:       req.Message,
		Signature:     result.Signature,
		Algorithm:     result.Algorithm,
		MessageLength: result.MessageLength,
	})
}
