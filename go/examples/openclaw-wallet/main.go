package main

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	sdk "github.com/TEENet-io/teenet-sdk/go"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"openclaw-wallet/handler"
	"openclaw-wallet/model"
)

func main() {
	consensusURL := envOrDefault("CONSENSUS_URL", "http://localhost:8089")
	host := envOrDefault("HOST", "0.0.0.0")
	port := envOrDefault("PORT", "8080")
	dataDir := envOrDefault("DATA_DIR", "/data")
	baseURL := envOrDefault("BASE_URL", "http://localhost:"+port)
	frontendURL := envOrDefault("FRONTEND_URL", "*") // set to specific origin in production
	chainsFile := envOrDefault("CHAINS_FILE", "./chains.json")
	apiKeyRateLimit      := envOrDefaultInt("API_KEY_RATE_LIMIT", 60)       // general: requests per minute per API key
	walletCreateRateLimit := envOrDefaultInt("WALLET_CREATE_RATE_LIMIT", 5) // wallet creation is TEE-DKG-bound

	// Load chain configuration.
	model.LoadChains(chainsFile)

	// Init SQLite DB.
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("mkdir data dir: %v", err)
	}
	dbPath := filepath.Join(dataDir, "wallet.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(
		&model.User{},
		&model.Wallet{},
		&model.ApprovalPolicy{},
		&model.ApprovalRequest{},
		&model.AllowedContract{},
		&model.AuditLog{},
	); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	// Drop the old single-column unique index on wallet_id (superseded by composite idx_wallet_currency).
	// GORM AutoMigrate adds new indexes but never removes old ones, so we do it explicitly.
	db.Exec("DROP INDEX IF EXISTS idx_approval_policies_wallet_id")

	// Init TEENet SDK.
	opts := &sdk.ClientOptions{
		RequestTimeout:     3 * time.Minute, // ECDSA DKG can take 1-2 min
		PendingWaitTimeout: 3 * time.Minute,
	}
	sdkClient := sdk.NewClientWithOptions(consensusURL, opts)
	if err := sdkClient.SetDefaultAppIDFromEnv(); err != nil {
		log.Printf("WARNING: APP_INSTANCE_ID not set — SDK signing will require explicit app ID")
	}
	defer sdkClient.Close()

	sessions := handler.NewSessionStore()

	// Router.
	r := gin.Default()
	r.Use(corsMiddleware(frontendURL))

	// Serve frontend.
	r.Static("/assets", "./frontend/assets")
	r.StaticFile("/favicon.ico", "./frontend/favicon.ico")
	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.JSON(404, gin.H{"error": "api endpoint not found"})
			return
		}
		c.File("./frontend/index.html")
	})

	// Health check (public).
	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "service": "openclaw-wallet"})
	})

	// Chain list (public) — used by frontend to populate chain selector.
	r.GET("/api/chains", func(c *gin.Context) {
		list := make([]model.ChainConfig, 0, len(model.Chains))
		for _, cfg := range model.Chains {
			list = append(list, cfg)
		}
		c.JSON(200, gin.H{"success": true, "chains": list})
	})

	// Auth handlers (public: login + registration flows only).
	authH := handler.NewAuthHandler(db, sdkClient, sessions, baseURL)
	r.GET("/api/auth/check-name", authH.CheckName)
	r.GET("/api/auth/passkey/options", authH.PasskeyOptions)
	r.POST("/api/auth/passkey/verify", authH.PasskeyVerify)
	r.POST("/api/auth/passkey/register/begin", authH.PasskeyRegistrationBegin)   // open registration
	r.GET("/api/auth/passkey/register/options", authH.PasskeyRegistrationOptions) // legacy: invite-token flow
	r.POST("/api/auth/passkey/register/verify", authH.PasskeyRegistrationVerify)

	// Protected routes (dual auth: API Key or Passkey session).
	rateLimiter       := handler.NewRateLimiter(apiKeyRateLimit, time.Minute)
	walletRateLimiter := handler.NewRateLimiter(walletCreateRateLimit, time.Minute)
	auth := r.Group("/api")
	auth.Use(handler.AuthMiddleware(db, sessions))
	auth.Use(handler.APIKeyRateLimitMiddleware(rateLimiter))

	// API Key management + session management (Passkey only).
	passkeyOnly := auth.Group("")
	passkeyOnly.Use(handler.PasskeyOnlyMiddleware())
	passkeyOnly.POST("/auth/invite", authH.InviteUser)          // admin action: Passkey only
	passkeyOnly.DELETE("/auth/session", authH.Logout)           // revoke current session
	passkeyOnly.DELETE("/auth/account", authH.DeleteAccount)    // delete account + all keys
	passkeyOnly.POST("/auth/apikey/generate", authH.GenerateAPIKey)
	passkeyOnly.GET("/auth/apikey/list", authH.ListAPIKeys)
	passkeyOnly.DELETE("/auth/apikey", authH.RevokeAPIKey)

	// Contract whitelist (dual-auth for read, Passkey-only for write).
	contractH := handler.NewContractHandler(db, sdkClient)
	auth.GET("/wallets/:id/contracts", contractH.ListContracts)
	auth.POST("/wallets/:id/contracts", contractH.AddContract)           // passkey: direct; apikey: pending approval
	passkeyOnly.DELETE("/wallets/:id/contracts/:cid", contractH.DeleteContract)

	// Wallet routes (API Key or Passkey).
	walletH := handler.NewWalletHandler(db, sdkClient, baseURL)
	auth.POST("/wallets", handler.APIKeyRateLimitMiddleware(walletRateLimiter), walletH.CreateWallet)
	auth.GET("/wallets", walletH.ListWallets)
	auth.GET("/wallets/:id", walletH.GetWallet)
	passkeyOnly.DELETE("/wallets/:id", walletH.DeleteWallet) // irreversible: Passkey only
	auth.POST("/wallets/:id/sign", walletH.Sign)
	auth.POST("/wallets/:id/transfer", walletH.Transfer) // backend builds+broadcasts tx
	auth.GET("/wallets/:id/pubkey", walletH.GetPubkey)
	auth.GET("/wallets/:id/policy", walletH.GetPolicy)        // read: API Key or Passkey
	auth.PUT("/wallets/:id/policy", walletH.SetPolicy)        // passkey: apply directly; API key: creates approval
	passkeyOnly.DELETE("/wallets/:id/policy", walletH.DeletePolicy) // irreversible: Passkey only

	// Balance (API Key or Passkey).
	balanceH := handler.NewBalanceHandler(db)
	auth.GET("/wallets/:id/balance", balanceH.GetBalance)

	// Audit log routes (dual-auth).
	auditH := handler.NewAuditHandler(db)
	auth.GET("/audit/logs", auditH.ListLogs)

	// Approval routes.
	approvalH := handler.NewApprovalHandler(db, sdkClient)
	auth.GET("/approvals/pending", approvalH.ListPending)
	auth.GET("/approvals/:id", approvalH.GetApproval)

	// Approve/reject: Passkey only.
	approveOnly := auth.Group("")
	approveOnly.Use(handler.PasskeyOnlyMiddleware())
	approveOnly.POST("/approvals/:id/approve", approvalH.Approve)
	approveOnly.POST("/approvals/:id/reject", approvalH.Reject)

	addr := host + ":" + port
	log.Printf("[openclaw-wallet] listening on %s", addr)
	log.Printf("[openclaw-wallet] CONSENSUS_URL=%s", consensusURL)
	log.Printf("[openclaw-wallet] BASE_URL=%s", baseURL)
	log.Printf("[openclaw-wallet] CHAINS_FILE=%s (%d chains loaded)", chainsFile, len(model.Chains))
	if err := r.Run(addr); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func envOrDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envOrDefaultInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func corsMiddleware(allowedOrigin string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", allowedOrigin)
		c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization,Content-Type")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
