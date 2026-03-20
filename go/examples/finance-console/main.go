package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	sdk "github.com/TEENet-io/teenet-sdk/go"
)

// ── Mock data types ────────────────────────────────────────────────────────────

type Product struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Token       string  `json:"token"`
	APY         string  `json:"apy"`
	Chain       string  `json:"chain"`
	Currency    string  `json:"currency"`
	Description string  `json:"description"`
	TotalSupply float64 `json:"total_supply"`
	NAV         float64 `json:"nav"`
}

type EpochPrice struct {
	ID      string    `json:"id"`
	PriceID string    `json:"price_id,omitempty"`
	Price   float64   `json:"price"`
	SetAt   time.Time `json:"set_at"`
}

type Epoch struct {
	ID             string       `json:"id"`
	ProductID      string       `json:"product_id"`
	EpochNumber    int          `json:"epoch_number"`
	Status         string       `json:"status"` // active, closed
	Price          float64      `json:"price"`
	SubscribeTotal float64      `json:"subscribe_total"`
	RedeemTotal    float64      `json:"redeem_total"`
	StartTime      time.Time    `json:"start_time"`
	EndTime        time.Time    `json:"end_time"`
	PriceHistory   []EpochPrice `json:"price_history,omitempty"`
	BoundPriceID   string       `json:"bound_price_id,omitempty"`
}

type Subscription struct {
	ID           string    `json:"id"`
	InvestorAddr string    `json:"investor_addr"`
	ProductID    string    `json:"product_id"`
	EpochID      string    `json:"epoch_id"`
	Amount       float64   `json:"amount"`
	Status       string    `json:"status"` // pending_approval, pending_tee_approval, approved, rejected, processing
	TxID         string    `json:"tx_id,omitempty"`
	RequestID    uint64    `json:"request_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type InvestorApplication struct {
	ID           string    `json:"id"`
	Address      string    `json:"address"`
	Organization string    `json:"organization"`
	KYCStatus    string    `json:"kyc_status"` // pending, approved, rejected, pending_tee_approval
	TxID         string    `json:"tx_id,omitempty"`
	RequestID    uint64    `json:"request_id,omitempty"`
	AppliedAt    time.Time `json:"applied_at"`
}

type AllowlistEntry struct {
	Address string    `json:"address"`
	AddedAt time.Time `json:"added_at"`
	Status  string    `json:"status"` // active, removed
}

// ── In-memory store ────────────────────────────────────────────────────────────

// pendingPriceUpdate tracks a set-price sign request that is awaiting approval.
type pendingPriceUpdate struct {
	EpochID   string
	Price     float64
	Hash      string
	TxID      string
	StoredAt  time.Time
	PriceDate time.Time // the calendar day the user clicked (YYYY-MM-DD, no carry-forward)
}

// pendingAllowlistUpdate tracks an allowlist change sign request that is awaiting approval.
type pendingAllowlistUpdate struct {
	Action   string // "add" or "remove"
	Address  string
	Hash     string
	TxID     string
	StoredAt time.Time
}

// pendingSubscriptionUpdate tracks a subscription approve/reject that is awaiting approval.
type pendingSubscriptionUpdate struct {
	SubID    string
	Action   string // "approve" or "reject"
	Hash     string
	TxID     string
	StoredAt time.Time
}

// pendingKYCUpdate tracks a KYC decision that is awaiting approval.
type pendingKYCUpdate struct {
	AppID    string
	Decision string // "approve" or "reject"
	Hash     string
	TxID     string
	StoredAt time.Time
}

type mockStore struct {
	mu                          sync.RWMutex
	products                    []Product
	epochs                      []Epoch
	subscriptions               []Subscription
	applications                []InvestorApplication
	allowlist                   []AllowlistEntry
	pendingPriceUpdates         map[string]pendingPriceUpdate         // keyed by hash
	pendingAllowlistUpdates     map[string]pendingAllowlistUpdate     // keyed by hash
	pendingSubscriptionUpdates  map[string]pendingSubscriptionUpdate  // keyed by hash
	pendingKYCUpdates           map[string]pendingKYCUpdate           // keyed by hash
}

func newMockStore() *mockStore {
	now := time.Now()
	return &mockStore{
		pendingPriceUpdates:        make(map[string]pendingPriceUpdate),
		pendingAllowlistUpdates:    make(map[string]pendingAllowlistUpdate),
		pendingSubscriptionUpdates: make(map[string]pendingSubscriptionUpdate),
		pendingKYCUpdates:          make(map[string]pendingKYCUpdate),
		products: []Product{
			{
				ID: "prod-usdf", Name: "USDF Money Market", Token: "USDF",
				APY: "5.2%", Chain: "Ethereum", Currency: "USD",
				Description: "A tokenized US Dollar money market fund with daily liquidity and T+0 redemption.",
				TotalSupply: 50_000_000, NAV: 1.0023,
			},
			{
				ID: "prod-bond", Name: "USDT Bond Fund", Token: "BOND",
				APY: "7.8%", Chain: "Polygon", Currency: "USD",
				Description: "A diversified bond fund investing in short-duration US Treasuries and AAA-rated corporates.",
				TotalSupply: 120_000_000, NAV: 10.4512,
			},
		},
		epochs: []Epoch{
			{
				ID: "ep-usdf-3", ProductID: "prod-usdf", EpochNumber: 3, Status: "active",
				Price: 1.0023, SubscribeTotal: 2_340_000, RedeemTotal: 890_000,
				StartTime: now.AddDate(0, 0, -7), EndTime: now.AddDate(0, 0, 7),
			},
			{
				ID: "ep-usdf-2", ProductID: "prod-usdf", EpochNumber: 2, Status: "closed",
				Price: 1.0021, SubscribeTotal: 1_890_000, RedeemTotal: 430_000,
				StartTime: now.AddDate(0, 0, -21), EndTime: now.AddDate(0, 0, -7),
			},
			{
				ID: "ep-usdf-1", ProductID: "prod-usdf", EpochNumber: 1, Status: "closed",
				Price: 1.0018, SubscribeTotal: 1_200_000, RedeemTotal: 200_000,
				StartTime: now.AddDate(0, 0, -35), EndTime: now.AddDate(0, 0, -21),
			},
			{
				ID: "ep-bond-5", ProductID: "prod-bond", EpochNumber: 5, Status: "active",
				Price: 10.4512, SubscribeTotal: 8_900_000, RedeemTotal: 1_200_000,
				StartTime: now.AddDate(0, 0, -14), EndTime: now.AddDate(0, 0, 14),
			},
			{
				ID: "ep-bond-4", ProductID: "prod-bond", EpochNumber: 4, Status: "closed",
				Price: 10.3891, SubscribeTotal: 6_500_000, RedeemTotal: 900_000,
				StartTime: now.AddDate(0, 0, -42), EndTime: now.AddDate(0, 0, -14),
			},
		},
		subscriptions: []Subscription{
			{ID: "sub-001", InvestorAddr: "0xAbcd...1234", ProductID: "prod-usdf", EpochID: "ep-usdf-3", Amount: 5_000_000, Status: "pending_approval", CreatedAt: now.Add(-2 * time.Hour)},
			{ID: "sub-002", InvestorAddr: "0xDef0...5678", ProductID: "prod-bond", EpochID: "ep-bond-5", Amount: 250_000, Status: "approved", CreatedAt: now.Add(-5 * time.Hour)},
			{ID: "sub-003", InvestorAddr: "0x1234...abcd", ProductID: "prod-usdf", EpochID: "ep-usdf-3", Amount: 10_000_000, Status: "pending_approval", CreatedAt: now.Add(-1 * time.Hour)},
			{ID: "sub-004", InvestorAddr: "0x5678...efgh", ProductID: "prod-bond", EpochID: "ep-bond-5", Amount: 800_000, Status: "approved", CreatedAt: now.Add(-24 * time.Hour)},
			{ID: "sub-005", InvestorAddr: "0x9abc...def0", ProductID: "prod-usdf", EpochID: "ep-usdf-3", Amount: 150_000, Status: "rejected", CreatedAt: now.Add(-48 * time.Hour)},
			{ID: "sub-006", InvestorAddr: "0xijkl...mnop", ProductID: "prod-bond", EpochID: "ep-bond-5", Amount: 2_000_000, Status: "processing", CreatedAt: now.Add(-3 * time.Hour)},
			{ID: "sub-007", InvestorAddr: "0xqrst...uvwx", ProductID: "prod-usdf", EpochID: "ep-usdf-3", Amount: 500_000, Status: "approved", CreatedAt: now.Add(-72 * time.Hour)},
			{ID: "sub-008", InvestorAddr: "0xyzab...cdef", ProductID: "prod-bond", EpochID: "ep-bond-5", Amount: 3_500_000, Status: "pending_approval", CreatedAt: now.Add(-30 * time.Minute)},
			{ID: "sub-009", InvestorAddr: "0x1111...2222", ProductID: "prod-usdf", EpochID: "ep-usdf-3", Amount: 75_000, Status: "approved", CreatedAt: now.Add(-96 * time.Hour)},
			{ID: "sub-010", InvestorAddr: "0x3333...4444", ProductID: "prod-bond", EpochID: "ep-bond-5", Amount: 1_200_000, Status: "approved", CreatedAt: now.Add(-120 * time.Hour)},
		},
		applications: []InvestorApplication{
			{ID: "app-001", Address: "0xAaBb...CcDd", Organization: "Alpha Capital LLC", KYCStatus: "pending", AppliedAt: now.Add(-3 * time.Hour)},
			{ID: "app-002", Address: "0xEeFf...GgHh", Organization: "Beta Investments Ltd", KYCStatus: "approved", AppliedAt: now.Add(-24 * time.Hour)},
			{ID: "app-003", Address: "0xIiJj...KkLl", Organization: "Gamma Hedge Fund", KYCStatus: "pending", AppliedAt: now.Add(-48 * time.Hour)},
			{ID: "app-004", Address: "0xMmNn...OoPp", Organization: "Delta Asset Management", KYCStatus: "rejected", AppliedAt: now.Add(-72 * time.Hour)},
			{ID: "app-005", Address: "0xQqRr...SsTt", Organization: "Epsilon Ventures", KYCStatus: "approved", AppliedAt: now.Add(-120 * time.Hour)},
		},
		allowlist: []AllowlistEntry{
			{Address: "0xA1B2C3D4E5F6789012345678901234567890ABCD", AddedAt: now.Add(-30 * 24 * time.Hour), Status: "active"},
			{Address: "0xB2C3D4E5F67890123456789012345678901BCDE", AddedAt: now.Add(-25 * 24 * time.Hour), Status: "active"},
			{Address: "0xC3D4E5F678901234567890123456789012CDEF0", AddedAt: now.Add(-20 * 24 * time.Hour), Status: "active"},
			{Address: "0xD4E5F6789012345678901234567890123DEF012", AddedAt: now.Add(-15 * 24 * time.Hour), Status: "active"},
			{Address: "0xE5F67890123456789012345678901234EF01234", AddedAt: now.Add(-10 * 24 * time.Hour), Status: "removed"},
		},
	}
}

// ── Server ─────────────────────────────────────────────────────────────────────

type sessionState struct {
	ApprovalToken string
	LoggedIn      bool // true after successful passkey login
}

type server struct {
	consensusURL   string
	appInstanceID  string
	frontendDir    string
	bootstrapToken string
	baseURL        string
	sdkClient      *sdk.Client
	store          *mockStore

	mu          sync.RWMutex
	sessions    map[string]*sessionState
	sdkClientMu sync.Mutex
}

var demoSessionPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{12,128}$`)

func main() {
	consensusURL := strings.TrimSpace(os.Getenv("CONSENSUS_URL"))
	if consensusURL == "" {
		consensusURL = "http://127.0.0.1:8089"
	}
	appInstanceID := strings.TrimSpace(os.Getenv("APP_INSTANCE_ID"))
	host := strings.TrimSpace(os.Getenv("DEMO_HOST"))
	if host == "" {
		host = "127.0.0.1"
	}
	port := strings.TrimSpace(os.Getenv("DEMO_PORT"))
	if port == "" {
		port = "18091"
	}
	bootstrapToken := strings.TrimSpace(os.Getenv("APPROVAL_TOKEN"))
	baseURL := strings.TrimSpace(os.Getenv("DEMO_BASE_URL"))
	if baseURL == "" {
		baseURL = "http://" + host + ":" + port
	}

	s := &server{
		consensusURL:   consensusURL,
		appInstanceID:  appInstanceID,
		bootstrapToken: bootstrapToken,
		baseURL:        baseURL,
		frontendDir:    detectFrontendDir(),
		sdkClient:      sdk.NewClient(consensusURL),
		store:          newMockStore(),
		sessions:       make(map[string]*sessionState),
	}
	if appInstanceID != "" {
		s.sdkClient.SetDefaultAppInstanceID(appInstanceID)
	}
	defer s.sdkClient.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)

	addr := host + ":" + port
	log.Printf("[finance-console] http://%s", addr)
	log.Printf("[finance-console] CONSENSUS_URL=%s", consensusURL)
	if appInstanceID == "" {
		log.Printf("[finance-console] APP_INSTANCE_ID=(missing — sign ops will fail)")
	} else {
		log.Printf("[finance-console] APP_INSTANCE_ID=%s", appInstanceID)
	}

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func (s *server) handle(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		s.handleAPI(w, r)
		return
	}
	s.serveStatic(w, r)
}

// ── API router ─────────────────────────────────────────────────────────────────

func (s *server) handleAPI(w http.ResponseWriter, r *http.Request) {
	sid := s.ensureSessionID(w, r)
	state := s.getSession(sid)
	withClient := func(token string, fn func(client *sdk.Client, approvalToken string) error) error {
		s.sdkClientMu.Lock()
		defer s.sdkClientMu.Unlock()
		return fn(s.sdkClient, token)
	}

	// ── Dashboard stats ──────────────────────────────────────────────────────
	if r.Method == http.MethodGet && r.URL.Path == "/api/dashboard/stats" {
		s.store.mu.RLock()
		pendingApprovals := 0
		todaySubs := 0
		todayAmount := 0.0
		today := time.Now().Truncate(24 * time.Hour)
		for _, sub := range s.store.subscriptions {
			if sub.Status == "pending_approval" || sub.Status == "pending_tee_approval" {
				pendingApprovals++
			}
			if sub.CreatedAt.After(today) {
				todaySubs++
				todayAmount += sub.Amount
			}
		}
		activeEpochs := 0
		for _, ep := range s.store.epochs {
			if ep.Status == "active" {
				activeEpochs++
			}
		}
		result := map[string]interface{}{
			"products":       len(s.store.products),
			"active_epochs":  activeEpochs,
			"pending_approvals": pendingApprovals,
			"today_subs":     todaySubs,
			"today_amount":   todayAmount,
		}
		s.store.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": result})
		return
	}

	// ── Products ─────────────────────────────────────────────────────────────
	if r.Method == http.MethodGet && r.URL.Path == "/api/products" {
		s.store.mu.RLock()
		products := s.store.products
		s.store.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "products": products})
		return
	}

	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/products/") {
		id := strings.TrimPrefix(r.URL.Path, "/api/products/")
		s.store.mu.RLock()
		var found *Product
		for i := range s.store.products {
			if s.store.products[i].ID == id {
				found = &s.store.products[i]
				break
			}
		}
		s.store.mu.RUnlock()
		if found == nil {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "product not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "product": found})
		return
	}

	// ── Products: Create ─────────────────────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/products" {
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		name := strings.TrimSpace(toString(body["name"]))
		token := strings.TrimSpace(toString(body["token"]))
		if name == "" || token == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "name and token are required"})
			return
		}
		totalSupply, _ := body["total_supply"].(json.Number)
		tsVal, _ := totalSupply.Float64()
		nav, _ := body["nav"].(json.Number)
		navVal, _ := nav.Float64()
		p := Product{
			ID:          newID("prod-"),
			Name:        name,
			Token:       token,
			APY:         strings.TrimSpace(toString(body["apy"])),
			Chain:       strings.TrimSpace(toString(body["chain"])),
			Currency:    strings.TrimSpace(toString(body["currency"])),
			Description: strings.TrimSpace(toString(body["description"])),
			TotalSupply: tsVal,
			NAV:         navVal,
		}
		s.store.mu.Lock()
		s.store.products = append(s.store.products, p)
		s.store.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "product": p})
		return
	}

	// ── Products: Update ─────────────────────────────────────────────────────
	if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/products/") {
		id := strings.TrimPrefix(r.URL.Path, "/api/products/")
		if id == "" || strings.Contains(id, "/") {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid product id"})
			return
		}
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		s.store.mu.Lock()
		var updated *Product
		for i := range s.store.products {
			if s.store.products[i].ID == id {
				if v := toString(body["name"]); v != "" {
					s.store.products[i].Name = v
				}
				if v := toString(body["token"]); v != "" {
					s.store.products[i].Token = v
				}
				if v := toString(body["apy"]); v != "" {
					s.store.products[i].APY = v
				}
				if v := toString(body["chain"]); v != "" {
					s.store.products[i].Chain = v
				}
				if v := toString(body["currency"]); v != "" {
					s.store.products[i].Currency = v
				}
				if v := toString(body["description"]); v != "" {
					s.store.products[i].Description = v
				}
				if n, ok := body["total_supply"].(json.Number); ok {
					if val, err := n.Float64(); err == nil {
						s.store.products[i].TotalSupply = val
					}
				}
				if n, ok := body["nav"].(json.Number); ok {
					if val, err := n.Float64(); err == nil {
						s.store.products[i].NAV = val
					}
				}
				updated = &s.store.products[i]
				break
			}
		}
		s.store.mu.Unlock()
		if updated == nil {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "product not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "product": updated})
		return
	}

	// ── Products: Delete ─────────────────────────────────────────────────────
	if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/products/") {
		id := strings.TrimPrefix(r.URL.Path, "/api/products/")
		if id == "" || strings.Contains(id, "/") {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid product id"})
			return
		}
		s.store.mu.Lock()
		found := false
		newProducts := s.store.products[:0]
		for _, p := range s.store.products {
			if p.ID == id {
				found = true
				continue
			}
			newProducts = append(newProducts, p)
		}
		s.store.products = newProducts
		s.store.mu.Unlock()
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "product not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": "product deleted"})
		return
	}

	// ── Epochs ───────────────────────────────────────────────────────────────
	if r.Method == http.MethodGet && r.URL.Path == "/api/epochs" {
		productID := r.URL.Query().Get("product_id")
		s.store.mu.RLock()
		var result []Epoch
		for _, ep := range s.store.epochs {
			if productID == "" || ep.ProductID == productID {
				result = append(result, ep)
			}
		}
		s.store.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "epochs": result})
		return
	}

	// ── Epochs: Without price ─────────────────────────────────────────────────
	if r.Method == http.MethodGet && r.URL.Path == "/api/epochs/without-price" {
		productID := r.URL.Query().Get("product_id")
		s.store.mu.RLock()
		var result []Epoch
		for _, ep := range s.store.epochs {
			if ep.Status != "active" {
				continue
			}
			if productID != "" && ep.ProductID != productID {
				continue
			}
			if ep.BoundPriceID == "" {
				result = append(result, ep)
			}
		}
		s.store.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "epochs": result})
		return
	}

	// ── Epochs: Price history ─────────────────────────────────────────────────
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/epochs/") && strings.HasSuffix(r.URL.Path, "/prices") {
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/epochs/"), "/prices")
		if id == "" || strings.Contains(id, "/") {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid epoch id"})
			return
		}
		s.store.mu.RLock()
		var history []EpochPrice
		for _, ep := range s.store.epochs {
			if ep.ID == id {
				history = ep.PriceHistory
				break
			}
		}
		s.store.mu.RUnlock()
		if history == nil {
			history = []EpochPrice{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "prices": history})
		return
	}

	// ── Epochs: Create ────────────────────────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/epochs" {
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		productID := strings.TrimSpace(toString(body["product_id"]))
		if productID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "product_id is required"})
			return
		}
		s.store.mu.RLock()
		productExists := false
		maxEpochNum := 0
		for _, p := range s.store.products {
			if p.ID == productID {
				productExists = true
				break
			}
		}
		for _, ep := range s.store.epochs {
			if ep.ProductID == productID && ep.EpochNumber > maxEpochNum {
				maxEpochNum = ep.EpochNumber
			}
		}
		s.store.mu.RUnlock()
		if !productExists {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "product not found"})
			return
		}
		priceNum, _ := body["price"].(json.Number)
		priceVal, _ := priceNum.Float64()
		startTime := time.Now()
		endTime := startTime.AddDate(0, 0, 14)
		if st, ok := body["start_time"].(string); ok && st != "" {
			if t, err := time.Parse(time.RFC3339, st); err == nil {
				startTime = t
			}
		}
		if et, ok := body["end_time"].(string); ok && et != "" {
			if t, err := time.Parse(time.RFC3339, et); err == nil {
				endTime = t
			}
		}
		ep := Epoch{
			ID:          newID("ep-"),
			ProductID:   productID,
			EpochNumber: maxEpochNum + 1,
			Status:      "active",
			Price:       priceVal,
			StartTime:   startTime,
			EndTime:     endTime,
		}
		s.store.mu.Lock()
		s.store.epochs = append(s.store.epochs, ep)
		s.store.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "epoch": ep})
		return
	}

	// ── Epochs: Update ────────────────────────────────────────────────────────
	if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/epochs/") && !strings.Contains(strings.TrimPrefix(r.URL.Path, "/api/epochs/"), "/") {
		id := strings.TrimPrefix(r.URL.Path, "/api/epochs/")
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		s.store.mu.Lock()
		var updated *Epoch
		for i := range s.store.epochs {
			if s.store.epochs[i].ID == id {
				if n, ok := body["price"].(json.Number); ok {
					if val, err := n.Float64(); err == nil {
						s.store.epochs[i].Price = val
					}
				}
				if st, ok := body["start_time"].(string); ok && st != "" {
					if t, err := time.Parse(time.RFC3339, st); err == nil {
						s.store.epochs[i].StartTime = t
					}
				}
				if et, ok := body["end_time"].(string); ok && et != "" {
					if t, err := time.Parse(time.RFC3339, et); err == nil {
						s.store.epochs[i].EndTime = t
					}
				}
				updated = &s.store.epochs[i]
				break
			}
		}
		s.store.mu.Unlock()
		if updated == nil {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "epoch not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "epoch": updated})
		return
	}

	// ── Epochs: Close ─────────────────────────────────────────────────────────
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/epochs/") && strings.HasSuffix(r.URL.Path, "/close") {
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/epochs/"), "/close")
		if id == "" || strings.Contains(id, "/") {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid epoch id"})
			return
		}
		s.store.mu.Lock()
		found := false
		for i := range s.store.epochs {
			if s.store.epochs[i].ID == id {
				s.store.epochs[i].Status = "closed"
				s.store.epochs[i].EndTime = time.Now()
				found = true
				break
			}
		}
		s.store.mu.Unlock()
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "epoch not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": "epoch closed"})
		return
	}

	// ── Epochs: Bind price ID ─────────────────────────────────────────────────
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/epochs/") && strings.HasSuffix(r.URL.Path, "/bind-price") {
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/epochs/"), "/bind-price")
		if id == "" || strings.Contains(id, "/") {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid epoch id"})
			return
		}
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		priceID := strings.TrimSpace(toString(body["price_id"]))
		priceNum, _ := body["price"].(json.Number)
		priceVal, _ := priceNum.Float64()
		if priceID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "price_id is required"})
			return
		}
		s.store.mu.Lock()
		found := false
		for i := range s.store.epochs {
			if s.store.epochs[i].ID == id {
				s.store.epochs[i].BoundPriceID = priceID
				if priceVal > 0 {
					s.store.epochs[i].Price = priceVal
					s.store.epochs[i].PriceHistory = append([]EpochPrice{{
						ID:      newID("ep-price-"),
						PriceID: priceID,
						Price:   priceVal,
						SetAt:   time.Now(),
					}}, s.store.epochs[i].PriceHistory...)
				}
				found = true
				break
			}
		}
		s.store.mu.Unlock()
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "epoch not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": "price bound", "price_id": priceID})
		return
	}

	// ── Subscriptions ────────────────────────────────────────────────────────
	if r.Method == http.MethodGet && r.URL.Path == "/api/subscriptions" {
		query := r.URL.Query()
		productID := query.Get("product_id")
		status := query.Get("status")
		page, _ := strconv.Atoi(query.Get("page"))
		limit, _ := strconv.Atoi(query.Get("limit"))
		if limit <= 0 {
			limit = 20
		}

		s.store.mu.RLock()
		var result []Subscription
		for _, sub := range s.store.subscriptions {
			if productID != "" && sub.ProductID != productID {
				continue
			}
			if status != "" && sub.Status != status {
				continue
			}
			result = append(result, sub)
		}
		total := len(result)
		// paginate
		start := page * limit
		if start > total {
			start = total
		}
		end := start + limit
		if end > total {
			end = total
		}
		result = result[start:end]
		s.store.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "subscriptions": result, "total": total})
		return
	}

	// ── Investor applications: List ───────────────────────────────────────────
	if r.Method == http.MethodGet && r.URL.Path == "/api/applications" {
		query := r.URL.Query()
		statusFilter := strings.TrimSpace(query.Get("status"))
		keyword := strings.ToLower(strings.TrimSpace(query.Get("keyword")))
		page, _ := strconv.Atoi(query.Get("page"))
		limit, _ := strconv.Atoi(query.Get("limit"))
		if limit <= 0 {
			limit = 20
		}

		s.store.mu.RLock()
		var result []InvestorApplication
		for _, app := range s.store.applications {
			if statusFilter != "" && app.KYCStatus != statusFilter {
				continue
			}
			if keyword != "" {
				if !strings.Contains(strings.ToLower(app.Address), keyword) &&
					!strings.Contains(strings.ToLower(app.Organization), keyword) {
					continue
				}
			}
			result = append(result, app)
		}
		s.store.mu.RUnlock()

		total := len(result)
		start := page * limit
		if start > total {
			start = total
		}
		end := start + limit
		if end > total {
			end = total
		}
		result = result[start:end]
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "applications": result, "total": total})
		return
	}

	// ── Investor applications: Create ─────────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/applications" {
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		address := strings.TrimSpace(toString(body["address"]))
		organization := strings.TrimSpace(toString(body["organization"]))
		if address == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "address is required"})
			return
		}
		app := InvestorApplication{
			ID:           newID("app-"),
			Address:      address,
			Organization: organization,
			KYCStatus:    "pending",
			AppliedAt:    time.Now(),
		}
		s.store.mu.Lock()
		s.store.applications = append(s.store.applications, app)
		s.store.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "application": app})
		return
	}

	// ── Investor applications: Update ─────────────────────────────────────────
	if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/applications/") {
		id := strings.TrimPrefix(r.URL.Path, "/api/applications/")
		if id == "" || strings.Contains(id, "/") {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid application id"})
			return
		}
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		s.store.mu.Lock()
		var updated *InvestorApplication
		for i := range s.store.applications {
			if s.store.applications[i].ID == id {
				if v := toString(body["organization"]); v != "" {
					s.store.applications[i].Organization = v
				}
				if v := toString(body["address"]); v != "" {
					s.store.applications[i].Address = v
				}
				updated = &s.store.applications[i]
				break
			}
		}
		s.store.mu.Unlock()
		if updated == nil {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "application not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "application": updated})
		return
	}

	// ── Allowlist ─────────────────────────────────────────────────────────────
	if r.Method == http.MethodGet && r.URL.Path == "/api/allowlist" {
		s.store.mu.RLock()
		list := s.store.allowlist
		s.store.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "allowlist": list})
		return
	}

	// ── TEENet: Set epoch price ───────────────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/epochs/set-price" {
		if s.appInstanceID == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "APP_INSTANCE_ID is not configured"})
			return
		}
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		epochID := toString(body["epoch_id"])
		newPrice, _ := body["new_price"].(json.Number)
		priceVal, _ := newPrice.Float64()
		publicKeyName := toString(body["public_key_name"])
		if epochID == "" || priceVal <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "epoch_id and new_price are required"})
			return
		}
		// Optional price_date (YYYY-MM-DD) from calendar click; defaults to today.
		priceDate := time.Now()
		if dateStr := strings.TrimSpace(toString(body["price_date"])); dateStr != "" {
			if parsed, err := time.ParseInLocation("2006-01-02", dateStr, time.Local); err == nil {
				priceDate = parsed
			}
		}

		// find epoch
		s.store.mu.RLock()
		var epochFound bool
		for _, ep := range s.store.epochs {
			if ep.ID == epochID {
				epochFound = true
				break
			}
		}
		s.store.mu.RUnlock()
		if !epochFound {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "epoch not found"})
			return
		}

		payload, _ := json.Marshal(map[string]interface{}{
			"operation":  "SET_EPOCH_PRICE",
			"epoch_id":   epochID,
			"new_price":  priceVal,
			"timestamp":  time.Now().Unix(),
			"initiated_by": "finance-console",
		})

		if !state.LoggedIn {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "passkey login required to perform signing operations"})
			return
		}
		var signRes *sdk.SignResult
		callErr := withClient(state.ApprovalToken, func(client *sdk.Client, approvalToken string) error {
			client.SetDefaultAppInstanceID(s.appInstanceID)
			var err error
			signRes, err = client.Sign(r.Context(), hashForSign(payload), publicKeyName, approvalToken)
			return err
		})

		resp := buildSignResponse(signRes, callErr, "SET_EPOCH_PRICE")
		if resp["sign_success"] == true {
			// Signed immediately (direct / voting mode) — update price now.
			s.applyPriceUpdate(epochID, priceVal, priceDate)
			resp["epoch_id"] = epochID
			resp["new_price"] = priceVal
		} else if signRes != nil && signRes.ErrorCode == "APPROVAL_PENDING" && signRes.VotingInfo != nil {
			// Approval pending — store the intent so we can apply it once signed.
			hash := signRes.VotingInfo.Hash
			txID := signRes.VotingInfo.TxID
			if hash != "" {
				s.store.mu.Lock()
				s.store.pendingPriceUpdates[hash] = pendingPriceUpdate{
					EpochID:   epochID,
					Price:     priceVal,
					Hash:      hash,
					TxID:      txID,
					StoredAt:  time.Now(),
					PriceDate: priceDate,
				}
				s.store.mu.Unlock()
			}
			resp["epoch_id"] = epochID
			resp["new_price"] = priceVal
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": resp})
		return
	}

	// ── Epochs: Poll pending price update ────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/epochs/poll-price" {
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		hash := strings.TrimSpace(toString(body["hash"]))
		if hash == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "hash is required"})
			return
		}
		s.store.mu.RLock()
		pending, ok := s.store.pendingPriceUpdates[hash]
		s.store.mu.RUnlock()
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "no pending price update found for this hash"})
			return
		}
		// Query consensus cache for signature status.
		var status *sdk.VoteStatus
		err := withClient("", func(client *sdk.Client, _ string) error {
			var e error
			status, e = client.GetStatus(r.Context(), hash)
			return e
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": "failed to query status: " + err.Error()})
			return
		}
		if status == nil || !status.Found {
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "status": "pending", "message": "approval still in progress"})
			return
		}
		if status.Status == "signed" {
			s.applyPriceUpdate(pending.EpochID, pending.Price, pending.PriceDate)
			s.store.mu.Lock()
			delete(s.store.pendingPriceUpdates, hash)
			s.store.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"success":   true,
				"status":    "signed",
				"epoch_id":  pending.EpochID,
				"new_price": pending.Price,
			})
			return
		}
		// still pending or failed
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "status": status.Status})
		return
	}

	// ── Subscriptions: Create ────────────────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/subscriptions" {
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		investorAddr := strings.TrimSpace(toString(body["investor_addr"]))
		productID := strings.TrimSpace(toString(body["product_id"]))
		epochID := strings.TrimSpace(toString(body["epoch_id"]))
		if investorAddr == "" || productID == "" || epochID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "investor_addr, product_id and epoch_id are required"})
			return
		}
		amountNum, _ := body["amount"].(json.Number)
		amount, _ := amountNum.Float64()
		sub := Subscription{
			ID:           newID("sub-"),
			InvestorAddr: investorAddr,
			ProductID:    productID,
			EpochID:      epochID,
			Amount:       amount,
			Status:       "pending_approval",
			CreatedAt:    time.Now(),
		}
		s.store.mu.Lock()
		s.store.subscriptions = append(s.store.subscriptions, sub)
		s.store.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "subscription": sub})
		return
	}

	// ── TEENet: Reject subscription ───────────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/subscriptions/reject" {
		if s.appInstanceID == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "APP_INSTANCE_ID is not configured"})
			return
		}
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		subID := toString(body["subscription_id"])
		publicKeyName := toString(body["public_key_name"])
		if subID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "subscription_id is required"})
			return
		}

		s.store.mu.RLock()
		var sub *Subscription
		for i := range s.store.subscriptions {
			if s.store.subscriptions[i].ID == subID {
				sub = &s.store.subscriptions[i]
				break
			}
		}
		s.store.mu.RUnlock()
		if sub == nil {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "subscription not found"})
			return
		}

		payload, _ := json.Marshal(map[string]interface{}{
			"operation":       "REJECT_SUBSCRIPTION",
			"subscription_id": subID,
			"investor_addr":   sub.InvestorAddr,
			"product_id":      sub.ProductID,
			"amount":          sub.Amount,
			"reason":          toString(body["reason"]),
			"timestamp":       time.Now().Unix(),
		})

		if !state.LoggedIn {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "passkey login required to perform signing operations"})
			return
		}
		var signRes *sdk.SignResult
		callErr := withClient(state.ApprovalToken, func(client *sdk.Client, approvalToken string) error {
			client.SetDefaultAppInstanceID(s.appInstanceID)
			var err error
			signRes, err = client.Sign(r.Context(), hashForSign(payload), publicKeyName, approvalToken)
			return err
		})

		resp := buildSignResponse(signRes, callErr, "REJECT_SUBSCRIPTION")
		s.store.mu.Lock()
		for i := range s.store.subscriptions {
			if s.store.subscriptions[i].ID == subID {
				if resp["sign_success"] == true {
					s.store.subscriptions[i].Status = "rejected"
				} else if resp["error_code"] == "APPROVAL_PENDING" {
					s.store.subscriptions[i].Status = "pending_tee_approval"
				}
				break
			}
		}
		s.store.mu.Unlock()
		if signRes != nil && signRes.ErrorCode == "APPROVAL_PENDING" && signRes.VotingInfo != nil {
			if hash := signRes.VotingInfo.Hash; hash != "" {
				s.store.mu.Lock()
				s.store.pendingSubscriptionUpdates[hash] = pendingSubscriptionUpdate{
					SubID: subID, Action: "reject", Hash: hash,
					TxID: signRes.VotingInfo.TxID, StoredAt: time.Now(),
				}
				s.store.mu.Unlock()
			}
		}
		resp["subscription_id"] = subID
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": resp})
		return
	}

	// ── TEENet: Approve subscription ──────────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/subscriptions/approve" {
		if s.appInstanceID == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "APP_INSTANCE_ID is not configured"})
			return
		}
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		subID := toString(body["subscription_id"])
		publicKeyName := toString(body["public_key_name"])
		if subID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "subscription_id is required"})
			return
		}

		s.store.mu.RLock()
		var sub *Subscription
		for i := range s.store.subscriptions {
			if s.store.subscriptions[i].ID == subID {
				sub = &s.store.subscriptions[i]
				break
			}
		}
		s.store.mu.RUnlock()
		if sub == nil {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "subscription not found"})
			return
		}

		payload, _ := json.Marshal(map[string]interface{}{
			"operation":     "APPROVE_SUBSCRIPTION",
			"subscription_id": subID,
			"investor_addr": sub.InvestorAddr,
			"product_id":    sub.ProductID,
			"amount":        sub.Amount,
			"timestamp":     time.Now().Unix(),
		})

		if !state.LoggedIn {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "passkey login required to perform signing operations"})
			return
		}
		var signRes *sdk.SignResult
		callErr := withClient(state.ApprovalToken, func(client *sdk.Client, approvalToken string) error {
			client.SetDefaultAppInstanceID(s.appInstanceID)
			var err error
			signRes, err = client.Sign(r.Context(), hashForSign(payload), publicKeyName, approvalToken)
			return err
		})

		resp := buildSignResponse(signRes, callErr, "APPROVE_SUBSCRIPTION")
		s.store.mu.Lock()
		for i := range s.store.subscriptions {
			if s.store.subscriptions[i].ID == subID {
				if resp["sign_success"] == true {
					s.store.subscriptions[i].Status = "approved"
				} else if resp["error_code"] == "APPROVAL_PENDING" {
					s.store.subscriptions[i].Status = "pending_tee_approval"
					if reqID, ok := resp["request_id"].(uint64); ok {
						s.store.subscriptions[i].RequestID = reqID
					}
					if txID, ok := resp["tx_id"].(string); ok {
						s.store.subscriptions[i].TxID = txID
					}
				}
				break
			}
		}
		s.store.mu.Unlock()
		if signRes != nil && signRes.ErrorCode == "APPROVAL_PENDING" && signRes.VotingInfo != nil {
			if hash := signRes.VotingInfo.Hash; hash != "" {
				s.store.mu.Lock()
				s.store.pendingSubscriptionUpdates[hash] = pendingSubscriptionUpdate{
					SubID: subID, Action: "approve", Hash: hash,
					TxID: signRes.VotingInfo.TxID, StoredAt: time.Now(),
				}
				s.store.mu.Unlock()
			}
		}
		resp["subscription_id"] = subID
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": resp})
		return
	}

	// ── TEENet: Update allowlist ──────────────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/allowlist/update" {
		if s.appInstanceID == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "APP_INSTANCE_ID is not configured"})
			return
		}
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		action := toString(body["action"]) // "add" or "remove"
		address := strings.TrimSpace(toString(body["address"]))
		publicKeyName := toString(body["public_key_name"])
		if action == "" || address == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "action and address are required"})
			return
		}

		payload, _ := json.Marshal(map[string]interface{}{
			"operation": "UPDATE_ALLOWLIST",
			"action":    action,
			"address":   address,
			"timestamp": time.Now().Unix(),
		})

		if !state.LoggedIn {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "passkey login required to perform signing operations"})
			return
		}
		var signRes *sdk.SignResult
		callErr := withClient(state.ApprovalToken, func(client *sdk.Client, approvalToken string) error {
			client.SetDefaultAppInstanceID(s.appInstanceID)
			var err error
			signRes, err = client.Sign(r.Context(), hashForSign(payload), publicKeyName, approvalToken)
			return err
		})

		resp := buildSignResponse(signRes, callErr, "UPDATE_ALLOWLIST")
		if resp["sign_success"] == true {
			s.applyAllowlistUpdate(action, address)
		} else if signRes != nil && signRes.ErrorCode == "APPROVAL_PENDING" && signRes.VotingInfo != nil {
			hash := signRes.VotingInfo.Hash
			txID := signRes.VotingInfo.TxID
			if hash != "" {
				s.store.mu.Lock()
				s.store.pendingAllowlistUpdates[hash] = pendingAllowlistUpdate{
					Action:   action,
					Address:  address,
					Hash:     hash,
					TxID:     txID,
					StoredAt: time.Now(),
				}
				s.store.mu.Unlock()
			}
		}
		resp["action"] = action
		resp["address"] = address
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": resp})
		return
	}

	// ── Allowlist: Poll pending update ────────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/allowlist/poll" {
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		hash := strings.TrimSpace(toString(body["hash"]))
		if hash == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "hash is required"})
			return
		}
		s.store.mu.RLock()
		pending, ok := s.store.pendingAllowlistUpdates[hash]
		s.store.mu.RUnlock()
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "no pending allowlist update found for this hash"})
			return
		}
		var status *sdk.VoteStatus
		err := withClient("", func(client *sdk.Client, _ string) error {
			var e error
			status, e = client.GetStatus(r.Context(), hash)
			return e
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": "failed to query status: " + err.Error()})
			return
		}
		if status == nil || !status.Found {
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "status": "pending", "message": "approval still in progress"})
			return
		}
		if status.Status == "signed" {
			s.applyAllowlistUpdate(pending.Action, pending.Address)
			s.store.mu.Lock()
			delete(s.store.pendingAllowlistUpdates, hash)
			s.store.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"success": true,
				"status":  "signed",
				"action":  pending.Action,
				"address": pending.Address,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "status": status.Status})
		return
	}

	// ── Subscriptions: Poll pending update ───────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/subscriptions/poll" {
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		hash := strings.TrimSpace(toString(body["hash"]))
		if hash == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "hash is required"})
			return
		}
		s.store.mu.RLock()
		pending, ok := s.store.pendingSubscriptionUpdates[hash]
		s.store.mu.RUnlock()
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "no pending subscription update found for this hash"})
			return
		}
		var status *sdk.VoteStatus
		err := withClient("", func(client *sdk.Client, _ string) error {
			var e error
			status, e = client.GetStatus(r.Context(), hash)
			return e
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": "failed to query status: " + err.Error()})
			return
		}
		if status == nil || !status.Found {
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "status": "pending"})
			return
		}
		if status.Status == "signed" {
			s.applySubscriptionUpdate(pending.SubID, pending.Action)
			s.store.mu.Lock()
			delete(s.store.pendingSubscriptionUpdates, hash)
			s.store.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"success":         true,
				"status":          "signed",
				"action":          pending.Action,
				"subscription_id": pending.SubID,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "status": status.Status})
		return
	}

	// ── Applications: Poll pending KYC update ────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/applications/poll" {
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		hash := strings.TrimSpace(toString(body["hash"]))
		if hash == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "hash is required"})
			return
		}
		s.store.mu.RLock()
		pending, ok := s.store.pendingKYCUpdates[hash]
		s.store.mu.RUnlock()
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "no pending KYC update found for this hash"})
			return
		}
		var status *sdk.VoteStatus
		err := withClient("", func(client *sdk.Client, _ string) error {
			var e error
			status, e = client.GetStatus(r.Context(), hash)
			return e
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": "failed to query status: " + err.Error()})
			return
		}
		if status == nil || !status.Found {
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "status": "pending"})
			return
		}
		if status.Status == "signed" {
			s.applyKYCUpdate(pending.AppID, pending.Decision)
			s.store.mu.Lock()
			delete(s.store.pendingKYCUpdates, hash)
			s.store.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"success":        true,
				"status":         "signed",
				"decision":       pending.Decision,
				"application_id": pending.AppID,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "status": status.Status})
		return
	}

	// ── TEENet: KYC approve ───────────────────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/applications/kyc-approve" {
		if s.appInstanceID == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "APP_INSTANCE_ID is not configured"})
			return
		}
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		appID := toString(body["application_id"])
		decision := toString(body["decision"]) // "approve" or "reject"
		publicKeyName := toString(body["public_key_name"])
		if appID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "application_id is required"})
			return
		}
		if decision == "" {
			decision = "approve"
		}

		s.store.mu.RLock()
		var app *InvestorApplication
		for i := range s.store.applications {
			if s.store.applications[i].ID == appID {
				app = &s.store.applications[i]
				break
			}
		}
		s.store.mu.RUnlock()
		if app == nil {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "application not found"})
			return
		}

		payload, _ := json.Marshal(map[string]interface{}{
			"operation":      "KYC_DECISION",
			"application_id": appID,
			"address":        app.Address,
			"organization":   app.Organization,
			"decision":       decision,
			"timestamp":      time.Now().Unix(),
		})

		if !state.LoggedIn {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "passkey login required to perform signing operations"})
			return
		}
		var signRes *sdk.SignResult
		callErr := withClient(state.ApprovalToken, func(client *sdk.Client, approvalToken string) error {
			client.SetDefaultAppInstanceID(s.appInstanceID)
			var err error
			signRes, err = client.Sign(r.Context(), hashForSign(payload), publicKeyName, approvalToken)
			return err
		})

		resp := buildSignResponse(signRes, callErr, "KYC_DECISION")
		s.store.mu.Lock()
		for i := range s.store.applications {
			if s.store.applications[i].ID == appID {
				if resp["sign_success"] == true {
					if decision == "approve" {
						s.store.applications[i].KYCStatus = "approved"
					} else {
						s.store.applications[i].KYCStatus = "rejected"
					}
				} else if resp["error_code"] == "APPROVAL_PENDING" {
					s.store.applications[i].KYCStatus = "pending_tee_approval"
					if reqID, ok := resp["request_id"].(uint64); ok {
						s.store.applications[i].RequestID = reqID
					}
					if txID, ok := resp["tx_id"].(string); ok {
						s.store.applications[i].TxID = txID
					}
				}
				break
			}
		}
		s.store.mu.Unlock()
		if signRes != nil && signRes.ErrorCode == "APPROVAL_PENDING" && signRes.VotingInfo != nil {
			if hash := signRes.VotingInfo.Hash; hash != "" {
				s.store.mu.Lock()
				s.store.pendingKYCUpdates[hash] = pendingKYCUpdate{
					AppID: appID, Decision: decision, Hash: hash,
					TxID: signRes.VotingInfo.TxID, StoredAt: time.Now(),
				}
				s.store.mu.Unlock()
			}
		}
		resp["application_id"] = appID
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": resp})
		return
	}

	// ── Generate key ──────────────────────────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/generate-key" {
		if s.appInstanceID == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "APP_INSTANCE_ID is not configured"})
			return
		}
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		protocol := strings.ToLower(strings.TrimSpace(toString(body["protocol"])))
		curve := strings.ToLower(strings.TrimSpace(toString(body["curve"])))
		if curve == "" {
			curve = "ed25519"
		}
		var res *sdk.GenerateKeyResult
		callErr := withClient("", func(client *sdk.Client, _ string) error {
			client.SetDefaultAppInstanceID(s.appInstanceID)
			var err error
			if protocol == "ecdsa" {
				res, err = client.GenerateECDSAKey(r.Context(), curve)
			} else {
				res, err = client.GenerateSchnorrKey(r.Context(), curve)
			}
			return err
		})
		if callErr != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": callErr.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	// ── Get status by hash ────────────────────────────────────────────────────
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/status/") {
		hash := strings.TrimPrefix(r.URL.Path, "/api/status/")
		hash, _ = url.QueryUnescape(hash)
		hash = strings.TrimSpace(hash)
		if hash == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "hash is required"})
			return
		}
		var voteStatus *sdk.VoteStatus
		callErr := withClient("", func(client *sdk.Client, _ string) error {
			var err error
			voteStatus, err = client.GetStatus(r.Context(), hash)
			return err
		})
		if callErr != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": callErr.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": voteStatus})
		return
	}

	// ── Sign (generic) ────────────────────────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/sign" {
		if s.appInstanceID == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "APP_INSTANCE_ID is not configured"})
			return
		}
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		publicKeyName := strings.TrimSpace(toString(body["public_key_name"]))
		if publicKeyName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "public_key_name is required"})
			return
		}
		message, err := buildSignMessageBytes(body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		if !state.LoggedIn {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "passkey login required to perform signing operations"})
			return
		}
		var signRes *sdk.SignResult
		callErr := withClient(state.ApprovalToken, func(client *sdk.Client, approvalToken string) error {
			client.SetDefaultAppInstanceID(s.appInstanceID)
			var innerErr error
			signRes, innerErr = client.Sign(r.Context(), message, publicKeyName, approvalToken)
			return innerErr
		})
		resp := buildSignResponse(signRes, callErr, "GENERIC_SIGN")
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": resp})
		return
	}

	// ── Public keys ───────────────────────────────────────────────────────────
	if r.Method == http.MethodGet && r.URL.Path == "/api/public-keys" {
		if s.appInstanceID == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "APP_INSTANCE_ID is not configured"})
			return
		}
		var keys []sdk.PublicKeyInfo
		err := withClient("", func(client *sdk.Client, _ string) error {
			client.SetDefaultAppInstanceID(s.appInstanceID)
			var callErr error
			keys, callErr = client.GetPublicKeys(r.Context())
			return callErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "keys": keys})
		return
	}

	// ── Passkey: Login options ────────────────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/logout" {
		s.mu.Lock()
		state.ApprovalToken = s.bootstrapToken
		state.LoggedIn = false
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
		return
	}

	if r.Method == http.MethodGet && r.URL.Path == "/api/login/options" {
		var res *sdk.ApprovalResult
		err := withClient("", func(client *sdk.Client, _ string) error {
			var callErr error
			res, callErr = client.PasskeyLoginOptions(r.Context())
			return callErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	// ── Passkey: Login verify ─────────────────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/login/verify" {
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		loginID, _ := toUint64(body["login_session_id"])
		credentialBytes, err := marshalAny(body["credential"])
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid credential payload"})
			return
		}
		var res *sdk.ApprovalResult
		callErr := withClient("", func(client *sdk.Client, _ string) error {
			var err error
			res, err = client.PasskeyLoginVerify(r.Context(), loginID, credentialBytes)
			return err
		})
		if callErr != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": callErr.Error()})
			return
		}
		if res.Success {
			if token, _ := stringValue(res.Data["token"]); token != "" {
				s.mu.Lock()
				state.ApprovalToken = token
				state.LoggedIn = true
				s.mu.Unlock()
			}
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	// ── Approvals: Pending ────────────────────────────────────────────────────
	if r.Method == http.MethodGet && r.URL.Path == "/api/approvals/pending" {
		token := s.sessionToken(state)
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "not logged in"})
			return
		}
		query := r.URL.Query()
		appInstanceID := strings.TrimSpace(query.Get("app_instance_id"))
		if appInstanceID == "" {
			appInstanceID = s.appInstanceID
		}
		publicKeyName := strings.TrimSpace(query.Get("public_key_name"))
		var res *sdk.ApprovalResult
		err := withClient(token, func(client *sdk.Client, approvalToken string) error {
			var callErr error
			res, callErr = client.ApprovalPending(r.Context(), approvalToken, nil)
			return callErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		filterPendingApprovalsResult(res, appInstanceID, publicKeyName)
		writeJSON(w, http.StatusOK, res)
		return
	}

	// ── Approvals: Challenge / confirm / action ───────────────────────────────
	if r.Method == http.MethodGet {
		if reqID, ok := matchUintPath(r.URL.Path, "/api/approvals/request/", "/challenge"); ok {
			token := s.sessionToken(state)
			if token == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "not logged in"})
				return
			}
			var res *sdk.ApprovalResult
			err := withClient(token, func(client *sdk.Client, approvalToken string) error {
				var callErr error
				res, callErr = client.ApprovalRequestChallenge(r.Context(), reqID, approvalToken)
				return callErr
			})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, res)
			return
		}
		if taskID, ok := matchUintPath(r.URL.Path, "/api/approvals/", "/challenge"); ok {
			token := s.sessionToken(state)
			if token == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "not logged in"})
				return
			}
			var res *sdk.ApprovalResult
			err := withClient(token, func(client *sdk.Client, approvalToken string) error {
				var callErr error
				res, callErr = client.ApprovalActionChallenge(r.Context(), taskID, approvalToken)
				return callErr
			})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, res)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/signature/by-tx/") {
			token := s.sessionToken(state)
			if token == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "not logged in"})
				return
			}
			txID := strings.TrimPrefix(r.URL.Path, "/api/signature/by-tx/")
			txID, _ = url.QueryUnescape(txID)
			txID = strings.TrimSpace(txID)
			var res *sdk.ApprovalResult
			err := withClient(token, func(client *sdk.Client, approvalToken string) error {
				var callErr error
				res, callErr = client.GetSignatureByTx(r.Context(), txID, approvalToken)
				return callErr
			})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, res)
			return
		}
	}

	if r.Method == http.MethodPost {
		if reqID, ok := matchUintPath(r.URL.Path, "/api/approvals/request/", "/confirm"); ok {
			token := s.sessionToken(state)
			if token == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "not logged in"})
				return
			}
			var body map[string]interface{}
			if err := decodeJSON(r.Body, &body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
				return
			}
			payloadBytes, _ := json.Marshal(body)
			var res *sdk.ApprovalResult
			err := withClient(token, func(client *sdk.Client, approvalToken string) error {
				var callErr error
				res, callErr = client.ApprovalRequestConfirm(r.Context(), reqID, payloadBytes, approvalToken)
				return callErr
			})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, res)
			return
		}
		if taskID, ok := matchUintPath(r.URL.Path, "/api/approvals/", "/action"); ok {
			token := s.sessionToken(state)
			if token == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "not logged in"})
				return
			}
			var body map[string]interface{}
			if err := decodeJSON(r.Body, &body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
				return
			}
			payloadBytes, _ := json.Marshal(body)
			var res *sdk.ApprovalResult
			err := withClient(token, func(client *sdk.Client, approvalToken string) error {
				var callErr error
				res, callErr = client.ApprovalAction(r.Context(), taskID, payloadBytes, approvalToken)
				return callErr
			})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, res)
			return
		}
	}

	// ── My requests ───────────────────────────────────────────────────────────
	if r.Method == http.MethodGet && r.URL.Path == "/api/requests/mine" {
		token := s.sessionToken(state)
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "not logged in"})
			return
		}
		var res *sdk.ApprovalResult
		err := withClient(token, func(client *sdk.Client, approvalToken string) error {
			var callErr error
			res, callErr = client.GetMyRequests(r.Context(), approvalToken)
			return callErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	// ── Cancel request ────────────────────────────────────────────────────────
	if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/requests/") {
		token := s.sessionToken(state)
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "not logged in"})
			return
		}
		parts := strings.TrimPrefix(r.URL.Path, "/api/requests/")
		id, parseErr := strconv.ParseUint(parts, 10, 64)
		if parseErr != nil || id == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid id"})
			return
		}
		idType := r.URL.Query().Get("type")
		if idType == "" {
			idType = "session"
		}
		var res *sdk.ApprovalResult
		err := withClient(token, func(client *sdk.Client, approvalToken string) error {
			var callErr error
			res, callErr = client.CancelRequest(r.Context(), id, idType, approvalToken)
			return callErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	// ── Admin: List passkey users ─────────────────────────────────────────────
	if r.Method == http.MethodGet && r.URL.Path == "/api/admin/passkey/users" {
		query := r.URL.Query()
		page, _ := strconv.Atoi(query.Get("page"))
		limit, _ := strconv.Atoi(query.Get("limit"))
		var res *sdk.PasskeyUsersResult
		err := withClient("", func(client *sdk.Client, _ string) error {
			var callErr error
			res, callErr = client.ListPasskeyUsers(r.Context(), page, limit)
			return callErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	// ── Admin: Invite passkey user ────────────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/admin/passkey/invite" {
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		req := sdk.PasskeyInviteRequest{
			DisplayName: toString(body["display_name"]),
		}
		if exp, ok := toUint64(body["expires_in_seconds"]); ok {
			req.ExpiresInSeconds = int(exp)
		}
		var res *sdk.PasskeyInviteResult
		err := withClient("", func(client *sdk.Client, _ string) error {
			var callErr error
			res, callErr = client.InvitePasskeyUser(r.Context(), req)
			return callErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		if res != nil && res.Success && res.InviteToken != "" {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"success":      res.Success,
				"invite_token": res.InviteToken,
				"expires_at":   res.ExpiresAt,
			})
		} else {
			writeJSON(w, http.StatusOK, res)
		}
		return
	}

	// ── Admin: Delete passkey user ────────────────────────────────────────────
	if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/admin/passkey/users/") {
		userIDStr := strings.TrimPrefix(r.URL.Path, "/api/admin/passkey/users/")
		if userIDStr == "" || strings.Contains(userIDStr, "/") {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid user id"})
			return
		}
		userID, parseErr := strconv.ParseUint(userIDStr, 10, 64)
		if parseErr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid user id"})
			return
		}
		var res *sdk.AdminResult
		err := withClient("", func(client *sdk.Client, _ string) error {
			var callErr error
			res, callErr = client.DeletePasskeyUser(r.Context(), uint(userID))
			return callErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	// ── Admin: Audit records ──────────────────────────────────────────────────
	if r.Method == http.MethodGet && r.URL.Path == "/api/admin/audit-records" {
		query := r.URL.Query()
		page, _ := strconv.Atoi(query.Get("page"))
		limit, _ := strconv.Atoi(query.Get("limit"))
		var res *sdk.AuditRecordsResult
		err := withClient("", func(client *sdk.Client, _ string) error {
			var callErr error
			res, callErr = client.ListAuditRecords(r.Context(), page, limit)
			return callErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	// ── Admin: Upsert policy ──────────────────────────────────────────────────
	if r.Method == http.MethodPut && r.URL.Path == "/api/admin/policy" {
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		req := sdk.PolicyRequest{
			PublicKeyName: toString(body["public_key_name"]),
		}
		if enabled, ok := body["enabled"].(bool); ok {
			req.Enabled = enabled
		}
		if timeout, ok := toUint64(body["timeout_seconds"]); ok {
			req.TimeoutSeconds = int(timeout)
		}
		if levelsRaw, ok := body["levels"].([]interface{}); ok {
			for _, lv := range levelsRaw {
				lvMap, ok := lv.(map[string]interface{})
				if !ok {
					continue
				}
				level := sdk.PolicyLevel{}
				if v, ok := toUint64(lvMap["level_index"]); ok {
					level.LevelIndex = int(v)
				}
				if v, ok := toUint64(lvMap["threshold"]); ok {
					level.Threshold = int(v)
				}
				if mids, ok := lvMap["member_ids"].([]interface{}); ok {
					for _, mid := range mids {
						if v, ok := toUint64(mid); ok {
							level.MemberIDs = append(level.MemberIDs, uint(v))
						}
					}
				}
				req.Levels = append(req.Levels, level)
			}
		}
		var res *sdk.AdminResult
		err := withClient("", func(client *sdk.Client, _ string) error {
			var callErr error
			res, callErr = client.UpsertPermissionPolicy(r.Context(), req)
			return callErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	// ── Admin: Get policy ─────────────────────────────────────────────────────
	if r.Method == http.MethodGet && r.URL.Path == "/api/admin/policy" {
		keyName := strings.TrimSpace(r.URL.Query().Get("key_name"))
		if keyName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "key_name is required"})
			return
		}
		var res *sdk.PolicyResult
		err := withClient("", func(client *sdk.Client, _ string) error {
			var callErr error
			res, callErr = client.GetPermissionPolicy(r.Context(), keyName)
			return callErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	// ── Admin: Delete policy ──────────────────────────────────────────────────
	if r.Method == http.MethodDelete && r.URL.Path == "/api/admin/policy" {
		keyName := strings.TrimSpace(r.URL.Query().Get("key_name"))
		if keyName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "key_name is required"})
			return
		}
		var res *sdk.AdminResult
		err := withClient("", func(client *sdk.Client, _ string) error {
			var callErr error
			res, callErr = client.DeletePermissionPolicy(r.Context(), keyName)
			return callErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	// ── Passkey: Register options ──────────────────────────────────────────────
	if r.Method == http.MethodGet && r.URL.Path == "/api/passkey/register/options" {
		token := strings.TrimSpace(r.URL.Query().Get("token"))
		if token == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "token is required"})
			return
		}
		var res *sdk.PasskeyRegistrationOptionsResult
		err := withClient("", func(client *sdk.Client, _ string) error {
			var callErr error
			res, callErr = client.PasskeyRegistrationOptions(r.Context(), token)
			return callErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	// ── Passkey: Register verify ───────────────────────────────────────────────
	if r.Method == http.MethodPost && r.URL.Path == "/api/passkey/register/verify" {
		var body map[string]interface{}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid json body"})
			return
		}
		token := toString(body["invite_token"])
		if token == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invite_token is required"})
			return
		}
		var res *sdk.PasskeyRegistrationVerifyResult
		err := withClient("", func(client *sdk.Client, _ string) error {
			var callErr error
			res, callErr = client.PasskeyRegistrationVerify(r.Context(), token, body["credential"])
			return callErr
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "API endpoint not found"})
}

// applyPriceUpdate writes the signed price to an epoch's in-memory record.
// priceDate is the calendar day the user selected (day-exact, no carry-forward).
func (s *server) applyPriceUpdate(epochID string, priceVal float64, priceDate time.Time) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	for i := range s.store.epochs {
		if s.store.epochs[i].ID == epochID {
			s.store.epochs[i].Price = priceVal
			s.store.epochs[i].PriceHistory = append([]EpochPrice{{
				ID:    newID("ep-price-"),
				Price: priceVal,
				SetAt: priceDate,
			}}, s.store.epochs[i].PriceHistory...)
			break
		}
	}
}

// applyAllowlistUpdate writes a signed add/remove to the in-memory allowlist.
func (s *server) applyAllowlistUpdate(action, address string) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	switch action {
	case "add":
		found := false
		for i := range s.store.allowlist {
			if strings.EqualFold(s.store.allowlist[i].Address, address) {
				s.store.allowlist[i].Status = "active"
				found = true
				break
			}
		}
		if !found {
			s.store.allowlist = append(s.store.allowlist, AllowlistEntry{
				Address: address,
				AddedAt: time.Now(),
				Status:  "active",
			})
		}
	case "remove":
		for i := range s.store.allowlist {
			if strings.EqualFold(s.store.allowlist[i].Address, address) {
				s.store.allowlist[i].Status = "removed"
				break
			}
		}
	}
}

// applySubscriptionUpdate writes a signed approve/reject to the in-memory subscription record.
func (s *server) applySubscriptionUpdate(subID, action string) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	for i := range s.store.subscriptions {
		if s.store.subscriptions[i].ID == subID {
			if action == "approve" {
				s.store.subscriptions[i].Status = "approved"
			} else {
				s.store.subscriptions[i].Status = "rejected"
			}
			break
		}
	}
}

// applyKYCUpdate writes a signed KYC decision to the in-memory application record.
func (s *server) applyKYCUpdate(appID, decision string) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	for i := range s.store.applications {
		if s.store.applications[i].ID == appID {
			if decision == "approve" {
				s.store.applications[i].KYCStatus = "approved"
			} else {
				s.store.applications[i].KYCStatus = "rejected"
			}
			break
		}
	}
}

// ── Sign response builder ──────────────────────────────────────────────────────

// hashForSign Keccak256-hashes the payload for Ethereum-compatible ECDSA signing (32 bytes).
func hashForSign(payload []byte) []byte {
	return ethcrypto.Keccak256(payload)
}

func buildSignResponse(signRes *sdk.SignResult, callErr error, operation string) map[string]interface{} {
	resp := map[string]interface{}{
		"operation": operation,
	}
	if callErr != nil {
		resp["sign_success"] = false
		resp["error"] = callErr.Error()
		return resp
	}
	if signRes == nil {
		resp["sign_success"] = false
		resp["error"] = "empty sign response"
		return resp
	}
	resp["sign_success"] = signRes.Success
	resp["error"] = signRes.Error
	resp["error_code"] = signRes.ErrorCode
	if signRes.VotingInfo != nil {
		resp["status"] = signRes.VotingInfo.Status
		resp["hash"] = signRes.VotingInfo.Hash
		resp["request_id"] = signRes.VotingInfo.RequestID
		resp["tx_id"] = signRes.VotingInfo.TxID
		resp["needs_voting"] = signRes.VotingInfo.NeedsVoting
	}
	if signRes.Success && len(signRes.Signature) > 0 {
		resp["signature"] = "0x" + hex.EncodeToString(signRes.Signature)
	}
	if _, ok := resp["status"]; !ok {
		if signRes.Success {
			resp["status"] = "signed"
		} else {
			resp["status"] = "failed"
		}
	}
	return resp
}

// ── Session helpers ────────────────────────────────────────────────────────────

func (s *server) sessionToken(state *sessionState) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if state != nil && strings.TrimSpace(state.ApprovalToken) != "" {
		return strings.TrimSpace(state.ApprovalToken)
	}
	return s.bootstrapToken
}

func (s *server) ensureSessionID(w http.ResponseWriter, r *http.Request) string {
	rawHeader := strings.TrimSpace(r.Header.Get("X-Demo-Session"))
	if rawHeader != "" && demoSessionPattern.MatchString(rawHeader) {
		s.mu.Lock()
		if _, ok := s.sessions[rawHeader]; !ok {
			s.sessions[rawHeader] = &sessionState{ApprovalToken: s.bootstrapToken}
		}
		s.mu.Unlock()
		return rawHeader
	}
	if c, err := r.Cookie("demo_sid"); err == nil {
		sid := strings.TrimSpace(c.Value)
		if sid != "" {
			s.mu.Lock()
			if _, ok := s.sessions[sid]; !ok {
				s.sessions[sid] = &sessionState{ApprovalToken: s.bootstrapToken}
			}
			s.mu.Unlock()
			return sid
		}
	}
	sid := randomSessionID()
	http.SetCookie(w, &http.Cookie{
		Name: "demo_sid", Value: sid, Path: "/",
		HttpOnly: true, MaxAge: 86400, SameSite: http.SameSiteLaxMode,
	})
	s.mu.Lock()
	s.sessions[sid] = &sessionState{ApprovalToken: s.bootstrapToken}
	s.mu.Unlock()
	return sid
}

func (s *server) getSession(sid string) *sessionState {
	s.mu.RLock()
	state := s.sessions[sid]
	s.mu.RUnlock()
	if state != nil {
		return state
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[sid] == nil {
		s.sessions[sid] = &sessionState{ApprovalToken: s.bootstrapToken}
	}
	return s.sessions[sid]
}

// ── Static file serving ────────────────────────────────────────────────────────

func (s *server) serveStatic(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Path
	if target == "/" {
		target = "/index.html"
	}
	clean := filepath.Clean(strings.TrimPrefix(target, "/"))
	full := filepath.Join(s.frontendDir, clean)
	if !strings.HasPrefix(full, s.frontendDir) {
		http.NotFound(w, r)
		return
	}
	if st, err := os.Stat(full); err == nil && !st.IsDir() {
		http.ServeFile(w, r, full)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.frontendDir, "index.html"))
}

func detectFrontendDir() string {
	if custom := strings.TrimSpace(os.Getenv("DEMO_FRONTEND_DIR")); custom != "" {
		return custom
	}
	candidates := []string{
		filepath.Join(".", "finance-console", "frontend"),
		filepath.Join(".", "frontend"),
	}
	for _, dir := range candidates {
		if st, err := os.Stat(filepath.Join(dir, "index.html")); err == nil && !st.IsDir() {
			return dir
		}
	}
	return filepath.Join(".", "finance-console", "frontend")
}

// ── Shared helpers ─────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func decodeJSON(body io.ReadCloser, out interface{}) error {
	defer body.Close()
	dec := json.NewDecoder(body)
	dec.UseNumber()
	return dec.Decode(out)
}

func buildSignMessageBytes(body map[string]interface{}) ([]byte, error) {
	if rawPayload, ok := body["payload"]; ok && rawPayload != nil {
		switch payload := rawPayload.(type) {
		case string:
			payload = strings.TrimSpace(payload)
			if payload == "" {
				return nil, fmt.Errorf("payload is empty")
			}
			return []byte(payload), nil
		default:
			out, err := json.Marshal(payload)
			if err != nil {
				return nil, fmt.Errorf("invalid payload")
			}
			return out, nil
		}
	}
	message := strings.TrimSpace(toString(body["message"]))
	if message == "" {
		return nil, fmt.Errorf("payload or message is required")
	}
	return []byte(message), nil
}

func matchUintPath(path, prefix, suffix string) (uint64, bool) {
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return 0, false
	}
	mid := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	if mid == "" || strings.Contains(mid, "/") {
		return 0, false
	}
	v, err := strconv.ParseUint(mid, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func marshalAny(v interface{}) ([]byte, error) {
	if v == nil {
		return []byte(`{}`), nil
	}
	return json.Marshal(v)
}

func toUint64(v interface{}) (uint64, bool) {
	switch n := v.(type) {
	case float64:
		if n <= 0 || math.IsNaN(n) || math.IsInf(n, 0) {
			return 0, false
		}
		return uint64(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil || i <= 0 {
			return 0, false
		}
		return uint64(i), true
	case int:
		if n <= 0 {
			return 0, false
		}
		return uint64(n), true
	case int64:
		if n <= 0 {
			return 0, false
		}
		return uint64(n), true
	case uint64:
		if n == 0 {
			return 0, false
		}
		return n, true
	case string:
		u, err := strconv.ParseUint(strings.TrimSpace(n), 10, 64)
		if err != nil || u == 0 {
			return 0, false
		}
		return u, true
	default:
		return 0, false
	}
}

func toString(v interface{}) string {
	s, _ := stringValue(v)
	return s
}

func stringValue(v interface{}) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	return strings.TrimSpace(s), true
}

func randomSessionID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func newID(prefix string) string {
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	return prefix + hex.EncodeToString(buf)
}

func asSliceMap(v interface{}) ([]map[string]interface{}, bool) {
	arr, ok := v.([]interface{})
	if !ok {
		return nil, false
	}
	out := make([]map[string]interface{}, 0, len(arr))
	for _, it := range arr {
		if m, ok := it.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out, true
}

func filterPendingApprovalsResult(res *sdk.ApprovalResult, appInstanceID, publicKeyName string) {
	if res == nil || !res.Success || res.Data == nil {
		return
	}
	appInstanceID = strings.TrimSpace(appInstanceID)
	publicKeyName = strings.TrimSpace(publicKeyName)
	if appInstanceID == "" && publicKeyName == "" {
		return
	}
	approvals, ok := asSliceMap(res.Data["approvals"])
	if !ok {
		return
	}
	filtered := make([]map[string]interface{}, 0, len(approvals))
	taskIDs := make(map[string]struct{}, len(approvals))
	for _, item := range approvals {
		if appInstanceID != "" && toString(item["app_instance_id"]) != appInstanceID {
			continue
		}
		if publicKeyName != "" {
			keyName := toString(item["public_key_name"])
			if keyName == "" {
				keyName = toString(item["key_name"])
			}
			if keyName != publicKeyName {
				continue
			}
		}
		filtered = append(filtered, item)
		if id, ok := toUint64(item["id"]); ok {
			taskIDs[strconv.FormatUint(id, 10)] = struct{}{}
		}
	}
	res.Data["approvals"] = filtered
	res.Data["total"] = len(filtered)
	if levelProgress, ok := res.Data["level_progress"].(map[string]interface{}); ok {
		pruned := make(map[string]interface{}, len(filtered))
		for taskID := range taskIDs {
			if progress, exists := levelProgress[taskID]; exists {
				pruned[taskID] = progress
			}
		}
		res.Data["level_progress"] = pruned
	}
}
