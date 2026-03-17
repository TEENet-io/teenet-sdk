package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openclaw-wallet/model"
)

// sessionEntry holds a passkey session token and its expiry.
type sessionEntry struct {
	userID    uint
	expiresAt time.Time
}

// SessionStore is an in-memory store for passkey sessions.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*sessionEntry
}

// NewSessionStore creates a new session store with background cleanup.
func NewSessionStore() *SessionStore {
	s := &SessionStore{sessions: make(map[string]*sessionEntry)}
	go s.cleanup()
	return s
}

func (s *SessionStore) Set(token string, userID uint, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = &sessionEntry{userID: userID, expiresAt: time.Now().Add(ttl)}
}

func (s *SessionStore) Get(token string) (uint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.sessions[token]
	if !ok || time.Now().After(entry.expiresAt) {
		return 0, false
	}
	return entry.userID, true
}

func (s *SessionStore) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

func (s *SessionStore) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for k, v := range s.sessions {
			if now.After(v.expiresAt) {
				delete(s.sessions, k)
			}
		}
		s.mu.Unlock()
	}
}

// AuthMiddleware authenticates requests via API Key (ocw_...) or Passkey session (ps_...).
// Sets "userID" and "authMode" in the context.
func AuthMiddleware(db *gorm.DB, sessions *SessionStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractBearer(c)
		if token == "" {
			log.Printf("[auth] missing Authorization header: %s %s ip=%s", c.Request.Method, c.Request.URL.Path, c.ClientIP())
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization required"})
			return
		}

		if strings.HasPrefix(token, "ps_") {
			// Passkey session auth
			userID, ok := sessions.Get(token)
			if !ok {
				log.Printf("[auth] invalid or expired session: %s %s ip=%s", c.Request.Method, c.Request.URL.Path, c.ClientIP())
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired session"})
				return
			}
			c.Set("userID", userID)
			c.Set("authMode", "passkey")
			c.Set("sessionToken", token)
			c.Next()
			return
		}

		// API Key auth (ocw_... prefix)
		hash := hashAPIKey(token)
		var user model.User
		if err := db.Where("api_key_hash = ?", hash).First(&user).Error; err != nil {
			log.Printf("[auth] invalid API key (prefix %.8s...): %s %s ip=%s", token, c.Request.Method, c.Request.URL.Path, c.ClientIP())
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid API key"})
			return
		}
		c.Set("userID", user.ID)
		c.Set("authMode", "apikey")
		c.Next()
	}
}

// PasskeyOnlyMiddleware rejects non-passkey requests (used for approval actions).
func PasskeyOnlyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		mode, _ := c.Get("authMode")
		if mode != "passkey" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "this action requires passkey authentication",
			})
			return
		}
		c.Next()
	}
}

func extractBearer(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	return ""
}

func hashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// requestBaseURL returns the base URL of the current request, honoring
// X-Forwarded-Proto / X-Forwarded-Host / X-App-Instance-ID headers set by reverse proxies (e.g. UMS).
// When behind UMS, requests arrive under /instance/{id}/, so the approval link must include that path.
// Falls back to the configured baseURL if headers are absent.
func requestBaseURL(c *gin.Context, fallback string) string {
	host := c.GetHeader("X-Forwarded-Host")
	if host == "" {
		host = c.GetHeader("X-Real-Host")
	}
	if host == "" {
		host = c.Request.Host
	}
	if host == "" {
		return fallback
	}
	scheme := c.GetHeader("X-Forwarded-Proto")
	if scheme == "" {
		if c.Request.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	base := scheme + "://" + strings.TrimRight(host, "/")
	// UMS reverse-proxy sets X-App-Instance-ID; the app is mounted at /instance/{id}/.
	if instanceID := c.GetHeader("X-App-Instance-ID"); instanceID != "" {
		base = base + "/instance/" + instanceID
	}
	return base
}
