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

// Package network provides callback server functionality for TEENet SDK.
package network

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	// DefaultCallbackPort is the fixed port for callback server
	DefaultCallbackPort = 19080
)

// CallbackPayload is the structure sent by consensus nodes to callback URLs.
// This is exported so it can be used by the main SDK package.
type CallbackPayload struct {
	Hash      string `json:"hash"`
	Status    string `json:"status"`
	Signature string `json:"signature"`
	Error     string `json:"error,omitempty"`
}

// CallbackServer manages a fixed-port HTTP server for receiving callbacks
type CallbackServer struct {
	server   *http.Server
	listener net.Listener
	port     int // Fixed to DefaultCallbackPort

	// Callback channels keyed by hash
	callbacks sync.Map // map[string]chan *CallbackPayload

	mu       sync.Mutex
	started  bool
	shutdown chan struct{}
}

// NewCallbackServer creates a new callback server on the fixed port 19080
func NewCallbackServer() (*CallbackServer, error) {
	// Listen on fixed port 19080, all interfaces (0.0.0.0) to accept external connections
	addr := fmt.Sprintf("0.0.0.0:%d", DefaultCallbackPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on port %d: %w (port may be in use by another application)", DefaultCallbackPort, err)
	}

	cs := &CallbackServer{
		listener: listener,
		port:     DefaultCallbackPort,
		shutdown: make(chan struct{}),
	}

	// Create HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/callback/", cs.handleCallback)

	cs.server = &http.Server{
		Handler: mux,
	}

	return cs, nil
}

// start starts the callback server in a goroutine
func (cs *CallbackServer) Start() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.started {
		return fmt.Errorf("server already started")
	}

	cs.started = true

	// Start server in background
	go func() {
		if err := cs.server.Serve(cs.listener); err != nil && err != http.ErrServerClosed {
			log.Printf("Callback server error: %v", err)
		}
	}()

	log.Printf("Callback server started on port %d", cs.port)
	return nil
}

// stop stops the callback server
func (cs *CallbackServer) Stop() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if !cs.started {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := cs.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	close(cs.shutdown)
	cs.started = false

	log.Printf("Callback server stopped")
	return nil
}

// registerCallback registers a callback channel for a specific hash
func (cs *CallbackServer) RegisterCallback(hash string) chan *CallbackPayload {
	ch := make(chan *CallbackPayload, 1)
	cs.callbacks.Store(hash, ch)
	return ch
}

// unregisterCallback removes a callback channel
func (cs *CallbackServer) UnregisterCallback(hash string) {
	cs.callbacks.Delete(hash)
}

// handleCallback handles incoming callback requests
func (cs *CallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Extract hash from URL path
	// Path format: /callback/0x...
	hash := r.URL.Path[len("/callback/"):]

	if hash == "" {
		http.Error(w, "Missing hash in callback URL", http.StatusBadRequest)
		return
	}

	// Parse callback payload
	var payload CallbackPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse callback payload: %v", err), http.StatusBadRequest)
		return
	}

	log.Printf("Received callback for hash %s: status=%s", hash, payload.Status)

	// Find the callback channel
	if ch, ok := cs.callbacks.Load(hash); ok {
		callbackChan := ch.(chan *CallbackPayload)

		// Send payload to channel (non-blocking)
		select {
		case callbackChan <- &payload:
			// Successfully sent
		default:
			// Channel full or closed, ignore
			log.Printf("Warning: callback channel for %s is full or closed", hash)
		}
	} else {
		log.Printf("Warning: no callback registered for hash %s", hash)
	}

	// Send success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Callback received",
	})
}
