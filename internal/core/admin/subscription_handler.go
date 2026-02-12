// Package admin provides HTTP API handlers for administration.
package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/cocowh/netproxy/internal/feature/subscription"
)

// SubscriptionHandler handles subscription-related API requests.
type SubscriptionHandler struct {
	updater *subscription.Updater
}

// NewSubscriptionHandler creates a new subscription handler.
func NewSubscriptionHandler(updater *subscription.Updater) *SubscriptionHandler {
	return &SubscriptionHandler{
		updater: updater,
	}
}

// RegisterRoutes registers the subscription API routes.
func (h *SubscriptionHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/subscriptions", h.handleSubscriptions)
	mux.HandleFunc("/api/v1/subscriptions/update", h.handleUpdate)
	mux.HandleFunc("/api/v1/subscriptions/update/", h.handleUpdateSource)
}

// SubscriptionSourceResponse represents a subscription source in API responses.
type SubscriptionSourceResponse struct {
	Name           string        `json:"name"`
	Type           string        `json:"type"`
	URL            string        `json:"url"`
	LocalPath      string        `json:"local_path,omitempty"`
	UpdateInterval time.Duration `json:"update_interval"`
	Enabled        bool          `json:"enabled"`
	LastUpdate     *time.Time    `json:"last_update,omitempty"`
	Hash           string        `json:"hash,omitempty"`
}

// SubscriptionListResponse represents the response for listing subscriptions.
type SubscriptionListResponse struct {
	Sources []SubscriptionSourceResponse `json:"sources"`
}

// UpdateResponse represents the response for an update operation.
type UpdateResponse struct {
	Source    string     `json:"source"`
	Success   bool       `json:"success"`
	Error     string     `json:"error,omitempty"`
	UpdatedAt time.Time  `json:"updated_at"`
	Changed   bool       `json:"changed"`
	OldHash   string     `json:"old_hash,omitempty"`
	NewHash   string     `json:"new_hash,omitempty"`
}

// handleSubscriptions handles GET /api/v1/subscriptions
func (h *SubscriptionHandler) handleSubscriptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sources := h.updater.GetSources()
	response := SubscriptionListResponse{
		Sources: make([]SubscriptionSourceResponse, 0, len(sources)),
	}

	for _, source := range sources {
		resp := SubscriptionSourceResponse{
			Name:           source.Name,
			Type:           string(source.Type),
			URL:            source.URL,
			LocalPath:      source.LocalPath,
			UpdateInterval: source.UpdateInterval,
			Enabled:        source.Enabled,
		}

		if lastUpdate, ok := h.updater.GetLastUpdate(source.Name); ok {
			resp.LastUpdate = &lastUpdate
		}

		if hash, ok := h.updater.GetHash(source.Name); ok {
			resp.Hash = hash
		}

		response.Sources = append(response.Sources, resp)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleUpdate handles POST /api/v1/subscriptions/update
func (h *SubscriptionHandler) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	results := h.updater.UpdateAll()
	responses := make([]UpdateResponse, 0, len(results))

	for _, result := range results {
		resp := UpdateResponse{
			Source:    result.Source.Name,
			Success:   result.Success,
			UpdatedAt: result.UpdatedAt,
			Changed:   result.Changed,
			OldHash:   result.OldHash,
			NewHash:   result.NewHash,
		}

		if result.Error != nil {
			resp.Error = result.Error.Error()
		}

		responses = append(responses, resp)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(responses)
}

// handleUpdateSource handles POST /api/v1/subscriptions/update/{name}
func (h *SubscriptionHandler) handleUpdateSource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract source name from URL
	name := r.URL.Path[len("/api/v1/subscriptions/update/"):]
	if name == "" {
		http.Error(w, "Source name required", http.StatusBadRequest)
		return
	}

	result := h.updater.ForceUpdate(name)

	resp := UpdateResponse{
		UpdatedAt: result.UpdatedAt,
		Success:   result.Success,
		Changed:   result.Changed,
		OldHash:   result.OldHash,
		NewHash:   result.NewHash,
	}

	if result.Source != nil {
		resp.Source = result.Source.Name
	}

	if result.Error != nil {
		resp.Error = result.Error.Error()
		w.WriteHeader(http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
