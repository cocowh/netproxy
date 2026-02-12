package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/cocowh/netproxy/internal/feature/user"
)

// UserHandler handles user management API requests.
type UserHandler struct {
	store user.Store
}

// NewUserHandler creates a new user handler.
func NewUserHandler(store user.Store) *UserHandler {
	return &UserHandler{store: store}
}

// RegisterRoutes registers user API routes.
func (h *UserHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/users", h.handleUsers)
	mux.HandleFunc("/api/v1/users/", h.handleUser)
}

// handleUsers handles /api/v1/users endpoint.
func (h *UserHandler) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listUsers(w, r)
	case http.MethodPost:
		h.createUser(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleUser handles /api/v1/users/:id endpoint.
func (h *UserHandler) handleUser(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path
	path := r.URL.Path
	id := path[len("/api/v1/users/"):]

	// Check for sub-resources
	if len(id) > 0 {
		parts := splitPath(id)
		if len(parts) >= 2 {
			id = parts[0]
			subResource := parts[1]
			switch subResource {
			case "stats":
				h.getUserStats(w, r, id)
				return
			case "reset":
				h.resetUserTraffic(w, r, id)
				return
			case "uuid":
				h.regenerateUUID(w, r, id)
				return
			}
		}
	}

	switch r.Method {
	case http.MethodGet:
		h.getUser(w, r, id)
	case http.MethodPut:
		h.updateUser(w, r, id)
	case http.MethodDelete:
		h.deleteUser(w, r, id)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// listUsers returns a list of all users.
func (h *UserHandler) listUsers(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	query := r.URL.Query().Get("q")

	var users []*user.User
	var total int
	var err error

	if query != "" {
		users, total, err = h.store.Search(r.Context(), query, offset, limit)
	} else {
		users, total, err = h.store.List(r.Context(), offset, limit)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"users":  users,
		"total":  total,
		"offset": offset,
		"limit":  limit,
	}

	writeJSON(w, http.StatusOK, response)
}

// createUser creates a new user.
func (h *UserHandler) createUser(w http.ResponseWriter, r *http.Request) {
	var req user.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Create user
	newUser, err := user.NewUser(req.Username, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Apply optional fields
	if req.Email != "" {
		newUser.Email = req.Email
	}
	if req.Level != 0 {
		newUser.Level = req.Level
	}
	if req.Quota > 0 {
		newUser.Quota = req.Quota
	}
	if req.ExpireDays > 0 {
		newUser.ExpireAt = time.Now().AddDate(0, 0, req.ExpireDays)
	}
	if req.MaxConnections > 0 {
		newUser.MaxConnections = req.MaxConnections
	}
	if req.SpeedLimit > 0 {
		newUser.SpeedLimit = req.SpeedLimit
	}
	if req.Metadata != nil {
		newUser.Metadata = req.Metadata
	}

	// Save to store
	if err := h.store.Create(r.Context(), newUser); err != nil {
		if err == user.ErrUserExists {
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, newUser)
}

// getUser returns a single user by ID.
func (h *UserHandler) getUser(w http.ResponseWriter, r *http.Request, id string) {
	u, err := h.store.Get(r.Context(), id)
	if err != nil {
		if err == user.ErrUserNotFound {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, u)
}

// updateUser updates an existing user.
func (h *UserHandler) updateUser(w http.ResponseWriter, r *http.Request, id string) {
	// Get existing user
	u, err := h.store.Get(r.Context(), id)
	if err != nil {
		if err == user.ErrUserNotFound {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse update request
	var req user.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Apply updates
	if err := req.Apply(u); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Save to store
	if err := h.store.Update(r.Context(), u); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, u)
}

// deleteUser deletes a user.
func (h *UserHandler) deleteUser(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.store.Delete(r.Context(), id); err != nil {
		if err == user.ErrUserNotFound {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// getUserStats returns user traffic statistics.
func (h *UserHandler) getUserStats(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	u, err := h.store.Get(r.Context(), id)
	if err != nil {
		if err == user.ErrUserNotFound {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, u.GetTrafficStats())
}

// resetUserTraffic resets a user's traffic counters.
func (h *UserHandler) resetUserTraffic(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := h.store.ResetTraffic(r.Context(), id); err != nil {
		if err == user.ErrUserNotFound {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// regenerateUUID regenerates a user's UUID.
func (h *UserHandler) regenerateUUID(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	u, err := h.store.Get(r.Context(), id)
	if err != nil {
		if err == user.ErrUserNotFound {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	u.RegenerateUUID()

	if err := h.store.Update(r.Context(), u); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"uuid": u.UUID})
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// splitPath splits a path by "/".
func splitPath(path string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			if i > start {
				parts = append(parts, path[start:i])
			}
			start = i + 1
		}
	}
	if start < len(path) {
		parts = append(parts, path[start:])
	}
	return parts
}
