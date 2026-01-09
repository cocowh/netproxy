package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/cocowh/netproxy/internal/core/logger"
)

// HTTPAuthenticator authenticates users via remote HTTP API
type HTTPAuthenticator struct {
	apiURL     string
	httpClient *http.Client
	logger     logger.Logger
}

func NewHTTPAuthenticator(apiURL string, l logger.Logger) Authenticator {
	return &HTTPAuthenticator{
		apiURL: apiURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		logger: l,
	}
}

type authRequest struct {
	User     string `json:"user"`
	password string `json:"password"`
}

func (a *HTTPAuthenticator) Authenticate(ctx context.Context, user, password string) (*User, error) {
	reqBody, err := json.Marshal(authRequest{User: user, password: password})
	if err != nil {
		a.logger.Error("Failed to marshal auth request", logger.Any("error", err))
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.apiURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.logger.Error("Auth API request failed", logger.Any("error", err))
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return &User{
			Username: user,
			Groups:   []string{"user"}, // Could be parsed from response if API supports it
		}, nil
	}

	a.logger.Warn("Auth failed", logger.Any("user", user), logger.Any("status", resp.Status))
	return nil, errors.New("authentication failed")
}
