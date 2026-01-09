package auth

import (
	"context"
	"errors"
)

// User represents an authenticated user
type User struct {
	Username string
	Groups   []string
	Meta     map[string]interface{}
}

// Authenticator defines the interface for authentication
type Authenticator interface {
	// Authenticate checks the credentials and returns the user if successful
	Authenticate(ctx context.Context, user, password string) (*User, error)
}

// LocalAuthenticator implements simple user/pass auth from a map
type LocalAuthenticator struct {
	users map[string]string // username -> password
}

// NewLocalAuthenticator creates a new local authenticator
func NewLocalAuthenticator(users map[string]string) Authenticator {
	return &LocalAuthenticator{
		users: users,
	}
}

func (a *LocalAuthenticator) Authenticate(ctx context.Context, user, password string) (*User, error) {
	storedPass, ok := a.users[user]
	if !ok || storedPass != password {
		return nil, errors.New("invalid credentials")
	}

	return &User{
		Username: user,
		Groups:   []string{"user"},
	}, nil
}
