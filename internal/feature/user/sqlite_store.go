// Package user provides SQLite-based user storage implementation.
package user

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// SQLiteStore implements Store using SQLite database.
type SQLiteStore struct {
	db     *sql.DB
	mu     sync.RWMutex
	closed bool
}

// NewSQLiteStore creates a new SQLite-based user store.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable WAL mode for better concurrency
	_, err = db.Exec("PRAGMA journal_mode=WAL")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	store := &SQLiteStore{db: db}

	// Initialize schema
	if err := store.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return store, nil
}

// initSchema creates the database schema if it doesn't exist.
func (s *SQLiteStore) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		email TEXT,
		uuid TEXT UNIQUE NOT NULL,
		level INTEGER DEFAULT 1,
		quota INTEGER DEFAULT 0,
		used_upload INTEGER DEFAULT 0,
		used_download INTEGER DEFAULT 0,
		expire_at DATETIME,
		enabled INTEGER DEFAULT 1,
		max_connections INTEGER DEFAULT 0,
		speed_limit INTEGER DEFAULT 0,
		allowed_ips TEXT,
		metadata TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		last_login_at DATETIME,
		last_login_ip TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid);
	CREATE INDEX IF NOT EXISTS idx_users_enabled ON users(enabled);

	CREATE TABLE IF NOT EXISTS traffic_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL,
		upload INTEGER NOT NULL,
		download INTEGER NOT NULL,
		timestamp DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE INDEX IF NOT EXISTS idx_traffic_logs_user_id ON traffic_logs(user_id);
	CREATE INDEX IF NOT EXISTS idx_traffic_logs_timestamp ON traffic_logs(timestamp);
	`

	_, err := s.db.Exec(schema)
	return err
}

// Create creates a new user.
func (s *SQLiteStore) Create(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("store is closed")
	}

	allowedIPs, _ := json.Marshal(user.AllowedIPs)
	metadata, _ := json.Marshal(user.Metadata)

	query := `
	INSERT INTO users (
		id, username, password_hash, email, uuid, level, quota,
		used_upload, used_download, expire_at, enabled,
		max_connections, speed_limit, allowed_ips, metadata,
		created_at, updated_at, last_login_at, last_login_ip
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	var expireAt interface{}
	if !user.ExpireAt.IsZero() {
		expireAt = user.ExpireAt
	}

	var lastLoginAt interface{}
	if !user.LastLoginAt.IsZero() {
		lastLoginAt = user.LastLoginAt
	}

	_, err := s.db.ExecContext(ctx, query,
		user.ID, user.Username, user.PasswordHash, user.Email, user.UUID,
		user.Level, user.Quota, user.UsedUpload, user.UsedDownload,
		expireAt, user.Enabled, user.MaxConnections, user.SpeedLimit,
		string(allowedIPs), string(metadata),
		user.CreatedAt, user.UpdatedAt, lastLoginAt, user.LastLoginIP,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// Get retrieves a user by ID.
func (s *SQLiteStore) Get(ctx context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, errors.New("store is closed")
	}

	return s.getUser(ctx, "id = ?", id)
}

// GetByUsername retrieves a user by username.
func (s *SQLiteStore) GetByUsername(ctx context.Context, username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, errors.New("store is closed")
	}

	return s.getUser(ctx, "username = ?", username)
}

// GetByUUID retrieves a user by UUID.
func (s *SQLiteStore) GetByUUID(ctx context.Context, uuid string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, errors.New("store is closed")
	}

	return s.getUser(ctx, "uuid = ?", uuid)
}

// getUser is a helper function to retrieve a user by a condition.
func (s *SQLiteStore) getUser(ctx context.Context, condition string, args ...interface{}) (*User, error) {
	query := `
	SELECT id, username, password_hash, email, uuid, level, quota,
		used_upload, used_download, expire_at, enabled,
		max_connections, speed_limit, allowed_ips, metadata,
		created_at, updated_at, last_login_at, last_login_ip
	FROM users WHERE ` + condition

	row := s.db.QueryRowContext(ctx, query, args...)

	var user User
	var allowedIPs, metadata string
	var expireAt, lastLoginAt sql.NullTime
	var lastLoginIP sql.NullString

	err := row.Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.Email, &user.UUID,
		&user.Level, &user.Quota, &user.UsedUpload, &user.UsedDownload,
		&expireAt, &user.Enabled, &user.MaxConnections, &user.SpeedLimit,
		&allowedIPs, &metadata,
		&user.CreatedAt, &user.UpdatedAt, &lastLoginAt, &lastLoginIP,
	)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if expireAt.Valid {
		user.ExpireAt = expireAt.Time
	}
	if lastLoginAt.Valid {
		user.LastLoginAt = lastLoginAt.Time
	}
	if lastLoginIP.Valid {
		user.LastLoginIP = lastLoginIP.String
	}

	json.Unmarshal([]byte(allowedIPs), &user.AllowedIPs)
	json.Unmarshal([]byte(metadata), &user.Metadata)

	return &user, nil
}

// Update updates an existing user.
func (s *SQLiteStore) Update(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("store is closed")
	}

	allowedIPs, _ := json.Marshal(user.AllowedIPs)
	metadata, _ := json.Marshal(user.Metadata)

	query := `
	UPDATE users SET
		username = ?, password_hash = ?, email = ?, uuid = ?, level = ?,
		quota = ?, used_upload = ?, used_download = ?, expire_at = ?,
		enabled = ?, max_connections = ?, speed_limit = ?,
		allowed_ips = ?, metadata = ?, updated_at = ?,
		last_login_at = ?, last_login_ip = ?
	WHERE id = ?
	`

	var expireAt interface{}
	if !user.ExpireAt.IsZero() {
		expireAt = user.ExpireAt
	}

	var lastLoginAt interface{}
	if !user.LastLoginAt.IsZero() {
		lastLoginAt = user.LastLoginAt
	}

	result, err := s.db.ExecContext(ctx, query,
		user.Username, user.PasswordHash, user.Email, user.UUID, user.Level,
		user.Quota, user.UsedUpload, user.UsedDownload, expireAt,
		user.Enabled, user.MaxConnections, user.SpeedLimit,
		string(allowedIPs), string(metadata), time.Now(),
		lastLoginAt, user.LastLoginIP,
		user.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrUserNotFound
	}

	return nil
}

// Delete deletes a user by ID.
func (s *SQLiteStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("store is closed")
	}

	// Delete traffic logs first
	_, err := s.db.ExecContext(ctx, "DELETE FROM traffic_logs WHERE user_id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete traffic logs: %w", err)
	}

	// Delete user
	result, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrUserNotFound
	}

	return nil
}

// List returns all users with pagination.
func (s *SQLiteStore) List(ctx context.Context, offset, limit int) ([]*User, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, 0, errors.New("store is closed")
	}

	// Get total count
	var total int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	query := `
	SELECT id, username, password_hash, email, uuid, level, quota,
		used_upload, used_download, expire_at, enabled,
		max_connections, speed_limit, allowed_ips, metadata,
		created_at, updated_at, last_login_at, last_login_ip
	FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?
	`

	rows, err := s.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	users, err := s.scanUsers(rows)
	if err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

// Count returns the total number of users.
func (s *SQLiteStore) Count(ctx context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return 0, errors.New("store is closed")
	}

	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}

	return count, nil
}

// Search searches users by username or email.
func (s *SQLiteStore) Search(ctx context.Context, query string, offset, limit int) ([]*User, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, 0, errors.New("store is closed")
	}

	searchPattern := "%" + query + "%"

	// Get total count
	var total int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM users WHERE username LIKE ? OR email LIKE ?",
		searchPattern, searchPattern,
	).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	sqlQuery := `
	SELECT id, username, password_hash, email, uuid, level, quota,
		used_upload, used_download, expire_at, enabled,
		max_connections, speed_limit, allowed_ips, metadata,
		created_at, updated_at, last_login_at, last_login_ip
	FROM users WHERE username LIKE ? OR email LIKE ?
	ORDER BY created_at DESC LIMIT ? OFFSET ?
	`

	rows, err := s.db.QueryContext(ctx, sqlQuery, searchPattern, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search users: %w", err)
	}
	defer rows.Close()

	users, err := s.scanUsers(rows)
	if err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

// UpdateTraffic updates a user's traffic counters.
func (s *SQLiteStore) UpdateTraffic(ctx context.Context, id string, upload, download int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("store is closed")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Update user traffic
	result, err := tx.ExecContext(ctx, `
		UPDATE users SET
			used_upload = used_upload + ?,
			used_download = used_download + ?,
			updated_at = ?
		WHERE id = ?
	`, upload, download, time.Now(), id)

	if err != nil {
		return fmt.Errorf("failed to update traffic: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrUserNotFound
	}

	// Log traffic
	_, err = tx.ExecContext(ctx, `
		INSERT INTO traffic_logs (user_id, upload, download, timestamp)
		VALUES (?, ?, ?, ?)
	`, id, upload, download, time.Now())

	if err != nil {
		return fmt.Errorf("failed to log traffic: %w", err)
	}

	return tx.Commit()
}

// ResetTraffic resets a user's traffic counters.
func (s *SQLiteStore) ResetTraffic(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("store is closed")
	}

	result, err := s.db.ExecContext(ctx, `
		UPDATE users SET
			used_upload = 0,
			used_download = 0,
			updated_at = ?
		WHERE id = ?
	`, time.Now(), id)

	if err != nil {
		return fmt.Errorf("failed to reset traffic: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrUserNotFound
	}

	return nil
}

// ResetAllTraffic resets all users' traffic counters.
func (s *SQLiteStore) ResetAllTraffic(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("store is closed")
	}

	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET
			used_upload = 0,
			used_download = 0,
			updated_at = ?
	`, time.Now())

	if err != nil {
		return fmt.Errorf("failed to reset all traffic: %w", err)
	}

	return nil
}

// GetActiveUsers returns users who are enabled and not expired.
func (s *SQLiteStore) GetActiveUsers(ctx context.Context) ([]*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, errors.New("store is closed")
	}

	query := `
	SELECT id, username, password_hash, email, uuid, level, quota,
		used_upload, used_download, expire_at, enabled,
		max_connections, speed_limit, allowed_ips, metadata,
		created_at, updated_at, last_login_at, last_login_ip
	FROM users
	WHERE enabled = 1 AND (expire_at IS NULL OR expire_at > ?)
	ORDER BY created_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to list active users: %w", err)
	}
	defer rows.Close()

	users, err := s.scanUsers(rows)
	if err != nil {
		return nil, err
	}

	// Filter out users who exceeded quota
	activeUsers := make([]*User, 0, len(users))
	for _, user := range users {
		if !user.IsQuotaExceeded() {
			activeUsers = append(activeUsers, user)
		}
	}

	return activeUsers, nil
}

// scanUsers scans multiple user rows.
func (s *SQLiteStore) scanUsers(rows *sql.Rows) ([]*User, error) {
	var users []*User
	for rows.Next() {
		var user User
		var allowedIPs, metadata string
		var expireAt, lastLoginAt sql.NullTime
		var lastLoginIP sql.NullString

		err := rows.Scan(
			&user.ID, &user.Username, &user.PasswordHash, &user.Email, &user.UUID,
			&user.Level, &user.Quota, &user.UsedUpload, &user.UsedDownload,
			&expireAt, &user.Enabled, &user.MaxConnections, &user.SpeedLimit,
			&allowedIPs, &metadata,
			&user.CreatedAt, &user.UpdatedAt, &lastLoginAt, &lastLoginIP,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}

		if expireAt.Valid {
			user.ExpireAt = expireAt.Time
		}
		if lastLoginAt.Valid {
			user.LastLoginAt = lastLoginAt.Time
		}
		if lastLoginIP.Valid {
			user.LastLoginIP = lastLoginIP.String
		}

		json.Unmarshal([]byte(allowedIPs), &user.AllowedIPs)
		json.Unmarshal([]byte(metadata), &user.Metadata)

		users = append(users, &user)
	}

	return users, nil
}

// Close closes the database connection.
func (s *SQLiteStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	return s.db.Close()
}

// GetTrafficLogs retrieves traffic logs for a user within a time range.
func (s *SQLiteStore) GetTrafficLogs(ctx context.Context, userID string, start, end time.Time) ([]TrafficLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, errors.New("store is closed")
	}

	query := `
		SELECT id, user_id, upload, download, timestamp
		FROM traffic_logs
		WHERE user_id = ? AND timestamp BETWEEN ? AND ?
		ORDER BY timestamp DESC
	`

	rows, err := s.db.QueryContext(ctx, query, userID, start, end)
	if err != nil {
		return nil, fmt.Errorf("failed to get traffic logs: %w", err)
	}
	defer rows.Close()

	var logs []TrafficLog
	for rows.Next() {
		var log TrafficLog
		err := rows.Scan(&log.ID, &log.UserID, &log.Upload, &log.Download, &log.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("failed to scan traffic log: %w", err)
		}
		logs = append(logs, log)
	}

	return logs, nil
}

// TrafficLog represents a traffic log entry.
type TrafficLog struct {
	ID        int64     `json:"id"`
	UserID    string    `json:"user_id"`
	Upload    int64     `json:"upload"`
	Download  int64     `json:"download"`
	Timestamp time.Time `json:"timestamp"`
}
