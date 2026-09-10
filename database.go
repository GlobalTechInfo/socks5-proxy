package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db     *sql.DB
	logger *slog.Logger
	mu     sync.Mutex
}

func NewStore(dbPath string, logger *slog.Logger) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL&_foreign_keys=ON")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	s := &Store{db: db, logger: logger}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return s, nil
}

func (s *Store) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS stats_snapshots (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			active_connections INTEGER DEFAULT 0,
			total_connections INTEGER DEFAULT 0,
			auth_failures INTEGER DEFAULT 0,
			blocked_connections INTEGER DEFAULT 0,
			recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS destinations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target TEXT NOT NULL,
			connections INTEGER DEFAULT 1,
			recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_stats_snapshots_time ON stats_snapshots(recorded_at)`,
		`CREATE INDEX IF NOT EXISTS idx_destinations_time ON destinations(recorded_at)`,
		`CREATE INDEX IF NOT EXISTS idx_destinations_target ON destinations(target)`,
		// Users table
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			tier TEXT NOT NULL DEFAULT 'free',
			max_connections INTEGER NOT NULL DEFAULT 1,
			bandwidth_mbps INTEGER NOT NULL DEFAULT 1,
			data_limit_bytes INTEGER NOT NULL DEFAULT 1073741824,
			data_used_bytes INTEGER NOT NULL DEFAULT 0,
			expiry DATETIME,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS user_connections (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			target TEXT NOT NULL,
			bytes_up INTEGER NOT NULL DEFAULT 0,
			bytes_down INTEGER NOT NULL DEFAULT 0,
			connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			disconnected_at DATETIME,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_user_connections_user ON user_connections(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_user_connections_time ON user_connections(connected_at)`,
	}

	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("exec %q: %w", q, err)
		}
	}
	return nil
}

// ─── Config persistence ────────────────────────────────────────────────────

func (s *Store) LoadConfig() map[string]string {
	rows, err := s.db.Query("SELECT key, value FROM config")
	if err != nil {
		s.logger.Warn("failed to load config from db", "error", err)
		return nil
	}
	defer rows.Close()

	result := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			continue
		}
		result[k] = v
	}
	return result
}

func (s *Store) SaveConfig(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		"INSERT INTO config (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
		key, value,
	)
	return err
}

func (s *Store) SaveConfigBatch(cfg map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO config (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for k, v := range cfg {
		if _, err := stmt.Exec(k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ─── Stats persistence ─────────────────────────────────────────────────────

func (s *Store) SaveStatsSnapshot(active, total, authFails, blocked int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		"INSERT INTO stats_snapshots (active_connections, total_connections, auth_failures, blocked_connections, recorded_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
		active, total, authFails, blocked,
	)
	return err
}

type StatsSnapshot struct {
	ActiveConns    int64     `json:"active_connections"`
	TotalConns     int64     `json:"total_connections"`
	AuthFailures   int64     `json:"auth_failures"`
	BlockedConns   int64     `json:"blocked_connections"`
	RecordedAt     time.Time `json:"recorded_at"`
}

func (s *Store) GetStatsHistory(limit int) ([]StatsSnapshot, error) {
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.Query(
		"SELECT active_connections, total_connections, auth_failures, blocked_connections, recorded_at FROM stats_snapshots ORDER BY id DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []StatsSnapshot
	for rows.Next() {
		var snap StatsSnapshot
		if err := rows.Scan(&snap.ActiveConns, &snap.TotalConns, &snap.AuthFailures, &snap.BlockedConns, &snap.RecordedAt); err != nil {
			continue
		}
		result = append(result, snap)
	}
	return result, nil
}

// ─── Destination persistence ───────────────────────────────────────────────

func (s *Store) SaveDestinations(dests map[string]int64) error {
	if len(dests) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO destinations (target, connections, recorded_at) VALUES (?, ?, CURRENT_TIMESTAMP)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for target, count := range dests {
		if _, err := stmt.Exec(target, count); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type DestinationStat struct {
	Target      string    `json:"target"`
	Connections int64     `json:"connections"`
	RecordedAt  time.Time `json:"recorded_at"`
}

func (s *Store) GetDestinationHistory(limit int) ([]DestinationStat, error) {
	if limit > 500 {
		limit = 500
	}
	rows, err := s.db.Query(
		"SELECT target, connections, recorded_at FROM destinations ORDER BY id DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []DestinationStat
	for rows.Next() {
		var d DestinationStat
		if err := rows.Scan(&d.Target, &d.Connections, &d.RecordedAt); err != nil {
			continue
		}
		result = append(result, d)
	}
	return result, nil
}

func (s *Store) GetTopDestinationsAllTime(limit int) map[string]int64 {
	if limit > 100 {
		limit = 100
	}
	rows, err := s.db.Query(
		"SELECT target, SUM(connections) as total FROM destinations GROUP BY target ORDER BY total DESC LIMIT ?",
		limit,
	)
	if err != nil {
		s.logger.Warn("failed to query top destinations", "error", err)
		return nil
	}
	defer rows.Close()

	result := make(map[string]int64)
	for rows.Next() {
		var target string
		var total int64
		if err := rows.Scan(&target, &total); err != nil {
			continue
		}
		result[target] = total
	}
	return result
}

func (s *Store) Cleanup(olderThanDays int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().AddDate(0, 0, -olderThanDays).Format("2006-01-02 15:04:05")

	_, err := s.db.Exec("DELETE FROM stats_snapshots WHERE recorded_at < ?", cutoff)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("DELETE FROM destinations WHERE recorded_at < ?", cutoff)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("DELETE FROM user_connections WHERE disconnected_at < ?", cutoff)
	return err
}

// ─── Tier Definitions ──────────────────────────────────────────────────────

type Tier struct {
	Name            string `json:"name"`
	MaxConnections  int    `json:"max_connections"`
	BandwidthMbps   int    `json:"bandwidth_mbps"`
	DataLimitBytes  int64  `json:"data_limit_bytes"`
	DaysExpiry      int    `json:"days_expiry"`
}

var Tiers = map[string]Tier{
	"free": {
		Name:           "free",
		MaxConnections: 1,
		BandwidthMbps:  1,
		DataLimitBytes: 1073741824,   // 1 GB
		DaysExpiry:     7,
	},
	"basic": {
		Name:           "basic",
		MaxConnections: 5,
		BandwidthMbps:  5,
		DataLimitBytes: 53687091200,  // 50 GB
		DaysExpiry:     30,
	},
	"pro": {
		Name:           "pro",
		MaxConnections: 20,
		BandwidthMbps:  50,
		DataLimitBytes: -1,           // unlimited
		DaysExpiry:     90,
	},
	"unlimited": {
		Name:           "unlimited",
		MaxConnections: -1,           // unlimited
		BandwidthMbps:  -1,
		DataLimitBytes: -1,
		DaysExpiry:     -1,
	},
}

// ─── User CRUD ─────────────────────────────────────────────────────────────

type User struct {
	ID              int64   `json:"id"`
	Username        string  `json:"username"`
	PasswordHash    string  `json:"-"`
	Tier            string  `json:"tier"`
	MaxConnections  int     `json:"max_connections"`
	BandwidthMbps   int     `json:"bandwidth_mbps"`
	DataLimitBytes  int64   `json:"data_limit_bytes"`
	DataUsedBytes   int64   `json:"data_used_bytes"`
	Expiry          *string `json:"expiry"`
	Enabled         bool    `json:"enabled"`
	CreatedAt       string  `json:"created_at"`
	ActiveConns     int64   `json:"active_connections"`
}

func GeneratePassword() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Store) CreateUser(username, password, tier string) (*User, error) {
	t, ok := Tiers[tier]
	if !ok {
		return nil, fmt.Errorf("unknown tier: %s", tier)
	}

	var expiry *string
	if t.DaysExpiry > 0 {
		e := time.Now().AddDate(0, 0, t.DaysExpiry).Format("2006-01-02 15:04:05")
		expiry = &e
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(
		`INSERT INTO users (username, password_hash, tier, max_connections, bandwidth_mbps, data_limit_bytes, expiry)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		username, password, tier, t.MaxConnections, t.BandwidthMbps, t.DataLimitBytes, expiry,
	)
	if err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}

	id, _ := result.LastInsertId()
	return &User{
		ID:             id,
		Username:       username,
		Tier:           tier,
		MaxConnections: t.MaxConnections,
		BandwidthMbps:  t.BandwidthMbps,
		DataLimitBytes: t.DataLimitBytes,
		DataUsedBytes:  0,
		Expiry:         expiry,
		Enabled:        true,
	}, nil
}

func (s *Store) GetUser(username string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u := &User{}
	var enabled int
	err := s.db.QueryRow(
		`SELECT id, username, password_hash, tier, max_connections, bandwidth_mbps, data_limit_bytes, data_used_bytes, expiry, enabled, created_at
		 FROM users WHERE username = ?`, username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Tier, &u.MaxConnections, &u.BandwidthMbps, &u.DataLimitBytes, &u.DataUsedBytes, &u.Expiry, &enabled, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.Enabled = enabled == 1

	// Get active connections count
	s.db.QueryRow("SELECT COUNT(*) FROM user_connections WHERE user_id = ? AND disconnected_at IS NULL", u.ID).Scan(&u.ActiveConns)

	return u, nil
}

func (s *Store) GetUserByID(id int64) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u := &User{}
	var enabled int
	err := s.db.QueryRow(
		`SELECT id, username, password_hash, tier, max_connections, bandwidth_mbps, data_limit_bytes, data_used_bytes, expiry, enabled, created_at
		 FROM users WHERE id = ?`, id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Tier, &u.MaxConnections, &u.BandwidthMbps, &u.DataLimitBytes, &u.DataUsedBytes, &u.Expiry, &enabled, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.Enabled = enabled == 1
	s.db.QueryRow("SELECT COUNT(*) FROM user_connections WHERE user_id = ? AND disconnected_at IS NULL", u.ID).Scan(&u.ActiveConns)

	return u, nil
}

func (s *Store) ListUsers() ([]User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(
		`SELECT u.id, u.username, u.tier, u.max_connections, u.bandwidth_mbps, u.data_limit_bytes, u.data_used_bytes, u.expiry, u.enabled, u.created_at,
		 (SELECT COUNT(*) FROM user_connections WHERE user_id = u.id AND disconnected_at IS NULL) as active_conns
		 FROM users u ORDER BY u.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		var enabled int
		if err := rows.Scan(&u.ID, &u.Username, &u.Tier, &u.MaxConnections, &u.BandwidthMbps, &u.DataLimitBytes, &u.DataUsedBytes, &u.Expiry, &enabled, &u.CreatedAt, &u.ActiveConns); err != nil {
			continue
		}
		u.Enabled = enabled == 1
		users = append(users, u)
	}
	return users, nil
}

func (s *Store) UpdateUser(id int64, tier *string, password *string, enabled *bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if tier != nil {
		t, ok := Tiers[*tier]
		if !ok {
			return fmt.Errorf("unknown tier: %s", *tier)
		}
		var expiry *string
		if t.DaysExpiry > 0 {
			e := time.Now().AddDate(0, 0, t.DaysExpiry).Format("2006-01-02 15:04:05")
			expiry = &e
		}
		_, err := s.db.Exec(
			`UPDATE users SET tier=?, max_connections=?, bandwidth_mbps=?, data_limit_bytes=?, expiry=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
			tier, t.MaxConnections, t.BandwidthMbps, t.DataLimitBytes, expiry, id,
		)
		if err != nil {
			return err
		}
	}
	if password != nil {
		_, err := s.db.Exec("UPDATE users SET password_hash=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", *password, id)
		if err != nil {
			return err
		}
	}
	if enabled != nil {
		v := 0
		if *enabled {
			v = 1
		}
		_, err := s.db.Exec("UPDATE users SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", v, id)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) DeleteUser(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM users WHERE id=?", id)
	return err
}

func (s *Store) ResetUserData(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("UPDATE users SET data_used_bytes=0, updated_at=CURRENT_TIMESTAMP WHERE id=?", id)
	return err
}

// ─── Connection Tracking ───────────────────────────────────────────────────

func (s *Store) TrackConnectionStart(userID int64, target string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(
		"INSERT INTO user_connections (user_id, target) VALUES (?, ?)",
		userID, target,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *Store) TrackConnectionEnd(connID int64, bytesUp, bytesDown int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		"UPDATE user_connections SET bytes_up=?, bytes_down=?, disconnected_at=CURRENT_TIMESTAMP WHERE id=?",
		bytesUp, bytesDown, connID,
	)
	if err != nil {
		return err
	}

	// Update user data usage
	_, err = s.db.Exec(
		`UPDATE users SET data_used_bytes = data_used_bytes + ?, updated_at=CURRENT_TIMESTAMP
		 WHERE id = (SELECT user_id FROM user_connections WHERE id = ?)`,
		bytesUp+bytesDown, connID,
	)
	return err
}

func (s *Store) GetActiveConnCount(userID int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var count int64
	err := s.db.QueryRow("SELECT COUNT(*) FROM user_connections WHERE user_id = ? AND disconnected_at IS NULL", userID).Scan(&count)
	return count, err
}

func (s *Store) Close() error {
	return s.db.Close()
}
