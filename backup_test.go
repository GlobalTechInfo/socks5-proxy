package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func quietStore(t *testing.T, dir string) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(dir, backupDBName), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// seed writes something worth losing: users, config and a REALITY keypair.
func seed(t *testing.T, store *Store) {
	t.Helper()
	if _, err := store.CreateUser("alice", "pw", "pro"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := store.CreateUser("bob", "pw", "free"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	for k, v := range map[string]string{
		dbRealityPrivateKey: "PRIVATE-KEY-UNDER-TEST",
		dbRealityShortID:    "0123456789abcdef",
		dbRealityClientIDs:  "uuid-one,uuid-two",
		"proxy_pass":        "stored-pass",
	} {
		if err := store.SaveConfig(k, v); err != nil {
			t.Fatalf("SaveConfig %s: %v", k, err)
		}
	}
}

// countUsers opens a connection, reads, and closes it before returning.
//
// Closing matters: SQLite does its WAL cleanup by *path* when the last
// connection to a database goes away, so a store still holding the old file
// after a restore has installed a new database at the same path can rewrite it
// on close. That is exactly why `restore` refuses to run while the server is
// up, and these helpers must not reproduce it inside the test.
func countUsers(t *testing.T, dir string) int {
	t.Helper()
	store := quietStore(t, dir)
	defer store.Close()
	var n int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	return n
}

func storedConfig(t *testing.T, dir, key string) string {
	t.Helper()
	store := quietStore(t, dir)
	defer store.Close()
	var v string
	err := store.db.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&v)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		t.Fatalf("read config %s: %v", key, err)
	}
	return v
}

// ─── The round trip ─────────────────────────────────────────────────────────

func TestBackupRestoreRoundTrip(t *testing.T) {
	data := t.TempDir()
	store := quietStore(t, data)
	seed(t, store)

	config := filepath.Join(data, "config.json")
	clientCfg := filepath.Join(data, "reality-client.json")
	if err := os.WriteFile(config, []byte(`{"proxy_port":1080}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientCfg, []byte(`{"vnext":"placeholder"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup([]string{"-out", archive, "-data", data, "-config", config, "-client-config", clientCfg}); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// Wipe the installation the way a lost server would.
	for _, name := range []string{backupDBName, backupDBName + "-wal", backupDBName + "-shm"} {
		os.Remove(filepath.Join(data, name))
	}
	os.Remove(config)
	os.Remove(clientCfg)
	if got := countUsers(t, data); got != 0 {
		t.Fatalf("wipe left %d users behind", got)
	}

	if err := runRestore([]string{"-in", archive, "-data", data, "-config", config, "-client-config", clientCfg}); err != nil {
		t.Fatalf("restore: %v", err)
	}

	if got := countUsers(t, data); got != 2 {
		t.Errorf("restored %d users, want 2", got)
	}
	// The REALITY keypair is the part that silently breaks clients if lost.
	for key, want := range map[string]string{
		dbRealityPrivateKey: "PRIVATE-KEY-UNDER-TEST",
		dbRealityShortID:    "0123456789abcdef",
		dbRealityClientIDs:  "uuid-one,uuid-two",
		"proxy_pass":        "stored-pass",
	} {
		if got := storedConfig(t, data, key); got != want {
			t.Errorf("after restore %s = %q, want %q", key, got, want)
		}
	}
	if _, err := os.Stat(config); err != nil {
		t.Errorf("config.json was not restored: %v", err)
	}
	if _, err := os.Stat(clientCfg); err != nil {
		t.Errorf("reality-client.json was not restored: %v", err)
	}
}

// The whole reason this uses VACUUM INTO: in WAL mode the newest writes live in
// the sidecar, so a plain file copy would silently lose them.
func TestBackupCapturesUncheckpointedWrites(t *testing.T) {
	data := t.TempDir()
	store := quietStore(t, data)
	seed(t, store)

	// Write and leave it in the WAL: no checkpoint, no close.
	if _, err := store.db.Exec(`INSERT INTO users (username, password_hash, tier, max_connections, bandwidth_mbps, data_limit_bytes)
	                          VALUES ('carol', 'pw', 'free', 1, 1, 1024)`); err != nil {
		t.Fatalf("insert: %v", err)
	}

	wal, err := os.Stat(filepath.Join(data, backupDBName+"-wal"))
	if err != nil {
		t.Fatalf("expected a WAL sidecar to exist: %v", err)
	}
	if wal.Size() == 0 {
		t.Fatal("expected uncheckpointed data in the WAL for this test to mean anything")
	}

	archive := filepath.Join(t.TempDir(), "b.tar.gz")
	if err := runBackup([]string{"-out", archive, "-data", data, "-config", filepath.Join(data, "none.json")}); err != nil {
		t.Fatalf("backup: %v", err)
	}

	for _, name := range []string{backupDBName, backupDBName + "-wal", backupDBName + "-shm"} {
		os.Remove(filepath.Join(data, name))
	}
	if err := runRestore([]string{"-in", archive, "-data", data, "-config", filepath.Join(data, "none.json")}); err != nil {
		t.Fatalf("restore: %v", err)
	}

	if got := countUsers(t, data); got != 3 {
		t.Errorf("restored %d users, want 3: the snapshot lost writes that were still in the WAL", got)
	}
}

// ─── Encryption ─────────────────────────────────────────────────────────────

func TestEncryptedBackupRoundTrip(t *testing.T) {
	data := t.TempDir()
	seed(t, quietStore(t, data))

	archive := filepath.Join(t.TempDir(), "secret.tar.gz")
	const pass = "correct horse battery staple"
	if err := runBackup([]string{"-out", archive, "-data", data, "-passphrase", pass,
		"-config", filepath.Join(data, "none.json")}); err != nil {
		t.Fatalf("backup: %v", err)
	}

	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	// The database must not be sitting in the archive in the clear.
	if bytes.Contains(raw, []byte("PRIVATE-KEY-UNDER-TEST")) {
		t.Error("the archive contains the REALITY private key in plaintext despite -passphrase")
	}
	if !bytes.Contains(raw, []byte(backupMagic)) {
		t.Error("archive is missing its magic header")
	}

	for _, name := range []string{backupDBName, backupDBName + "-wal", backupDBName + "-shm"} {
		os.Remove(filepath.Join(data, name))
	}
	if err := runRestore([]string{"-in", archive, "-data", data, "-passphrase", pass,
		"-config", filepath.Join(data, "none.json")}); err != nil {
		t.Fatalf("restore with the right passphrase: %v", err)
	}
	if got := countUsers(t, data); got != 2 {
		t.Errorf("restored %d users, want 2", got)
	}
	if got := storedConfig(t, data, dbRealityPrivateKey); got != "PRIVATE-KEY-UNDER-TEST" {
		t.Errorf("private key after restore = %q", got)
	}
}

func TestRestoreWrongPassphraseChangesNothing(t *testing.T) {
	data := t.TempDir()
	seed(t, quietStore(t, data))
	before := storedConfig(t, data, dbRealityPrivateKey)

	archive := filepath.Join(t.TempDir(), "secret.tar.gz")
	if err := runBackup([]string{"-out", archive, "-data", data, "-passphrase", "right",
		"-config", filepath.Join(data, "none.json")}); err != nil {
		t.Fatalf("backup: %v", err)
	}

	err := runRestore([]string{"-in", archive, "-data", data, "-passphrase", "wrong",
		"-config", filepath.Join(data, "none.json")})
	if err == nil {
		t.Fatal("restoring with the wrong passphrase should fail")
	}
	if !strings.Contains(err.Error(), "passphrase") && !strings.Contains(err.Error(), "damaged") {
		t.Errorf("error %q should name the passphrase as the likely cause", err)
	}
	// Nothing may have been replaced: this is the failure an operator meets
	// at 3am, and it must not cost them the installation.
	if got := storedConfig(t, data, dbRealityPrivateKey); got != before {
		t.Errorf("private key changed to %q after a failed restore", got)
	}
	if got := countUsers(t, data); got != 2 {
		t.Errorf("a failed restore left %d users, want the original 2", got)
	}
}

func TestRestorePassphraseMismatchesAreReportedClearly(t *testing.T) {
	data := t.TempDir()
	seed(t, quietStore(t, data))
	plain := filepath.Join(t.TempDir(), "plain.tar.gz")
	if err := runBackup([]string{"-out", plain, "-data", data, "-config", filepath.Join(data, "none.json")}); err != nil {
		t.Fatalf("backup: %v", err)
	}

	if err := runRestore([]string{"-in", plain, "-data", data, "-passphrase", "invented",
		"-config", filepath.Join(data, "none.json")}); err == nil || !strings.Contains(err.Error(), "not encrypted") {
		t.Errorf("giving a passphrase for a plain archive: err = %v, want a clear complaint", err)
	}

	enc := filepath.Join(t.TempDir(), "enc.tar.gz")
	if err := runBackup([]string{"-out", enc, "-data", data, "-passphrase", "p",
		"-config", filepath.Join(data, "none.json")}); err != nil {
		t.Fatalf("encrypted backup: %v", err)
	}
	if err := runRestore([]string{"-in", enc, "-data", data, "-config", filepath.Join(data, "none.json")}); err == nil ||
		!strings.Contains(err.Error(), "passphrase is required") {
		t.Errorf("restoring an encrypted archive with no passphrase: err = %v", err)
	}
}

// ─── Tampering and shape ────────────────────────────────────────────────────

func TestRestoreRejectsTamperedArchive(t *testing.T) {
	data := t.TempDir()
	seed(t, quietStore(t, data))
	archive := filepath.Join(t.TempDir(), "b.tar.gz")
	if err := runBackup([]string{"-out", archive, "-data", data, "-config", filepath.Join(data, "none.json")}); err != nil {
		t.Fatalf("backup: %v", err)
	}

	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte deep inside the compressed payload.
	raw[len(raw)/2] ^= 0xff
	if err := os.WriteFile(archive, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{backupDBName, backupDBName + "-wal", backupDBName + "-shm"} {
		os.Remove(filepath.Join(data, name))
	}
	if err := runRestore([]string{"-in", archive, "-data", data, "-config", filepath.Join(data, "none.json")}); err == nil {
		t.Fatal("a tampered archive should not restore")
	}
	if _, err := os.Stat(filepath.Join(data, backupDBName)); err == nil {
		t.Error("a failed restore left a database behind")
	}
}

func TestRestoreRejectsForeignArchives(t *testing.T) {
	data := t.TempDir()
	notOurs := filepath.Join(t.TempDir(), "random.bin")
	if err := os.WriteFile(notOurs, bytes.Repeat([]byte("A"), 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runRestore([]string{"-in", notOurs, "-data", data}); err == nil ||
		!strings.Contains(err.Error(), "not a socks5-proxy backup") {
		t.Errorf("restore of a foreign file: err = %v", err)
	}

	// Correct magic, wrong version: must be refused rather than guessed at.
	wrongVersion := filepath.Join(t.TempDir(), "future.tar.gz")
	raw := append([]byte(backupMagic), 99, 0)
	if err := os.WriteFile(wrongVersion, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runRestore([]string{"-in", wrongVersion, "-data", data}); err == nil ||
		!strings.Contains(err.Error(), "archive version") {
		t.Errorf("restore of a newer archive: err = %v", err)
	}
}

func newGzip(w io.Writer) *gzip.Writer { return gzip.NewWriter(w) }

func newTar(gz *gzip.Writer) *tar.Writer { return tar.NewWriter(gz) }

func writeEntry(t *testing.T, tw *tar.Writer, name string, data []byte) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
}

// An archive naming a file outside the known set must not be able to write it.
func TestRestoreIgnoresUnknownArchiveMembers(t *testing.T) {
	data := t.TempDir()
	seed(t, quietStore(t, data))

	// Build an archive by hand with a member this tool never writes.
	var payload bytes.Buffer
	gz := newGzip(&payload)
	tw := newTar(gz)
	writeEntry(t, tw, backupManifestTyp, []byte(`{"created_at":"now","proxy_version":"x","files":[{"name":"socks5.db","size":0,"sha256":""}]}`))
	writeEntry(t, tw, "../escaped.db", []byte("owned"))
	gz.Close()
	tw.Close()

	archive := filepath.Join(t.TempDir(), "hostile.tar.gz")
	header := append([]byte(backupMagic), backupVersion, backupFlagPlain)
	if err := os.WriteFile(archive, append(header, payload.Bytes()...), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runRestore([]string{"-in", archive, "-data", data, "-config", filepath.Join(data, "none.json")})
	// The manifest names socks5.db, which is absent, so it fails for that
	// reason; what matters is that nothing escaped.
	if err != nil && !strings.Contains(err.Error(), "missing socks5.db") {
		t.Errorf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(data), "escaped.db")); statErr == nil {
		t.Error("a path-traversal member was written outside the data directory")
	}
}

func TestBackupRefusesWhenServerRunning(t *testing.T) {
	data := t.TempDir()
	seed(t, quietStore(t, data))
	archive := filepath.Join(t.TempDir(), "b.tar.gz")
	if err := runBackup([]string{"-out", archive, "-data", data, "-config", filepath.Join(data, "none.json")}); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// This process is alive, so its pid is exactly the "server is running"
	// condition restore has to catch.
	if err := writePidFile(data); err != nil {
		t.Fatalf("writePidFile: %v", err)
	}
	defer removePidFile(data)

	if _, err := runningServerPID(data); err != nil {
		t.Fatalf("runningServerPID: %v", err)
	}
	err := runRestore([]string{"-in", archive, "-data", data, "-config", filepath.Join(data, "none.json")})
	if err == nil || !strings.Contains(err.Error(), "server is running") {
		t.Errorf("restore over a live server: err = %v, want a refusal", err)
	}

	// -force is the documented escape hatch and must work.
	if err := runRestore([]string{"-in", archive, "-data", data, "-force",
		"-config", filepath.Join(data, "none.json")}); err != nil {
		t.Errorf("restore -force: %v", err)
	}
}

func TestStalePidFileIsNotTreatedAsRunning(t *testing.T) {
	data := t.TempDir()
	// A pid that cannot be running: kernel pids max out well below this.
	if err := os.WriteFile(filepath.Join(data, backupPidName), []byte("4194303\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runningServerPID(data); err == nil {
		t.Error("a pid file from a crashed process should not block a restore")
	}
}

func TestRestoreKeepsTheExistingDatabase(t *testing.T) {
	data := t.TempDir()
	seed(t, quietStore(t, data))
	archive := filepath.Join(t.TempDir(), "b.tar.gz")
	if err := runBackup([]string{"-out", archive, "-data", data, "-config", filepath.Join(data, "none.json")}); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if err := runRestore([]string{"-in", archive, "-data", data, "-config", filepath.Join(data, "none.json")}); err != nil {
		t.Fatalf("restore: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(data, backupDBName+".pre-restore-*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("found %d pre-restore copies, want exactly 1 (%v)", len(matches), err)
	}
}

func TestBackupListDoesNotTouchAnything(t *testing.T) {
	data := t.TempDir()
	seed(t, quietStore(t, data))
	archive := filepath.Join(t.TempDir(), "b.tar.gz")
	if err := runBackup([]string{"-out", archive, "-data", data, "-config", filepath.Join(data, "none.json")}); err != nil {
		t.Fatalf("backup: %v", err)
	}
	for _, name := range []string{backupDBName, backupDBName + "-wal", backupDBName + "-shm"} {
		os.Remove(filepath.Join(data, name))
	}
	if err := listBackupContents(archive, ""); err != nil {
		t.Fatalf("list: %v", err)
	}
	if _, err := os.Stat(filepath.Join(data, backupDBName)); err == nil {
		t.Error("-list restored something; it must only print")
	}
}

func TestBackupRequiresDatabase(t *testing.T) {
	data := t.TempDir()
	archive := filepath.Join(t.TempDir(), "b.tar.gz")
	err := runBackup([]string{"-out", archive, "-data", data, "-config", filepath.Join(data, "none.json")})
	if err == nil || !strings.Contains(err.Error(), "no database") {
		t.Errorf("backup with no database: err = %v, want a clear refusal", err)
	}
	if _, statErr := os.Stat(archive); statErr == nil {
		t.Error("a failed backup left an archive behind")
	}
}

// ─── The pragmas this database actually runs with ───────────────────────────

// The DSN used to spell these the mattn/go-sqlite3 way, which modernc.org
// silently ignores. WAL matters most here: the snapshot design rests on it, and
// a file copy in rollback-journal mode can miss a transaction that was in
// flight when the copy was taken.
func TestDatabaseRunsInWALMode(t *testing.T) {
	store := quietStore(t, t.TempDir())

	var mode string
	if err := store.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}

	var fk int
	if err := store.db.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil {
		t.Fatalf("read foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, want 1: the schema declares a foreign key and nothing was enforcing it", fk)
	}
}

// Turning foreign keys on makes an orphaned reference an error rather than
// silent corruption. This asserts the enforcement is real, not just reported.
func TestForeignKeysAreEnforced(t *testing.T) {
	store := quietStore(t, t.TempDir())
	user, err := store.CreateUser("dave", "pw", "free")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.db.Exec(
		`INSERT INTO user_connections (user_id, target) VALUES (?, 'example.com:443')`, user.ID+9999); err == nil {
		t.Fatal("inserting a connection for a user that does not exist should fail")
	}
}

// The regression the foreign-key change would otherwise cause: deleting a user
// who has connection history must still work through the dashboard.
func TestDeleteUserWithConnectionHistory(t *testing.T) {
	store := quietStore(t, t.TempDir())
	user, err := store.CreateUser("erin", "pw", "free")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.TrackConnectionStart(user.ID, "example.com:443"); err != nil {
		t.Fatalf("TrackConnectionStart: %v", err)
	}

	var count int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM user_connections WHERE user_id = ?", user.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("expected recorded connection history for this test to mean anything")
	}

	if err := store.DeleteUser(user.ID); err != nil {
		t.Fatalf("DeleteUser with history present: %v", err)
	}
	var users, connections int
	store.db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", user.ID).Scan(&users)
	store.db.QueryRow("SELECT COUNT(*) FROM user_connections WHERE user_id = ?", user.ID).Scan(&connections)
	if users != 0 {
		t.Errorf("user row survived deletion")
	}
	if connections != 0 {
		t.Errorf("%d connection rows survived their user", connections)
	}
}
