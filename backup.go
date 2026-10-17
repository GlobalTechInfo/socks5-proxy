package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ─── Backup and restore ─────────────────────────────────────────────────────
//
// A running proxy cannot simply have its database file copied: SQLite runs in
// WAL mode here, so the most recent writes live in socks5.db-wal and a naive
// copy of socks5.db loses them. This takes a proper snapshot instead, with
// VACUUM INTO, which produces a single consistent file while the server keeps
// serving.
//
// The archive also carries config.json and the generated reality-client.json,
// because a database without its REALITY keypair is a database that silently
// invalidates every client the operator has imported.

const (
	backupMagic       = "S5BK"
	backupVersion     = 1
	backupFlagPlain   = 0
	backupFlagCrypto  = 1
	backupSaltLen     = 16
	backupNonceLen    = 12
	backupKeyLen      = 32
	backupPBKDF2Iters = 600000
	backupManifestTyp = "manifest.json"
	backupDBName      = "socks5.db"
	backupPidName     = "socks5.pid"
	// backupMaxFile bounds any single entry, so a corrupt length field cannot
	// make restore allocate an enormous buffer.
	backupMaxFile = 4 << 30
)

type backupManifest struct {
	CreatedAt    string        `json:"created_at"`
	ProxyVersion string        `json:"proxy_version"`
	Files        []backupEntry `json:"files"`
}

type backupEntry struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// backupFileNames are the members of an archive, in a fixed order.
var backupFileNames = []string{backupDBName, "config.json", "reality-client.json"}

// ─── backup ─────────────────────────────────────────────────────────────────

func runBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	out := fs.String("out", "", "output archive (required)")
	passphrase := fs.String("passphrase", "", "encrypt the archive with this passphrase")
	dataDir := fs.String("data", "data", "directory holding socks5.db")
	pass := fs.String("config", "config.json", "path to config.json to include, if present")
	clientCfg := fs.String("client-config", "reality-client.json", "REALITY client config to include, if present")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-out is required")
	}

	files := make([][]byte, len(backupFileNames))
	present := make([]bool, len(backupFileNames))
	for i, name := range backupFileNames {
		path := filepath.Join(*dataDir, name)
		if name == "config.json" {
			path = *pass
		}
		if name == "reality-client.json" {
			path = *clientCfg
		}

		if name == backupDBName {
			if _, statErr := os.Stat(path); statErr != nil {
				return fmt.Errorf("no database at %s: %w", path, statErr)
			}
			data, cleanup, err := snapshotDatabase(path)
			if err != nil {
				return err
			}
			defer cleanup()
			files[i], present[i] = data, true
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				// The config files are optional; the database is not.
				continue
			}
			return fmt.Errorf("read %s: %w", path, err)
		}
		files[i], present[i] = data, true
	}

	manifest := backupManifest{
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		ProxyVersion: version,
	}
	for i, name := range backupFileNames {
		if !present[i] {
			continue
		}
		sum := sha256.Sum256(files[i])
		manifest.Files = append(manifest.Files, backupEntry{
			Name:   name,
			Size:   int64(len(files[i])),
			SHA256: hex.EncodeToString(sum[:]),
		})
	}

	if err := writeBackupArchive(*out, files, present, manifest, *passphrase); err != nil {
		return err
	}
	info, _ := os.Stat(*out)
	size := int64(0)
	if info != nil {
		size = info.Size()
	}
	names := make([]string, 0, len(manifest.Files))
	for _, e := range manifest.Files {
		names = append(names, e.Name)
	}
	encrypted := ""
	if *passphrase != "" {
		encrypted = ", encrypted"
	}
	fmt.Fprintf(os.Stdout, "backup written to %s (%d bytes%s): %s\n",
		*out, size, encrypted, strings.Join(names, ", "))
	return nil
}

// writeBackupArchive lays the files out as a gzipped tar, wraps it in the small
// self-describing header, and optionally encrypts it.
func writeBackupArchive(path string, files [][]byte, present []bool, manifest backupManifest, passphrase string) error {
	var payload bytes.Buffer
	gz := gzip.NewWriter(&payload)
	tw := tar.NewWriter(gz)

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := writeTarEntry(tw, backupManifestTyp, manifestJSON); err != nil {
		return err
	}
	for i, name := range backupFileNames {
		if !present[i] {
			continue
		}
		if err := writeTarEntry(tw, name, files[i]); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}

	out := payload.Bytes()
	header := make([]byte, 0, len(backupMagic)+2+backupSaltLen+backupNonceLen)
	header = append(header, backupMagic...)
	header = append(header, backupVersion)

	if passphrase == "" {
		header = append(header, backupFlagPlain)
	} else {
		header = append(header, backupFlagCrypto)
		salt := make([]byte, backupSaltLen)
		if _, err := rand.Read(salt); err != nil {
			return fmt.Errorf("generate salt: %w", err)
		}
		nonce := make([]byte, backupNonceLen)
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("generate nonce: %w", err)
		}
		key, err := deriveBackupKey(passphrase, salt)
		if err != nil {
			return err
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		out = gcm.Seal(nil, nonce, payload.Bytes(), []byte(backupMagic))
		header = append(header, salt...)
		header = append(header, nonce...)
	}

	// Write to a temporary file and rename, so an interrupted backup never
	// leaves a half-written archive that looks complete.
	tmp := path + ".partial"
	if err := os.WriteFile(tmp, append(header, out...), 0o600); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("finalise backup: %w", err)
	}
	return nil
}

// snapshotDatabase returns a consistent copy of the database.
//
// It must not read the file. The database runs in WAL mode, so the most
// recently committed writes live in the -wal sidecar and a plain read of
// socks5.db can silently return a database that is missing them -- a backup that
// restores cleanly and loses data. VACUUM INTO asks SQLite for a consistent
// view and writes it to a single self-contained file, and it is safe to run
// while the server is serving.
func snapshotDatabase(dbPath string) ([]byte, func(), error) {
	tmp, err := os.CreateTemp("", "socks5-snapshot-*.db")
	if err != nil {
		return nil, func() {}, fmt.Errorf("snapshot: %w", err)
	}
	cleanup := func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}
	// VACUUM INTO refuses to overwrite, so the temporary must be empty and
	// then removed before it can be used as a target.
	if _, err := tmp.Write(nil); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	place := tmp.Name()
	tmp.Close()
	os.Remove(place)

	db, err := sql.Open("sqlite", dbPath+
		"?_pragma=busy_timeout(5000)"+
		"&_pragma=foreign_keys(1)"+
		"&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, func() {}, fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	escaped := strings.ReplaceAll(place, "'", "''")
	if _, err := db.Exec(`VACUUM INTO '` + escaped + `'`); err != nil {
		return nil, func() {}, fmt.Errorf("snapshot %s: %w", dbPath, err)
	}
	data, err := os.ReadFile(place)
	if err != nil {
		return nil, func() {}, fmt.Errorf("read snapshot: %w", err)
	}
	return data, cleanup, nil
}

func writeTarEntry(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     0o600,
		Size:     int64(len(data)),
		Typeflag: tar.TypeReg,
		ModTime:  time.Unix(0, 0),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func deriveBackupKey(passphrase string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, passphrase, salt, backupPBKDF2Iters, backupKeyLen)
}

// ─── restore ────────────────────────────────────────────────────────────────

func runRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	in := fs.String("in", "", "archive to restore (required)")
	passphrase := fs.String("passphrase", "", "passphrase the archive was created with")
	dataDir := fs.String("data", "data", "directory holding socks5.db")
	pass := fs.String("config", "config.json", "path config.json should be restored to")
	clientCfg := fs.String("client-config", "reality-client.json", "path the REALITY client config should be restored to")
	force := fs.Bool("force", false, "restore even while the server appears to be running")
	list := fs.Bool("list", false, "print the archive contents and exit, restoring nothing")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return errors.New("-in is required")
	}
	if *list {
		return listBackupContents(*in, *passphrase)
	}

	if !*force {
		if pid, err := runningServerPID(*dataDir); err == nil {
			return fmt.Errorf("refusing to restore while the server is running (pid %d); stop it first, or pass -force", pid)
		}
	}

	files, manifest, err := readBackupArchive(*in, *passphrase)
	if err != nil {
		return err
	}
	db, ok := files[backupDBName]
	if !ok {
		return fmt.Errorf("archive has no %s; refusing to restore", backupDBName)
	}

	// Everything is decoded and verified before anything is written, so a
	// failure cannot leave a half-restored installation.
	staged := make(map[string]string) // final path -> temp path
	defer func() {
		for _, tmp := range staged {
			os.Remove(tmp)
		}
	}()

	stage := func(final string, data []byte) error {
		if err := os.MkdirAll(filepath.Dir(final), 0o750); err != nil {
			return err
		}
		tmp := final + ".restore-tmp"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			return fmt.Errorf("stage %s: %w", final, err)
		}
		staged[final] = tmp
		return nil
	}

	dbFinal := filepath.Join(*dataDir, backupDBName)
	// Keep what is there now. Restoring over a live database is the one
	// operation here that cannot be undone.
	if _, err := os.Stat(dbFinal); err == nil {
		keep := fmt.Sprintf("%s.pre-restore-%s", dbFinal, time.Now().UTC().Format("20060102T150405Z"))
		if err := copyFile(dbFinal, keep); err != nil {
			return fmt.Errorf("preserve current database: %w", err)
		}
		fmt.Fprintf(os.Stdout, "  existing database kept as %s\n", keep)
	}
	if err := stage(dbFinal, db); err != nil {
		return err
	}
	if data, ok := files["config.json"]; ok {
		if err := stage(*pass, data); err != nil {
			return err
		}
	}
	if data, ok := files["reality-client.json"]; ok {
		if err := stage(*clientCfg, data); err != nil {
			return err
		}
	}

	for final, tmp := range staged {
		if err := os.Rename(tmp, final); err != nil {
			return fmt.Errorf("install %s: %w", final, err)
		}
		delete(staged, final)
	}

	fmt.Fprintf(os.Stdout, "restored %s (%s): %d files\n", *in, manifest.CreatedAt, len(manifest.Files))
	for _, e := range manifest.Files {
		fmt.Fprintf(os.Stdout, "  %-22s %10d bytes  sha256:%s\n", e.Name, e.Size, e.SHA256[:16])
	}
	if _, ok := files[backupDBName]; ok {
		fmt.Fprintln(os.Stdout, "  REALITY clients keep working if this archive held the same keypair; a different keypair invalidates them.")
	}
	return nil
}

// readBackupArchive decodes, decrypts if needed, and verifies every member
// against the manifest before returning anything.
func readBackupArchive(path, passphrase string) (map[string][]byte, backupManifest, error) {
	files := map[string][]byte{}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, backupManifest{}, fmt.Errorf("read %s: %w", path, err)
	}
	head := len(backupMagic) + 2
	if len(raw) < head || string(raw[:len(backupMagic)]) != backupMagic {
		return nil, backupManifest{}, errors.New("not a socks5-proxy backup archive")
	}
	if v := raw[len(backupMagic)]; v != backupVersion {
		return nil, backupManifest{}, fmt.Errorf("archive version %d, this build understands %d", v, backupVersion)
	}

	var payload []byte
	switch raw[len(backupMagic)+1] {
	case backupFlagPlain:
		if passphrase != "" {
			return nil, backupManifest{}, errors.New("this archive is not encrypted, but a passphrase was given")
		}
		payload = raw[head:]
	case backupFlagCrypto:
		if passphrase == "" {
			return nil, backupManifest{}, errors.New("this archive is encrypted; a passphrase is required")
		}
		need := head + backupSaltLen + backupNonceLen
		if len(raw) < need {
			return nil, backupManifest{}, errors.New("archive is truncated")
		}
		salt := raw[head : head+backupSaltLen]
		nonce := raw[head+backupSaltLen : need]
		key, err := deriveBackupKey(passphrase, salt)
		if err != nil {
			return nil, backupManifest{}, err
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, backupManifest{}, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, backupManifest{}, err
		}
		// GCM authenticates, so a wrong passphrase fails here with a clear
		// error rather than a checksum mismatch much later.
		payload, err = gcm.Open(nil, nonce, raw[need:], []byte(backupMagic))
		if err != nil {
			return nil, backupManifest{}, errors.New("wrong passphrase, or the archive is damaged")
		}
	default:
		return nil, backupManifest{}, fmt.Errorf("unknown archive flags 0x%02x", raw[len(backupMagic)+1])
	}

	gz, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, backupManifest{}, fmt.Errorf("archive is not a valid gzip stream: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, backupManifest{}, fmt.Errorf("read archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Refuse absurd declared sizes before allocating.
		if hdr.Size < 0 || hdr.Size > backupMaxFile {
			return nil, backupManifest{}, fmt.Errorf("archive entry %q has an implausible size %d", hdr.Name, hdr.Size)
		}
		// Only the known members are restored. An archive naming something
		// else must not be able to write outside the data directory.
		if !allowedBackupName(hdr.Name) {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, backupMaxFile+1))
		if err != nil {
			return nil, backupManifest{}, fmt.Errorf("read %s from archive: %w", hdr.Name, err)
		}
		files[hdr.Name] = data
	}

	var manifest backupManifest
	manifestJSON, ok := files[backupManifestTyp]
	if !ok {
		return nil, backupManifest{}, errors.New("archive has no manifest")
	}
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return nil, backupManifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	for _, e := range manifest.Files {
		data, ok := files[e.Name]
		if !ok {
			return nil, backupManifest{}, fmt.Errorf("archive is missing %s, listed in the manifest", e.Name)
		}
		if int64(len(data)) != e.Size {
			return nil, backupManifest{}, fmt.Errorf("%s is %d bytes, manifest says %d", e.Name, len(data), e.Size)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != e.SHA256 {
			return nil, backupManifest{}, fmt.Errorf("%s does not match its manifest checksum", e.Name)
		}
	}
	delete(files, backupManifestTyp)
	if len(files) == 0 {
		return nil, backupManifest{}, errors.New("archive contains no restorable files")
	}
	return files, manifest, nil
}

// allowedBackupName keeps extraction to the exact set of members this tool
// writes, so a hostile archive cannot drop a file anywhere else.
func allowedBackupName(name string) bool {
	if name == backupManifestTyp {
		return true
	}
	for _, allowed := range backupFileNames {
		if name == allowed {
			return true
		}
	}
	return false
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// ─── pid file ───────────────────────────────────────────────────────────────

// The pid file is how restore knows a server is holding the database. It is
// best-effort: a read-only or unusual data directory must not stop the proxy
// from starting.

func writePidFile(dataDir string) error {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dataDir, backupPidName),
		[]byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
}

func removePidFile(dataDir string) {
	_ = os.Remove(filepath.Join(dataDir, backupPidName))
}

// runningServerPID reports the pid of a live server using this data directory.
// A pid file left behind by a crash is not treated as running.
func runningServerPID(dataDir string) (int, error) {
	data, err := os.ReadFile(filepath.Join(dataDir, backupPidName))
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, errors.New("no usable pid file")
	}
	if pid == os.Getpid() {
		return pid, nil
	}
	// Signal 0 checks for existence without delivering anything.
	if err := kill0(pid); err != nil {
		return 0, errors.New("pid file is stale")
	}
	return pid, nil
}

// listBackupContents prints an archive's manifest without restoring it, which
// is what an operator wants before overwriting a working installation.
func listBackupContents(path, passphrase string) error {
	_, manifest, err := readBackupArchive(path, passphrase)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "%s\n  taken: %s by proxy %s\n", path, manifest.CreatedAt, manifest.ProxyVersion)
	names := make([]string, 0, len(manifest.Files))
	for _, e := range manifest.Files {
		names = append(names, e.Name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, e := range manifest.Files {
			if e.Name == name {
				fmt.Fprintf(os.Stdout, "  %-22s %10d bytes  sha256:%s\n", e.Name, e.Size, e.SHA256[:16])
			}
		}
	}
	return nil
}

// kill0 reports whether a process exists, without disturbing it.
func kill0(pid int) error {
	return syscall.Kill(pid, 0)
}
