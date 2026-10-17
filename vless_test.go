package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ─── Store ──────────────────────────────────────────────────────────────────

func TestVlessClientCRUD(t *testing.T) {
	store := newTestStore(t)

	const uuid = "0cd94710-7290-40da-857d-5f5a7670cd62"
	client, err := store.CreateVlessClient(uuid, "alice's phone")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !client.Enabled || client.Label != "alice's phone" {
		t.Errorf("created client = %+v, want enabled with its label", client)
	}

	// The same UUID twice is an error, not a second row: two rows would make
	// revocation ambiguous.
	if _, err := store.CreateVlessClient(uuid, "impostor"); err == nil {
		t.Error("the same uuid was accepted twice")
	}

	if _, err := store.CreateVlessClient("not-a-uuid", ""); err == nil {
		t.Error("a non-uuid was accepted")
	}

	clients, err := store.ListVlessClients()
	if err != nil || len(clients) != 1 {
		t.Fatalf("list = %+v, %v", clients, err)
	}

	disabled := false
	if err := store.UpdateVlessClient(client.ID, nil, &disabled); err != nil {
		t.Fatalf("disable: %v", err)
	}
	uuids, err := store.EnabledVlessClientUUIDs()
	if err != nil {
		t.Fatalf("enabled uuids: %v", err)
	}
	if len(uuids) != 0 {
		t.Errorf("a disabled client is still offered to xray: %v", uuids)
	}

	// A label-only edit must not silently re-enable it.
	if err := store.UpdateVlessClient(client.ID, stringPtr("renamed"), nil); err != nil {
		t.Fatalf("relabel: %v", err)
	}
	clients, _ = store.ListVlessClients()
	if clients[0].Label != "renamed" || clients[0].Enabled {
		t.Errorf("relabel changed more than the label: %+v", clients[0])
	}

	if err := store.DeleteVlessClient(client.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if clients, _ := store.ListVlessClients(); len(clients) != 0 {
		t.Errorf("delete left rows behind: %+v", clients)
	}
}

func stringPtr(v string) *string { return &v }

// ─── Where the client list comes from ───────────────────────────────────────

func TestResolveRealityKeysUsesManagedClients(t *testing.T) {
	bin := fakeXray(t, "private", "public")
	store := newTestStore(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := DefaultConfig()
	cfg.RealityXrayBin = bin

	// An id left behind by an earlier version, in the old comma-joined value.
	// Upgrading must adopt it, not drop it: the table would otherwise shadow
	// the config and revoke a client that is still in the field.
	const legacyID = "11111111-2222-3333-4444-555555555555"
	persisted := map[string]string{dbRealityClientIDs: legacyID}

	keys, err := resolveRealityKeys(cfg, persisted, store, log)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(keys.ClientIDs) != 1 || keys.ClientIDs[0] != legacyID {
		t.Fatalf("client ids = %v, want the legacy id adopted", keys.ClientIDs)
	}
	clients, _ := store.ListVlessClients()
	if len(clients) != 1 || clients[0].Label != "migrated" {
		t.Fatalf("legacy id was not adopted into the table: %+v", clients)
	}

	// Adding a managed client adds to the list. The adopted id stays: upgrading
	// and then adding someone must not quietly revoke the client that was
	// already in the field.
	const managedID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	if _, err := store.CreateVlessClient(managedID, "new phone"); err != nil {
		t.Fatalf("create managed: %v", err)
	}
	keys, err = resolveRealityKeys(cfg, persisted, store, log)
	if err != nil {
		t.Fatalf("resolve again: %v", err)
	}
	if len(keys.ClientIDs) != 2 {
		t.Errorf("client ids = %v, want the adopted and the new client", keys.ClientIDs)
	}
	found := false
	for _, id := range keys.ClientIDs {
		if id == managedID {
			found = true
		}
	}
	if !found {
		t.Errorf("the new client is missing from %v", keys.ClientIDs)
	}

	// Disabling one leaves the other alone.
	all, _ := store.ListVlessClients()
	for _, c := range all {
		if c.UUID == managedID {
			off := false
			if err := store.UpdateVlessClient(c.ID, nil, &off); err != nil {
				t.Fatalf("disable: %v", err)
			}
		}
	}
	keys, err = resolveRealityKeys(cfg, persisted, store, log)
	if err != nil {
		t.Fatalf("resolve with one disabled: %v", err)
	}
	if len(keys.ClientIDs) != 1 || keys.ClientIDs[0] != legacyID {
		t.Errorf("client ids = %v, want only the still-enabled one", keys.ClientIDs)
	}

	// Configuration still outranks the table, as it does everywhere else.
	cfg.RealityClientIDs = []string{legacyID}
	keys, err = resolveRealityKeys(cfg, persisted, store, log)
	if err != nil {
		t.Fatalf("resolve with config: %v", err)
	}
	if len(keys.ClientIDs) != 1 || keys.ClientIDs[0] != legacyID {
		t.Errorf("client ids = %v, want the configured id to win", keys.ClientIDs)
	}
}

// ─── The API ────────────────────────────────────────────────────────────────

// adminRequest drives the admin mux the way the dashboard does.
func adminRequest(t *testing.T, s *ProxyServer, method, path string, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.RemoteAddr = "127.0.0.1:5000"
	rec := httptest.NewRecorder()
	s.adminHandler().ServeHTTP(rec, req)
	return rec
}

func TestVlessClientAPIRequiresReality(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AdminPort = freePort(t)
	cfg.AuthEnabled = false
	s := NewProxyServer(cfg)
	s.store = newTestStore(t)

	// Listing works without xray, so the dashboard can say why it is empty.
	rec := adminRequest(t, s, http.MethodGet, "/api/vless-clients", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET with REALITY off = %d, want 200: %s", rec.Code, rec.Body)
	}
	var listing struct {
		Clients         []VlessClient `json:"clients"`
		RealityEnabled  bool          `json:"reality_enabled"`
		ManagedByConfig bool          `json:"managed_by_config"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listing); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if listing.RealityEnabled {
		t.Error("reality_enabled should be false when REALITY is off")
	}

	// Mutating is refused rather than accepted-and-ignored.
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/vless-clients", `{"label":"x"}`},
		{http.MethodPut, "/api/vless-clients/1", `{"enabled":false}`},
		{http.MethodDelete, "/api/vless-clients/1", ""},
	} {
		rec := adminRequest(t, s, tc.method, tc.path, tc.body)
		if rec.Code != http.StatusConflict {
			t.Errorf("%s %s with REALITY off = %d, want 409: %s", tc.method, tc.path, rec.Code, rec.Body)
		}
	}
}

func TestVlessClientAPIRejectsPinnedListAndLastRemoval(t *testing.T) {
	bin := requireXray(t)
	store := newTestStore(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := DefaultConfig()
	cfg.RealityXrayBin = bin
	cfg.RealityBind = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	keys, err := resolveRealityKeys(cfg, nil, store, log)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	runner, err := startReality(cfg, keys, log)
	if err != nil {
		t.Fatalf("start reality: %v", err)
	}
	defer runner.Stop()

	s := NewProxyServer(cfg)
	s.store = store
	s.reality, s.realityKeys = runner, keys

	// resolveRealityKeys generated and stored one client, which is now the only
	// one there is.
	clients, err := store.ListVlessClients()
	if err != nil || len(clients) != 1 {
		t.Fatalf("expected exactly the generated client: %+v, %v", clients, err)
	}
	created := clients[0]

	// Removing the last client would leave xray with nobody to serve, which
	// looks like a successful edit and breaks every client on the planet.
	rec := adminRequest(t, s, http.MethodDelete, fmt.Sprintf("/api/vless-clients/%d", created.ID), "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("removing the last client = %d, want an error: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "no clients") {
		t.Errorf("error %q should explain that no client would be left", rec.Body)
	}
	if clients, _ := store.ListVlessClients(); len(clients) != 1 {
		t.Fatalf("a refused removal still deleted the row: %+v", clients)
	}

	// A pinned list is refused instead of silently doing nothing.
	s.configMu.Lock()
	s.cfg.RealityClientIDs = []string{keys.ClientIDs[0]}
	s.configMu.Unlock()
	rec = adminRequest(t, s, http.MethodPost, "/api/vless-clients", `{"label":"ignored"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST with a pinned list = %d, want 409: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "REALITY_CLIENT_IDS") {
		t.Errorf("error %q should name the variable pinning the list", rec.Body)
	}
}

// ─── End to end ─────────────────────────────────────────────────────────────

// TestRealityClientRevocationTakesEffect runs the whole loop: a UUID is revoked
// from the database, and a REALITY client still configured with it must stop
// working without the proxy being restarted. A management screen that does not
// revoke anything is worse than no management screen.
func TestRealityClientRevocationTakesEffect(t *testing.T) {
	bin := requireXray(t)
	store := newTestStore(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// An origin the client will actually reach.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "revocation-e2e-ok")
	}))
	defer origin.Close()

	proxyCfg := DefaultConfig()
	proxyCfg.AuthEnabled = false
	proxyCfg.AdminEnabled = false
	proxyCfg.SecurityHeadersEnabled = false
	proxyCfg.RateLimitEnabled = false
	proxyCfg.ProxyPort = freePort(t)

	realityPort := freePort(t)
	cfg := proxyCfg
	cfg.RealityXrayBin = bin
	cfg.RealityEnabled = true
	cfg.RealityBind = fmt.Sprintf("127.0.0.1:%d", realityPort)
	cfg.RealityPublicHost = "127.0.0.1"

	// One config for the server and the runner: the reload re-renders from
	// server.cfg, exactly as runServer does.
	server := NewProxyServer(cfg)
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", proxyCfg.ProxyPort))
	if err != nil {
		t.Fatalf("listen socks: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go server.handleClient(conn, "")
		}
	}()

	const revokedID = "0cd94710-7290-40da-857d-5f5a7670cd62"
	const keptID = "0cd94710-7290-40da-857d-5f5a7670cd63"
	for _, id := range []string{revokedID, keptID} {
		if _, err := store.CreateVlessClient(id, "test client"); err != nil {
			t.Fatalf("seed client %s: %v", id, err)
		}
	}

	keys, err := resolveRealityKeys(cfg, nil, store, log)
	if err != nil {
		t.Fatalf("resolve keys: %v", err)
	}
	if len(keys.ClientIDs) != 2 {
		t.Fatalf("client ids = %v, want both managed clients", keys.ClientIDs)
	}

	runner, err := startReality(cfg, keys, log)
	if err != nil {
		t.Fatalf("start reality: %v", err)
	}
	defer runner.Stop()

	server.store = store
	server.reality, server.realityKeys = runner, keys

	// A REALITY client whose config still carries the id about to be revoked.
	staleClient := startRealityTestClient(t, bin, cfg, keys, revokedID, freePort(t))
	liveClient := startRealityTestClient(t, bin, cfg, keys, keptID, freePort(t))

	fetch := func(clientPort int) error {
		u, err := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", clientPort))
		if err != nil {
			return err
		}
		httpClient := &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(u)},
			Timeout:   25 * time.Second,
		}
		resp, err := httpClient.Get(origin.URL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if string(body) != "revocation-e2e-ok" {
			return fmt.Errorf("body = %q", body)
		}
		return nil
	}

	// Both work before the change.
	if err := fetch(staleClient); err != nil {
		t.Fatalf("the client that is about to be revoked should work now: %v", err)
	}
	if err := fetch(liveClient); err != nil {
		t.Fatalf("the client that stays should work now: %v", err)
	}

	// Revoke through the same path the dashboard uses.
	rec := adminRequest(t, server, http.MethodDelete, fmt.Sprintf("/api/vless-clients/%d", idOfUUID(t, store, revokedID)), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d: %s", rec.Code, rec.Body)
	}

	// No restart, no waiting: the revoked UUID must already be refused.
	if err := fetch(staleClient); err == nil {
		t.Error("a revoked uuid still works; the dashboard change did not reach xray")
	}
	// The other client is untouched.
	if err := fetch(liveClient); err != nil {
		t.Errorf("revoking one client broke another: %v", err)
	}
}

// startRealityTestClient runs a second xray as the client and returns the port
// of its local SOCKS5 inbound.
func startRealityTestClient(t *testing.T, bin string, cfg Config, keys realityKeys, uuid string, clientPort int) int {
	t.Helper()

	clientKeys := keys
	clientKeys.ClientIDs = []string{uuid}
	data, err := renderRealityClientConfig(cfg.RealityPublicHost, portOf(t, cfg.RealityBind), "127.0.0.1", clientPort, clientKeys)
	if err != nil {
		t.Fatalf("render client: %v", err)
	}
	file := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}

	cmd := exec.Command(bin, "run", "-c", file)
	// The client's own log is the only place a refusal shows up, and a silent
	// skip here would look like a flaky proxy rather than a rejected UUID.
	cmd.Stdout, cmd.Stderr = &testWriter{t: t, tag: "client"}, &testWriter{t: t, tag: "client"}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start client xray: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})

	deadline := time.Now().Add(15 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return clientPort
		}
		if time.Now().After(deadline) {
			t.Fatalf("client socks port %d never opened: %v", clientPort, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// testWriter routes a subprocess log into the test output.
type testWriter struct {
	t   *testing.T
	tag string
	buf string
}

func (w *testWriter) Write(p []byte) (int, error) {
	w.buf += string(p)
	for {
		i := strings.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.t.Logf("[%s] %s", w.tag, w.buf[:i])
		w.buf = w.buf[i+1:]
	}
	return len(p), nil
}

func portOf(t *testing.T, addr string) int {
	t.Helper()
	_, port, err := splitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	return port
}

func idOfUUID(t *testing.T, store *Store, uuid string) int64 {
	t.Helper()
	clients, err := store.ListVlessClients()
	if err != nil {
		t.Fatalf("list clients: %v", err)
	}
	for _, c := range clients {
		if c.UUID == uuid {
			return c.ID
		}
	}
	t.Fatalf("no managed client with uuid %s", uuid)
	return 0
}

// The dashboard is one HTML file with inline script, so the cheapest honest
// check is that the panel is wired to the endpoints this build serves.
func TestDashboardVlessPanelWiring(t *testing.T) {
	data, err := os.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("read dashboard: %v", err)
	}
	html := string(data)

	for _, id := range []string{"vless-body", "v-label", "v-uuid", "vless-msg"} {
		if !strings.Contains(html, `id="`+id+`"`) {
			t.Errorf("dashboard has no element with id %q", id)
		}
	}
	for _, fn := range []string{"loadVlessClients", "createVlessClient", "toggleVlessClient", "deleteVlessClient"} {
		if !strings.Contains(html, "function "+fn+"(") {
			t.Errorf("dashboard has no %s function", fn)
		}
	}
	if !strings.Contains(html, "/api/vless-clients") {
		t.Error("dashboard never talks to /api/vless-clients")
	}
	// Defined is not wired: the list has to load on startup.
	if !strings.Contains(html, "\nloadVlessClients();") {
		t.Error("loadVlessClients() is not called on startup")
	}

	cfg := DefaultConfig()
	cfg.AuthEnabled = false
	s := NewProxyServer(cfg)
	s.store = newTestStore(t)
	rec := adminRequest(t, s, http.MethodGet, "/api/vless-clients", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/vless-clients = %d", rec.Code)
	}
	var listing struct {
		Clients []VlessClient `json:"clients"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listing); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if listing.Clients == nil {
		t.Error("clients must serialise as [], not null, so the panel can loop over it")
	}
}
