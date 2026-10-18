package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The admin API uses HTTP Basic, and a browser attaches those credentials to any
// request for the origin -- including one a page on another site started. These
// tests hold the actual route that deletes a VLESS UUID, which is the worst case
// for an attacker: no request body, no unusual method, nothing a cross-site form
// cannot produce.
func csrfTestServer(t *testing.T) (*ProxyServer, *httptest.ResponseRecorder, string) {
	t.Helper()

	cfg := DefaultConfig()
	cfg.AuthEnabled = false
	s := NewProxyServer(cfg)
	s.store = newTestStore(t)
	row, err := s.store.CreateVlessClient("11111111-2222-3333-4444-555555555555", "victim")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return s, nil, fmt.Sprintf("%d", row.ID)
}

func csrfRequest(t *testing.T, s *ProxyServer, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.RemoteAddr = "127.0.0.1:5000"
	req.Host = "admin.example.com"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.adminHandler().ServeHTTP(rec, req)
	return rec
}

func TestCSRFRefusesCrossSiteStateChanges(t *testing.T) {
	s, _, id := csrfTestServer(t)
	path := "/api/vless-clients/" + id

	// What a page on another site can produce: a simple request, no preflight,
	// no body. Browsers attach the admin's Basic credentials to it.
	rec := csrfRequest(t, s, http.MethodDelete, path, map[string]string{
		"Origin": "https://evil.example",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("DELETE with a foreign Origin = %d, want 403: %s", rec.Code, rec.Body)
	}

	// Sec-Fetch-Site catches the same thing even when Origin is stripped.
	rec = csrfRequest(t, s, http.MethodDelete, path, map[string]string{
		"Sec-Fetch-Site": "cross-site",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("DELETE with Sec-Fetch-Site: cross-site = %d, want 403: %s", rec.Code, rec.Body)
	}

	// The user must still exist: the request was refused, not partly honoured.
	clients, err := s.store.ListVlessClients()
	if err != nil || len(clients) != 1 {
		t.Errorf("the refused request still deleted the client: %+v, %v", clients, err)
	}
}

func TestCSRFAllowsSameOriginAndNonBrowser(t *testing.T) {
	// What matters is that the request got past the CSRF layer and reached the
	// route, which may then refuse it for its own reasons -- REALITY being off
	// in this server, for one. Anything but 403 means the check let it by.
	cases := []struct {
		name    string
		headers map[string]string
	}{
		{"same origin, as the dashboard sends it", map[string]string{
			"Origin":         "https://admin.example.com",
			"Sec-Fetch-Site": "same-origin",
		}},
		{"no origin at all, as curl sends it", nil},
		{"same-site navigation", map[string]string{"Sec-Fetch-Site": "same-site"}},
		{"a direct link opened by hand", map[string]string{"Sec-Fetch-Site": "none"}},
	}

	for _, tc := range cases {
		server, _, id := csrfTestServer(t)
		rec := csrfRequest(t, server, http.MethodDelete, "/api/vless-clients/"+id, tc.headers)
		if rec.Code == http.StatusForbidden {
			t.Errorf("%s: refused as cross-site, want it to reach the route", tc.name)
		}
	}
}

func TestCSRFLeavesReadsAlone(t *testing.T) {
	s, _, _ := csrfTestServer(t)

	// A cross-site GET is harmless here and must not start failing: nothing on
	// this API changes state on a read.
	rec := csrfRequest(t, s, http.MethodGet, "/api/vless-clients", map[string]string{
		"Origin": "https://evil.example",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("cross-origin GET = %d, want 200: %s", rec.Code, rec.Body)
	}
	var listing struct {
		Clients []VlessClient `json:"clients"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listing); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(listing.Clients) != 1 {
		t.Errorf("clients = %d, want 1", len(listing.Clients))
	}
}

// The whole point of the change, exercised the way the attack would arrive: an
// admin's browser, carrying Basic credentials, hitting a mutating route that a
// page on another site caused.
func TestCSRFAttackCannotReachAStateChangingRoute(t *testing.T) {
	s, _, id := csrfTestServer(t)

	// What the browser sends for a cross-site form POST: no Origin suppressed,
	// no preflight, simple headers only.
	req := httptest.NewRequest(http.MethodPost, "/api/vless-clients/"+id+"/reset", nil)
	req.Host = "admin.example.com"
	req.RemoteAddr = "203.0.113.7:44444"
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Origin", "https://attacker.example")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	s.adminHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("a cross-site request reached the route: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "xray") {
		t.Error("the request was handled by the REALITY route instead of being refused")
	}
}
