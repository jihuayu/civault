package vault

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestEmptyMutationCannotEnableOrClearExpiry(t *testing.T) {
	f := newFixture(t)
	expiry := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	id, version := f.key("guarded", "synthetic", &expiry)
	p := f.policy("guarded", Rule{KeyIDs: []string{id}, OwnerID: "10"})
	base := "/v1/admin/workspaces/ws_default"
	f.admin("PATCH", base+"/keys/"+id, map[string]bool{"disabled": true}, 200)
	for _, path := range []string{base + "/keys/" + id, base + "/policies/" + p, base + "/keys/" + id + "/versions/" + version} {
		for _, body := range []any{json.RawMessage(`null`), map[string]any{}, []any{}} {
			f.admin("PATCH", path, body, 400)
		}
	}
	var keys []Key
	_ = json.Unmarshal(f.admin("GET", base+"/keys", nil, 200), &keys)
	if !keys[0].Disabled || keys[0].ExpiresAt == nil {
		t.Fatal("empty mutation changed lifecycle")
	}
	for _, name := range []string{"__proto__", "Constructor", "prototype", "GITHUB_ENV", "PATH", strings.Repeat("A", 201)} {
		f.expect("POST", "/v1/runtime/github-actions/resolve", ResolveRequest{WorkspaceID: "ws_default", References: map[string]string{name: "cv://ws_default/guarded"}}, "", 400)
	}
}

func TestReplayPinsVersionButRespectsCurrentAndPinnedExpiry(t *testing.T) {
	f := newFixture(t)
	id, oldVersion := f.key("rotating", "old", nil)
	f.policy("allow", Rule{KeyIDs: []string{id}, OwnerID: "10"})
	signer, _ := f.signer()
	jwt := sign(t, signer, claims(time.Now()))
	endpoint := "/v1/runtime/github-actions/resolve"
	f.expect("POST", endpoint, refs("rotating"), jwt, 200)
	_, current := f.key("rotating", "new", nil)
	b := f.expect("POST", endpoint, refs("rotating"), jwt, 200)
	var resolved ResolveResponse
	_ = json.Unmarshal(b, &resolved)
	if resolved.Values["VALUE_0"] != "old" {
		t.Fatal("retry changed the selected version")
	}
	base := "/v1/admin/workspaces/ws_default/keys/" + id + "/versions/"
	past := time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	f.admin("PATCH", base+current, map[string]any{"expires_at": past}, 200)
	f.expect("POST", endpoint, refs("rotating"), jwt, 403)
	f.admin("PATCH", base+current, map[string]any{"expires_at": nil}, 200)
	f.admin("PATCH", base+oldVersion, map[string]any{"expires_at": past}, 200)
	f.expect("POST", endpoint, refs("rotating"), jwt, 403)
}

func TestNotificationCancelledInsideKeyMutation(t *testing.T) {
	f := newFixture(t)
	enableMail(f, true)
	expiry := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	id, _ := f.key("pending", "synthetic", &expiry)
	if e := f.a.scheduleNotifications(context.Background()); e != nil {
		t.Fatal(e)
	}
	f.admin("PATCH", "/v1/admin/workspaces/ws_default/keys/"+id, map[string]bool{"disabled": true}, 200)
	var pending int
	if e := f.a.db.QueryRow("SELECT count(*) FROM notifications WHERE status='pending'").Scan(&pending); e != nil || pending != 0 {
		t.Fatal("mutation left pending notifications")
	}
}

func TestSessionExpiryAndPasswordRevocation(t *testing.T) {
	f := newFixture(t)
	req, _ := http.NewRequest("POST", f.server.URL+"/v1/admin/password", strings.NewReader(`{"current_password":"correct-horse-battery","new_password":"replacement-password-2026"}`))
	req.AddCookie(f.cookie)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", f.csrf)
	r, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("password update failed")
	}
	f.expect("GET", "/v1/admin/workspaces", nil, f.token, 401)
	req, _ = http.NewRequest("GET", f.server.URL+"/v1/auth/me", nil)
	req.AddCookie(f.cookie)
	r, e = http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatal("password change retained the old session")
	}
	login, _ := f.request("POST", "/v1/auth/login", map[string]string{"email": "owner@example.com", "password": "replacement-password-2026"}, "")
	if login.StatusCode != 200 {
		t.Fatal("new password login failed")
	}
	if _, e := f.a.db.Exec("UPDATE sessions SET expires_at=0"); e != nil {
		t.Fatal(e)
	}
	req, _ = http.NewRequest("GET", f.server.URL+"/v1/auth/me", nil)
	for _, c := range login.Cookies() {
		req.AddCookie(c)
	}
	r, e = http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatal("expired session was accepted")
	}
}

func TestSensitiveConfigAADAndAuditOperations(t *testing.T) {
	f := newFixture(t)
	s := f.settings()
	secret := "synthetic-config-value"
	f.admin("PUT", "/v1/admin/settings", SettingsUpdate{Settings: s.Settings, Revision: s.Revision, GithubSecret: &secret}, 200)
	var blob []byte
	var revision string
	if e := f.a.db.QueryRow("SELECT github_secret,github_secret_revision FROM settings").Scan(&blob, &revision); e != nil {
		t.Fatal(e)
	}
	for _, aad := range [][]string{{"settings", "resend_key", revision}, {"settings", "github_secret", "999"}, {"key", "ws_default", "github_secret", revision}} {
		if _, e := f.a.box.Open(blob, aad...); e == nil {
			t.Fatal("configuration ciphertext accepted in a different context")
		}
	}
	audit := string(f.admin("GET", "/v1/admin/audit-events?event=settings.updated", nil, 200))
	if strings.Contains(audit, secret) || !strings.Contains(audit, `"github_secret":"replace"`) {
		t.Fatal("sensitive configuration audit invalid")
	}
}
