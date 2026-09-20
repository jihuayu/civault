package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *safeBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

type fixture struct {
	t                        *testing.T
	a                        *App
	server                   *httptest.Server
	token, master, dir, csrf string
	cookie                   *http.Cookie
	log                      *safeBuffer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, dir: t.TempDir(), master: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), log: new(safeBuffer)}
	var e error
	f.a, e = Open(f.dir, f.master, nil, f.log)
	if e != nil {
		t.Fatal(e)
	}
	f.server = httptest.NewServer(f.a.Handler())
	t.Cleanup(func() { f.server.Close(); f.a.Close() })
	code, e := os.ReadFile(filepath.Join(f.dir, "setup-token"))
	if e != nil {
		t.Fatal(e)
	}
	f.expect("POST", "/v1/setup", map[string]any{"code": string(code), "email": "owner@example.com", "password": "correct-horse-battery", "public_url": f.server.URL}, "", 201)
	raw, body := f.request("POST", "/v1/auth/login", map[string]string{"email": "owner@example.com", "password": "correct-horse-battery"}, "")
	if raw.StatusCode != 200 {
		t.Fatalf("login %s", body)
	}
	for _, c := range raw.Cookies() {
		if c.Name == "civault_session" {
			f.cookie = c
		}
	}
	var login map[string]string
	_ = json.Unmarshal(body, &login)
	f.csrf = login["csrf_token"]
	req, _ := http.NewRequest("POST", f.server.URL+"/v1/admin/tokens", strings.NewReader(`{"name":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", f.csrf)
	req.AddCookie(f.cookie)
	res, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	var tok map[string]any
	if e = json.NewDecoder(res.Body).Decode(&tok); e != nil {
		t.Fatal(e)
	}
	if res.StatusCode != 201 {
		t.Fatal(tok)
	}
	f.token = tok["token"].(string)
	return f
}
func (f *fixture) request(method, path string, body any, token string) (*http.Response, []byte) {
	f.t.Helper()
	var reader io.Reader
	if body != nil {
		reader = strings.NewReader(jsonText(body))
	}
	req, _ := http.NewRequest(method, f.server.URL+path, reader)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, e := http.DefaultClient.Do(req)
	if e != nil {
		f.t.Fatal(e)
	}
	b, e := io.ReadAll(res.Body)
	res.Body.Close()
	if e != nil {
		f.t.Fatal(e)
	}
	return res, b
}
func (f *fixture) expect(method, path string, body any, token string, status int) []byte {
	f.t.Helper()
	r, b := f.request(method, path, body, token)
	if r.StatusCode != status {
		f.t.Fatalf("%s %s: got %d want %d: %s", method, path, r.StatusCode, status, b)
	}
	return b
}
func (f *fixture) admin(method, path string, body any, status int) []byte {
	return f.expect(method, path, body, f.token, status)
}
func (f *fixture) key(path, value string, expiry *string) (string, string) {
	f.t.Helper()
	var result map[string]any
	_ = json.Unmarshal(f.admin("POST", "/v1/admin/workspaces/ws_default/keys", map[string]any{"path": path, "value": value, "expires_at": expiry}, 201), &result)
	return result["id"].(string), result["version_id"].(string)
}
func (f *fixture) tag(name string) string {
	var tag Tag
	_ = json.Unmarshal(f.admin("POST", "/v1/admin/workspaces/ws_default/tags", map[string]string{"name": name}, 200), &tag)
	return tag.ID
}
func (f *fixture) policy(name string, rule Rule) string {
	var v map[string]any
	_ = json.Unmarshal(f.admin("POST", "/v1/admin/workspaces/ws_default/policies", PolicyInput{Name: name, Rule: rule}, 201), &v)
	return v["id"].(string)
}
func (f *fixture) settings() SettingsView {
	var s SettingsView
	_ = json.Unmarshal(f.admin("GET", "/v1/admin/settings", nil, 200), &s)
	return s
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}
func (f *fixture) signer() (*rsa.PrivateKey, *atomic.Int64) {
	f.t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		f.t.Fatal(e)
	}
	calls := new(atomic.Int64)
	f.a.oidc.client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != githubJWKS {
			f.t.Errorf("unexpected JWKS destination %s", r.URL)
		}
		calls.Add(1)
		return response(200, jsonText(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})), nil
	})}
	return key, calls
}
func claims(now time.Time) githubClaims {
	return githubClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: githubIssuer, Subject: "repo:acme/repo:ref:refs/heads/main", Audience: jwt.ClaimStrings{"urn:civault:workspace:ws_default"}, ID: randomToken(), IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now.Add(-time.Second)), ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute))}, OwnerID: "10", RepositoryID: "20", Repository: "acme/repo", Ref: "refs/heads/main", Event: "push", Runner: "github-hosted", WorkflowRef: "acme/repo/.github/workflows/publish.yml@refs/heads/main", WorkflowSHA: strings.Repeat("a", 40), RunID: "100", RunAttempt: "1"}
}
func sign(t *testing.T, key *rsa.PrivateKey, c githubClaims) string {
	t.Helper()
	v := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	v.Header["kid"] = "test-key"
	v.Header["jku"] = "https://attacker.invalid/keys"
	raw, e := v.SignedString(key)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func refs(paths ...string) ResolveRequest {
	r := ResolveRequest{WorkspaceID: "ws_default", References: map[string]string{}}
	for i, path := range paths {
		r.References[fmt.Sprintf("VALUE_%d", i)] = "cv://ws_default/" + path
	}
	return r
}

func TestSetupSettingsAndKeyPersistence(t *testing.T) {
	f := newFixture(t)
	if _, e := os.Stat(filepath.Join(f.dir, "setup-token")); !os.IsNotExist(e) {
		t.Fatal("setup code not removed")
	}
	f.expect("POST", "/v1/setup", map[string]any{}, "", 409)
	s := f.settings()
	gh, re := "synthetic-github-client-secret", "synthetic-resend-api-key"
	update := SettingsUpdate{Settings: s.Settings, Revision: s.Revision, GithubSecret: &gh, ResendKey: &re}
	update.GithubClientID = "test-client"
	update.GithubEnabled = true
	update.ResendEnabled = true
	update.ResendFrom = "alerts@example.com"
	b := f.admin("PUT", "/v1/admin/settings", update, 200)
	if bytes.Contains(b, []byte(gh)) || bytes.Contains(b, []byte(re)) {
		t.Fatal("secret returned in settings")
	}
	f.admin("PUT", "/v1/admin/settings", update, 409)
	s = f.settings()
	f.admin("PUT", "/v1/admin/settings", SettingsUpdate{Settings: s.Settings, Revision: s.Revision}, 200)
	got, e := f.a.configSecret(context.Background(), f.a.db, "github_secret")
	if e != nil || got != gh {
		t.Fatal("omitted secret was not preserved")
	}
	s = f.settings()
	empty := ""
	f.admin("PUT", "/v1/admin/settings", SettingsUpdate{Settings: s.Settings, Revision: s.Revision, GithubSecret: &empty}, 400)
	id, version := f.key("shared/token", "synthetic-plaintext-never-on-disk", nil)
	var encrypted []byte
	_ = f.a.db.QueryRow("SELECT encrypted FROM key_versions WHERE id=?", version).Scan(&encrypted)
	if _, e = f.a.box.Open(encrypted, "key", "ws_other", id, version); e == nil {
		t.Fatal("cross workspace decryption succeeded")
	}
	if _, e = f.a.db.Exec("UPDATE key_versions SET encrypted=? WHERE id=?", []byte("changed"), version); e == nil {
		t.Fatal("immutable encrypted record was editable")
	}
	for _, name := range []string{"civault.db", "civault.db-wal"} {
		b, _ := os.ReadFile(filepath.Join(f.dir, name))
		for _, secret := range []string{gh, re, "synthetic-plaintext-never-on-disk"} {
			if bytes.Contains(b, []byte(secret)) {
				t.Fatalf("plaintext in %s", name)
			}
		}
	}
	if strings.Contains(f.log.String(), gh) || strings.Contains(f.log.String(), "synthetic-plaintext-never-on-disk") {
		t.Fatal("secret in logs")
	}
	other, e := Open(f.dir, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), nil, io.Discard)
	if e == nil {
		other.Close()
		t.Fatal("wrong master key accepted")
	}
	s = f.settings()
	update = SettingsUpdate{Settings: s.Settings, Revision: s.Revision, ClearGithubSecret: true}
	update.GithubEnabled = false
	f.admin("PUT", "/v1/admin/settings", update, 200)
	if f.settings().GithubSecretConfigured {
		t.Fatal("explicit clear did not remove secret")
	}
	f.server.Close()
	f.a.Close()
	reopened, e := Open(f.dir, f.master, nil, io.Discard)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if !reopened.initialized(context.Background()) {
		t.Fatal("initialization lost across restart")
	}
	plain, e := reopened.box.Open(encrypted, "key", "ws_default", id, version)
	if e != nil || string(plain) != "synthetic-plaintext-never-on-disk" {
		t.Fatal("cannot decrypt after restart", e)
	}
}
func TestOIDCTagORAtomicResolveAndRevocation(t *testing.T) {
	f := newFixture(t)
	key, calls := f.signer()
	id, _ := f.key("npm/token", "test-secret-npm", nil)
	other, _ := f.key("docker/token", "test-secret-docker", nil)
	prod, npm := f.tag("production"), f.tag("npm")
	f.admin("PUT", "/v1/admin/workspaces/ws_default/keys/"+id+"/tags", map[string]any{"tag_ids": []string{npm}}, 200)
	rule := Rule{TagIDs: []string{prod, npm}, OwnerID: "10", RepositoryID: "20", WorkflowPath: ".github/workflows/publish.yml", Refs: []string{"refs/heads/main"}, Events: []string{"push"}, Runners: []string{"github-hosted"}}
	pid := f.policy("publish", rule)
	raw := sign(t, key, claims(time.Now()))
	b := f.expect("POST", "/v1/runtime/github-actions/resolve", refs("npm/token"), raw, 200)
	if !bytes.Contains(b, []byte("test-secret-npm")) {
		t.Fatal("tag OR rule did not allow key")
	}
	f.admin("PATCH", "/v1/admin/workspaces/ws_default/tags/"+npm, map[string]string{"name": "npm-renamed"}, 200)
	f.expect("POST", "/v1/runtime/github-actions/resolve", refs("npm/token"), raw, 200)
	b = f.expect("POST", "/v1/runtime/github-actions/resolve", refs("npm/token", "docker/token"), sign(t, key, claims(time.Now())), 403)
	if bytes.Contains(b, []byte("test-secret-npm")) {
		t.Fatal("partial secret response")
	}
	f.admin("PUT", "/v1/admin/workspaces/ws_default/keys/"+id+"/tags", map[string]any{"tag_ids": []string{}}, 200)
	f.expect("POST", "/v1/runtime/github-actions/resolve", refs("npm/token"), raw, 403)
	f.policy("direct", Rule{KeyIDs: []string{id, other}, OwnerID: "10"})
	f.expect("POST", "/v1/runtime/github-actions/resolve", refs("npm/token", "docker/token"), sign(t, key, claims(time.Now())), 200)
	f.admin("PATCH", "/v1/admin/workspaces/ws_default/policies/"+pid, map[string]bool{"disabled": true}, 200)
	f.admin("PATCH", "/v1/admin/workspaces/ws_default/keys/"+id, map[string]bool{"disabled": true}, 200)
	f.expect("POST", "/v1/runtime/github-actions/resolve", refs("npm/token"), sign(t, key, claims(time.Now())), 403)
	f.admin("DELETE", "/v1/admin/workspaces/ws_default/tags/"+prod, nil, 409)
	if calls.Load() != 1 {
		t.Fatalf("expected JWKS cache reuse, got %d requests", calls.Load())
	}
}
func TestOIDCClaimsAndReplayConcurrency(t *testing.T) {
	f := newFixture(t)
	key, _ := f.signer()
	id, _ := f.key("token", "replay-test-secret", nil)
	f.policy("direct", Rule{KeyIDs: []string{id}, OwnerID: "10", RepositoryID: "20", WorkflowPath: ".github/workflows/publish.yml", WorkflowSHA: strings.Repeat("a", 40), Runners: []string{"github-hosted"}, Environments: []string{"production"}, Refs: []string{"refs/heads/main"}, Events: []string{"push"}})
	base := claims(time.Now())
	base.Environment = "production"
	for _, test := range []struct {
		name   string
		mutate func(*githubClaims)
		status int
	}{
		{"runner", func(c *githubClaims) { c.Runner = "self-hosted" }, 403},
		{"workflow_sha", func(c *githubClaims) { c.WorkflowSHA = strings.Repeat("b", 40) }, 403},
		{"issuer", func(c *githubClaims) { c.Issuer = "https://wrong.invalid" }, 401}, {"audience", func(c *githubClaims) { c.Audience = jwt.ClaimStrings{"wrong"} }, 401}, {"expired", func(c *githubClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute)) }, 401}, {"iat", func(c *githubClaims) { c.IssuedAt = nil }, 401}, {"nbf", func(c *githubClaims) { c.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Minute)) }, 401}, {"repository", func(c *githubClaims) { c.RepositoryID = "21" }, 403}, {"owner", func(c *githubClaims) { c.OwnerID = "11" }, 403}, {"environment", func(c *githubClaims) { c.Environment = "" }, 403}, {"workflow", func(c *githubClaims) { c.WorkflowRef = "acme/repo/.github/workflows/other.yml@refs/heads/main" }, 403}, {"ref", func(c *githubClaims) { c.Ref = "refs/heads/dev" }, 403}, {"event", func(c *githubClaims) { c.Event = "pull_request" }, 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := base
			c.ID = randomToken()
			test.mutate(&c)
			f.expect("POST", "/v1/runtime/github-actions/resolve", refs("token"), sign(t, key, c), test.status)
		})
	}
	raw := sign(t, key, base)
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, b := f.request("POST", "/v1/runtime/github-actions/resolve", refs("token"), raw)
			if r.StatusCode == 200 {
				allowed.Add(1)
			} else if r.StatusCode != 409 {
				t.Errorf("unexpected concurrent status %d %s", r.StatusCode, b)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != 3 {
		t.Fatalf("allowed %d replays", allowed.Load())
	}
	f.expect("POST", "/v1/runtime/github-actions/resolve", ResolveRequest{WorkspaceID: "ws_default", References: map[string]string{"PATH": "cv://ws_default/token"}}, raw, 400)
	if strings.Contains(f.log.String(), raw) || strings.Contains(f.log.String(), "replay-test-secret") {
		t.Fatal("sensitive logging")
	}
}
func TestExpiryCrossWorkspaceAndAuditFailure(t *testing.T) {
	f := newFixture(t)
	signing, _ := f.signer()
	id, version := f.key("token", "never-partially-return-me", nil)
	f.policy("read", Rule{KeyIDs: []string{id}, OwnerID: "10"})
	f.admin("POST", "/v1/admin/workspaces", map[string]string{"name": "other"}, 201)
	f.admin("POST", "/v1/admin/workspaces/ws_missing/policies", PolicyInput{Name: "cross", Rule: Rule{KeyIDs: []string{id}, OwnerID: "10"}}, 400)
	raw := sign(t, signing, claims(time.Now()))
	f.expect("POST", "/v1/runtime/github-actions/resolve", refs("token"), raw, 200)
	f.admin("PATCH", "/v1/admin/workspaces/ws_default/keys/"+id+"/versions/"+version, map[string]any{"expires_at": time.Now().Add(-time.Second).UTC().Format(time.RFC3339)}, 200)
	f.expect("POST", "/v1/runtime/github-actions/resolve", refs("token"), raw, 403)
	f.admin("PATCH", "/v1/admin/workspaces/ws_default/keys/"+id+"/versions/"+version, map[string]any{"expires_at": nil}, 200)
	_, e := f.a.db.Exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;")
	if e != nil {
		t.Fatal(e)
	}
	r, b := f.request("POST", "/v1/runtime/github-actions/resolve", refs("token"), sign(t, signing, claims(time.Now())))
	if r.StatusCode == 200 || bytes.Contains(b, []byte("never-partially-return-me")) {
		t.Fatal("secret returned without durable audit")
	}
}
func TestCookieCSRFAndTokenRevocation(t *testing.T) {
	f := newFixture(t)
	req, _ := http.NewRequest("POST", f.server.URL+"/v1/admin/workspaces", strings.NewReader(`{"name":"csrf"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(f.cookie)
	res, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("cookie mutation did not require CSRF")
	}
	var tokens []struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(f.admin("GET", "/v1/admin/tokens", nil, 200), &tokens)
	f.admin("DELETE", "/v1/admin/tokens/"+tokens[0].ID, nil, 200)
	f.admin("GET", "/v1/admin/settings", nil, 401)
}
func TestWriteIdempotency(t *testing.T) {
	f := newFixture(t)
	send := func(value string) (int, []byte) {
		req, _ := http.NewRequest("POST", f.server.URL+"/v1/admin/workspaces/ws_default/keys", strings.NewReader(jsonText(map[string]string{"path": "idem/token", "value": value})))
		req.Header.Set("Authorization", "Bearer "+f.token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "same-request")
		res, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res.StatusCode, b
	}
	s1, b1 := send("first-value")
	s2, b2 := send("first-value")
	if s1 != 201 || s2 != 201 || string(b1) != string(b2) {
		t.Fatalf("idempotency failed %d %d", s1, s2)
	}
	s3, _ := send("different-value")
	if s3 != 409 {
		t.Fatal("different idempotent body accepted")
	}
	var n int
	_ = f.a.db.QueryRow("SELECT count(*) FROM key_versions").Scan(&n)
	if n != 1 {
		t.Fatal("duplicate version created")
	}
}
func TestOAuthVerifiedEmailBindingAndPKCE(t *testing.T) {
	f := newFixture(t)
	s := f.settings()
	secret := "oauth-config-secret"
	up := SettingsUpdate{Settings: s.Settings, Revision: s.Revision, GithubSecret: &secret}
	up.GithubEnabled = true
	up.GithubClientID = "client"
	f.admin("PUT", "/v1/admin/settings", up, 200)
	verified := false
	userID := 42
	var tokenRequests int
	f.a.client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Host + r.URL.Path {
		case "github.com/login/oauth/access_token":
			_ = r.ParseForm()
			if r.Form.Get("code_verifier") == "" || r.Form.Get("client_secret") != secret {
				t.Error("missing PKCE or client secret")
			}
			tokenRequests++
			return response(200, `{"access_token":"synthetic-github-token"}`), nil
		case "api.github.com/user":
			return response(200, fmt.Sprintf(`{"id":%d}`, userID)), nil
		case "api.github.com/user/emails":
			return response(200, fmt.Sprintf(`[{"email":"owner@example.com","verified":%v}]`, verified)), nil
		default:
			t.Errorf("unexpected request %s", r.URL)
			return response(500, `{}`), nil
		}
	})}
	flow := func() (string, *http.Cookie) {
		req, _ := http.NewRequest("GET", f.server.URL+"/v1/auth/github", nil)
		c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, e := c.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		u, _ := url.Parse(res.Header.Get("Location"))
		if u.Query().Get("code_challenge_method") != "S256" {
			t.Fatal("PKCE not configured")
		}
		return u.Query().Get("state"), res.Cookies()[0]
	}
	callback := func(state string, cookie *http.Cookie) int {
		req, _ := http.NewRequest("GET", f.server.URL+"/v1/auth/github/callback?state="+state+"&code=test-code", nil)
		req.AddCookie(cookie)
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		return res.StatusCode
	}
	state, cookie := flow()
	if callback(state, cookie) != 403 {
		t.Fatal("unverified email authorized")
	}
	verified = true
	state, cookie = flow()
	if callback(state, cookie) != 303 {
		t.Fatal("verified owner failed")
	}
	if f.settings().GithubID != "42" {
		t.Fatal("owner ID not bound")
	}
	if callback(state, cookie) != 403 {
		t.Fatal("OAuth replay accepted")
	}
	s = f.settings()
	up = SettingsUpdate{Settings: s.Settings, Revision: s.Revision}
	up.OwnerEmail = "changed-owner@example.com"
	f.admin("PUT", "/v1/admin/settings", up, 200)
	verified = false
	state, cookie = flow()
	if callback(state, cookie) != 303 || f.settings().GithubID != "42" {
		t.Fatal("email update unexpectedly changed the bound GitHub identity")
	}
	userID = 43
	state, cookie = flow()
	if callback(state, cookie) != 403 {
		t.Fatal("different GitHub ID accepted")
	}
	if tokenRequests != 4 {
		t.Fatalf("unexpected token exchanges %d", tokenRequests)
	}
}
