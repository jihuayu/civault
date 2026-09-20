package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPKeyPutPreservesStdinAndOmitsValueFlag(t *testing.T) {
	t.Setenv("CIVAULT_ADMIN_TOKEN", "synthetic-management-token")
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != "POST" || r.URL.Path != "/v1/admin/workspaces/ws_default/keys" || r.Header.Get("Authorization") != "Bearer synthetic-management-token" || r.Header.Get("Idempotency-Key") == "" {
			t.Error("invalid HTTP request")
		}
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["value"] != "line 1\nline 2\n" {
			t.Error("stdin whitespace changed")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"id":"key_test","version_id":"ver_test"}`)
	}))
	defer server.Close()
	var out bytes.Buffer
	cmd := New(strings.NewReader("line 1\nline 2\n"), &out, io.Discard)
	cmd.SetArgs([]string{"--server", server.URL, "--workspace", "ws_default", "key", "put", "test/key", "--stdin"})
	if e := cmd.Execute(); e != nil {
		t.Fatal(e)
	}
	if !called || strings.Contains(out.String(), "line 1") {
		t.Fatal("CLI did not use HTTP or leaked its input")
	}
	cmd = New(strings.NewReader(""), io.Discard, io.Discard)
	cmd.SetArgs([]string{"key", "put", "test/key", "--value", "secret"})
	if cmd.Execute() == nil {
		t.Fatal("plaintext value flag should not exist")
	}
}
func TestClientRejectsRemoteHTTPAndRedirects(t *testing.T) {
	c := &client{config: config{Server: "http://remote.example.com"}, http: http.DefaultClient}
	if _, e := c.request("GET", "/v1/admin/keys", nil); e == nil {
		t.Fatal("accepted remote HTTP")
	}
}
