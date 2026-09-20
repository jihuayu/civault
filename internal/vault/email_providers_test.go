package vault

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func enableAgentMail(f *fixture) {
	s := f.settings()
	key := "synthetic-agentmail-key"
	up := SettingsUpdate{Settings: s.Settings, Revision: s.Revision, AgentMailKey: &key}
	up.EmailProvider = "agentmail"
	up.AgentMailInboxID = "alerts@agentmail.to"
	up.ResendEnabled = true
	f.admin("PUT", "/v1/admin/settings", up, 200)
}

func TestAgentMailSendingAndProviderSwitch(t *testing.T) {
	f := newFixture(t)
	enableMail(f, true)
	expiry := time.Now().Add(time.Hour).Format(time.RFC3339)
	f.key("mail/provider", "never-in-email", &expiry)
	if e := f.a.scheduleNotifications(context.Background()); e != nil {
		t.Fatal(e)
	}
	enableAgentMail(f)
	calls := 0
	f.a.client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "api.agentmail.to" || r.URL.Path != "/v0/inboxes/alerts@agentmail.to/messages/send" || r.Method != "POST" {
			t.Fatalf("unexpected endpoint: %s", r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer synthetic-agentmail-key" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatal("incorrect headers")
		}
		if id := r.Header.Get("Idempotency-Key"); !strings.HasPrefix(id, "civault-") || strings.Contains(id, "/") {
			t.Fatal("invalid AgentMail idempotency key")
		}
		var body map[string]any
		if e := json.NewDecoder(r.Body).Decode(&body); e != nil {
			t.Fatal(e)
		}
		if _, ok := body["from"]; ok {
			t.Fatal("AgentMail sender belongs in URL")
		}
		if jsonText(body["to"]) != `["owner@example.com"]` || body["subject"] == "" || strings.Contains(jsonText(body), "never-in-email") {
			t.Fatal("incorrect email payload")
		}
		return response(200, `{"message_id":"agentmail-message","thread_id":"thread"}`), nil
	})}
	for range 2 {
		if e := f.a.ProcessNotifications(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	if calls != 1 {
		t.Fatalf("duplicate/missing notification: %d", calls)
	}
	var status, providerID string
	if e := f.a.db.QueryRow("SELECT status,provider_id FROM notifications").Scan(&status, &providerID); e != nil || status != "sent" || providerID != "agentmail-message" {
		t.Fatalf("%s %s %v", status, providerID, e)
	}
	f.admin("POST", "/v1/admin/notifications/test", map[string]any{}, 200)
	if calls != 2 {
		t.Fatal("test email did not use AgentMail")
	}
	s := f.settings()
	up := SettingsUpdate{Settings: s.Settings, Revision: s.Revision}
	up.EmailProvider = "resend"
	f.admin("PUT", "/v1/admin/settings", up, 200)
	f.a.client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.resend.com" || r.Header.Get("Authorization") != "Bearer synthetic-resend-key" {
			t.Fatal("original Resend credential not preserved")
		}
		return response(200, `{"id":"resend-message"}`), nil
	})}
	f.admin("POST", "/v1/admin/notifications/test", map[string]any{}, 200)
}

func TestAgentMailSettingsSecretsAndValidation(t *testing.T) {
	f := newFixture(t)
	s := f.settings()
	up := SettingsUpdate{Settings: s.Settings, Revision: s.Revision}
	up.EmailProvider = "unknown"
	f.admin("PUT", "/v1/admin/settings", up, 400)
	up.EmailProvider = "agentmail"
	up.ResendEnabled = true
	f.admin("PUT", "/v1/admin/settings", up, 400)
	key := "synthetic-agentmail-key"
	up.AgentMailKey = &key
	f.admin("PUT", "/v1/admin/settings", up, 400)
	up.AgentMailInboxID = "../inboxes"
	f.admin("PUT", "/v1/admin/settings", up, 400)
	up.AgentMailInboxID = "alerts@agentmail.to"
	up.ClearAgentMailKey = true
	f.admin("PUT", "/v1/admin/settings", up, 400)
	up.ClearAgentMailKey = false
	raw := f.admin("PUT", "/v1/admin/settings", up, 200)
	if strings.Contains(string(raw), key) || !f.settings().AgentMailKeyConfigured {
		t.Fatal("secret leaked or not configured")
	}
	var encrypted []byte
	if e := f.a.db.QueryRow("SELECT agentmail_key FROM settings").Scan(&encrypted); e != nil || strings.Contains(string(encrypted), key) {
		t.Fatal("credential not encrypted", e)
	}
	secret, e := f.a.configSecret(context.Background(), f.a.db, "agentmail_key")
	if e != nil || secret != key {
		t.Fatal("credential decryption failed", e)
	}
	audit := f.admin("GET", "/v1/admin/audit-events?event=settings.updated", nil, 200)
	if strings.Contains(string(audit), key) || !strings.Contains(string(audit), "agentmail_key") {
		t.Fatal("incorrect secret audit")
	}
	s = f.settings()
	up = SettingsUpdate{Settings: s.Settings, Revision: s.Revision, ClearAgentMailKey: true}
	f.admin("PUT", "/v1/admin/settings", up, 400)
	up.ResendEnabled = false
	f.admin("PUT", "/v1/admin/settings", up, 200)
	if f.settings().AgentMailKeyConfigured {
		t.Fatal("clear did not remove key")
	}
}

func TestAgentMailRetryAndSwitchUncertainty(t *testing.T) {
	f := newFixture(t)
	now := time.Now().Truncate(time.Second)
	f.a.now = func() time.Time { return now }
	enableMail(f, true)
	enableAgentMail(f)
	expiry := now.Add(time.Hour).Format(time.RFC3339)
	f.key("retry/provider", "secret", &expiry)
	calls := 0
	var firstBody, firstID string
	f.a.client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		body, _ := io.ReadAll(r.Body)
		if calls == 1 {
			firstBody = string(body)
			firstID = r.Header.Get("Idempotency-Key")
		} else if string(body) != firstBody || r.Header.Get("Idempotency-Key") != firstID {
			t.Fatal("retry changed request")
		}
		return nil, errors.New("timeout after acceptance")
	})}
	for range 2 {
		if e := f.a.ProcessNotifications(context.Background()); e != nil {
			t.Fatal(e)
		}
		now = now.Add(5 * time.Minute)
	}
	if calls != 2 {
		t.Fatal("missing retry")
	}
	s := f.settings()
	up := SettingsUpdate{Settings: s.Settings, Revision: s.Revision}
	up.EmailProvider = "resend"
	f.admin("PUT", "/v1/admin/settings", up, 200)
	if e := f.a.ProcessNotifications(context.Background()); e != nil {
		t.Fatal(e)
	}
	var status string
	if e := f.a.db.QueryRow("SELECT status FROM notifications").Scan(&status); e != nil || status != "needs_attention" || calls != 2 {
		t.Fatalf("unsafe provider switch: %s %d %v", status, calls, e)
	}
}

func TestAgentMailResponseHandling(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		retry  bool
		id     string
	}{
		{200, `{"message_id":"sent"}`, false, "sent"},
		{200, `{"id":"wrong-field"}`, true, ""},
		{200, `invalid`, true, ""},
		{401, `{}`, false, ""},
		{409, `{"code":"conflict"}`, true, ""},
		{429, `{}`, true, ""},
		{503, `{}`, true, ""},
	} {
		a := &App{now: time.Now, client: &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
			r := response(tc.status, tc.body)
			r.Header.Set("Retry-After", "120")
			return r, nil
		})}}
		got := a.sendEmail(context.Background(), "agentmail", "key", jsonText(emailPayload{From: "alerts@agentmail.to", To: []string{"owner@example.com"}, Subject: "test", Text: "text"}), "test")
		if got.Retry != tc.retry || got.ID != tc.id {
			t.Fatalf("%+v: %+v", tc, got)
		}
		if tc.status >= 400 && got.Delay != 2*time.Minute {
			t.Fatal("Retry-After ignored")
		}
	}
}

func TestEmailProviderMigrationFromV1(t *testing.T) {
	f := newFixture(t)
	enableMail(f, true)
	// Restore the original schema and a settings JSON without provider fields.
	if _, e := f.a.db.Exec(`ALTER TABLE settings DROP COLUMN agentmail_key; ALTER TABLE settings DROP COLUMN agentmail_key_revision; DELETE FROM schema_migrations WHERE version=2; UPDATE settings SET data=json_remove(data,'$.email_provider','$.agentmail_inbox_id');`); e != nil {
		t.Fatal(e)
	}
	f.server.Close()
	if e := f.a.Close(); e != nil {
		t.Fatal(e)
	}
	var e error
	f.a, e = Open(f.dir, f.master, nil, io.Discard)
	if e != nil {
		t.Fatal(e)
	}
	s, e := f.a.settings(context.Background(), f.a.db)
	if e != nil || s.EmailProvider != "resend" || !s.ResendEnabled || !s.ResendKeyConfigured || s.AgentMailKeyConfigured {
		t.Fatalf("legacy settings lost: %+v %v", s, e)
	}
	key, e := f.a.configSecret(context.Background(), f.a.db, "resend_key")
	if e != nil || key != "synthetic-resend-key" {
		t.Fatal("legacy key lost", e)
	}
	if e = f.a.Close(); e != nil {
		t.Fatal(e)
	}
	f.a, e = Open(f.dir, f.master, nil, io.Discard)
	if e != nil {
		t.Fatal("migration not restart safe", e)
	}
}
