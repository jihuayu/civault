package vault

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func enableMail(f *fixture, expiryNotification bool) {
	s := f.settings()
	key := "synthetic-resend-key"
	up := SettingsUpdate{Settings: s.Settings, Revision: s.Revision, ResendKey: &key}
	up.ResendFrom = "CIVault <alerts@example.com>"
	up.ResendEnabled = true
	up.NotifyOnExpiry = expiryNotification
	f.admin("PUT", "/v1/admin/settings", up, 200)
}
func TestNotificationThresholdsDedupAndExpiryRevision(t *testing.T) {
	f := newFixture(t)
	now := time.Now().Truncate(time.Second)
	f.a.now = func() time.Time { return now }
	enableMail(f, true)
	expiry := now.Add(6 * 24 * time.Hour).Format(time.RFC3339)
	id, version := f.key("expiring/token", "must-not-be-in-email", &expiry)
	count := 0
	ids := map[string]bool{}
	f.a.client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		count++
		if r.URL.String() != "https://api.resend.com/emails" {
			t.Fatal("unexpected mail endpoint")
		}
		id := r.Header.Get("Idempotency-Key")
		if id == "" {
			t.Fatal("missing idempotency key")
		}
		ids[id] = true
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "must-not-be-in-email") {
			t.Fatal("email leaked key value")
		}
		return response(200, `{"id":"message-id"}`), nil
	})}
	for i := 0; i < 2; i++ {
		if e := f.a.ProcessNotifications(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	if count != 1 {
		t.Fatalf("duplicate notification: %d", count)
	}
	now = now.Add(3 * 24 * time.Hour)
	if e := f.a.ProcessNotifications(context.Background()); e != nil {
		t.Fatal(e)
	}
	if count != 2 {
		t.Fatal("3-day reminder missing")
	}
	f.admin("PATCH", "/v1/admin/workspaces/ws_default/keys/"+id+"/versions/"+version, map[string]any{"expires_at": now.Add(2 * time.Hour).Format(time.RFC3339)}, 200)
	if e := f.a.ProcessNotifications(context.Background()); e != nil {
		t.Fatal(e)
	}
	if count != 3 || len(ids) != 3 {
		t.Fatal("changed expiry did not receive a new event")
	}
	f.admin("PATCH", "/v1/admin/workspaces/ws_default/keys/"+id, map[string]bool{"disabled": true}, 200)
	now = now.Add(3 * time.Hour)
	if e := f.a.ProcessNotifications(context.Background()); e != nil {
		t.Fatal(e)
	}
	if count != 3 {
		t.Fatal("disabled key notified")
	}
}
func TestNotificationTimeoutRestartAndWindow(t *testing.T) {
	f := newFixture(t)
	now := time.Now().Truncate(time.Second)
	f.a.now = func() time.Time { return now }
	enableMail(f, false)
	expiry := now.Add(12 * time.Hour).Format(time.RFC3339)
	f.key("retry/token", "not-an-email-value", &expiry)
	calls := 0
	var firstID, firstBody string
	transport := transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		b, _ := io.ReadAll(r.Body)
		if calls == 1 {
			firstID = r.Header.Get("Idempotency-Key")
			firstBody = string(b)
		} else if r.Header.Get("Idempotency-Key") != firstID || string(b) != firstBody {
			t.Error("retry changed idempotency key or body")
		}
		return nil, errors.New("timeout after remote acceptance")
	})
	f.a.client = &http.Client{Transport: transport}
	if e := f.a.ProcessNotifications(context.Background()); e != nil {
		t.Fatal(e)
	}
	f.server.Close()
	f.a.Close()
	var e error
	f.a, e = Open(f.dir, f.master, nil, io.Discard)
	if e != nil {
		t.Fatal(e)
	}
	f.a.now = func() time.Time { return now }
	f.a.client = &http.Client{Transport: transport}
	now = now.Add(3 * time.Minute)
	if e = f.a.ProcessNotifications(context.Background()); e != nil {
		t.Fatal(e)
	}
	if calls != 2 {
		t.Fatal("persistent retry not resumed")
	}
	now = now.Add(24 * time.Hour)
	if e = f.a.ProcessNotifications(context.Background()); e != nil {
		t.Fatal(e)
	}
	if calls != 2 {
		t.Fatal("resent outside idempotency window")
	}
	var status string
	if e = f.a.db.QueryRow("SELECT status FROM notifications WHERE attempts>0").Scan(&status); e != nil || status != "needs_attention" {
		t.Fatalf("status=%s err=%v", status, e)
	}
}
func TestNotificationConfigurationChangePreservesUncertainty(t *testing.T) {
	f := newFixture(t)
	enableMail(f, true)
	expiry := time.Now().Add(time.Hour).Format(time.RFC3339)
	f.key("mail/token", "value", &expiry)
	f.a.client = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("timeout") })}
	if e := f.a.ProcessNotifications(context.Background()); e != nil {
		t.Fatal(e)
	}
	s := f.settings()
	up := SettingsUpdate{Settings: s.Settings, Revision: s.Revision}
	up.OwnerEmail = "updated@example.com"
	f.admin("PUT", "/v1/admin/settings", up, 200)
	var status string
	_ = f.a.db.QueryRow("SELECT status FROM notifications WHERE attempts=1").Scan(&status)
	if status != "needs_attention" {
		t.Fatal("uncertain message should not be automatically resent after settings change")
	}
}
func TestConsistentBackupRestore(t *testing.T) {
	f := newFixture(t)
	id, version := f.key("backup/key", "backup-roundtrip-value", nil)
	destination := filepath.Join(t.TempDir(), "snapshot.db")
	if e := f.a.Backup(context.Background(), destination); e != nil {
		t.Fatal(e)
	}
	restoreDir := t.TempDir()
	data, e := os.ReadFile(destination)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(restoreDir, "civault.db"), data, 0600); e != nil {
		t.Fatal(e)
	}
	restored, e := Open(restoreDir, f.master, nil, io.Discard)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	var encrypted []byte
	if e = restored.db.QueryRow("SELECT encrypted FROM key_versions WHERE id=?", version).Scan(&encrypted); e != nil {
		t.Fatal(e)
	}
	plain, e := restored.box.Open(encrypted, "key", "ws_default", id, version)
	if e != nil || string(plain) != "backup-roundtrip-value" {
		t.Fatal("backup failed to restore key")
	}
}
func TestThresholdCatchup(t *testing.T) {
	now := time.Now().Unix()
	for _, x := range []struct {
		remain int64
		want   int
		ok     bool
	}{{10 * 86400, 0, false}, {6 * 86400, 7, true}, {2 * 86400, 3, true}, {3600, 1, true}, {-3600, 0, true}} {
		got, ok := threshold(now+x.remain, now, []int{7, 3, 1}, true)
		if got != x.want || ok != x.ok {
			t.Fatal(x, got, ok)
		}
	}
}
