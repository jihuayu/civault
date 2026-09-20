package vault

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

func (a *App) auditEvents(w http.ResponseWriter, r *http.Request) error {
	q := "SELECT id,created_at,request_id,actor,event,decision,workspace_id,details FROM audit_events WHERE 1=1"
	args := []any{}
	for _, x := range []struct{ param, column string }{{"workspace_id", "workspace_id"}, {"decision", "decision"}, {"event", "event"}, {"request_id", "request_id"}} {
		if v := r.URL.Query().Get(x.param); v != "" {
			q += " AND " + x.column + "=?"
			args = append(args, v)
		}
	}
	if v := r.URL.Query().Get("repository_id"); v != "" {
		q += " AND json_extract(details,'$.repository_id')=?"
		args = append(args, v)
	}
	for _, x := range []struct{ param, op string }{{"from", ">="}, {"to", "<="}} {
		if v := r.URL.Query().Get(x.param); v != "" {
			t, e := time.Parse(time.RFC3339, v)
			if e != nil {
				return bad("time filters must use RFC3339")
			}
			q += " AND created_at" + x.op + "?"
			args = append(args, t.Unix())
		}
	}
	q += " ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?"
	args = append(args, intParam(r, "limit", 100, 1000), intParam(r, "offset", 0, 1000000))
	return a.listJSON(w, r, q, args)
}
func (a *App) notifications(w http.ResponseWriter, r *http.Request) error {
	query := "SELECT n.id,n.version_id,n.expiry_revision,k.workspace_id,k.path,n.threshold,n.status,n.attempts,n.created_at,n.sent_at,n.provider_id,n.last_error FROM notifications n JOIN key_versions v ON v.id=n.version_id JOIN keys k ON k.id=v.key_id WHERE 1=1"
	args := []any{}
	if status := r.URL.Query().Get("status"); status != "" {
		query += " AND n.status=?"
		args = append(args, status)
	}
	query += " ORDER BY n.created_at DESC,n.id DESC LIMIT ? OFFSET ?"
	args = append(args, intParam(r, "limit", 100, 1000), intParam(r, "offset", 0, 1000000))
	return a.listJSON(w, r, query, args)
}

type emailPayload struct {
	From    string   `json:"from,omitempty"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Text    string   `json:"text"`
}
type expiringKey struct {
	Version, Path, Workspace string
	Expiry                   int64
	Revision                 int
}

func threshold(expiry, now int64, days []int, onExpiry bool) (int, bool) {
	if expiry <= now {
		return 0, onExpiry
	}
	ordered := slices.Clone(days)
	slices.Sort(ordered)
	for _, d := range ordered {
		if expiry-now <= int64(d)*86400 {
			return d, true
		}
	}
	return 0, false
}
func cancelStaleNotifications(ctx context.Context, q queryer) error {
	_, e := q.ExecContext(ctx, `UPDATE notifications SET status='cancelled',last_error='key_changed' WHERE status IN ('pending','retry','sending') AND NOT EXISTS(SELECT 1 FROM key_versions v JOIN keys k ON k.active_version_id=v.id WHERE v.id=notifications.version_id AND v.expiry_revision=notifications.expiry_revision AND k.disabled=0 AND k.deleted=0 AND v.expires_at IS NOT NULL)`)
	return e
}

func (a *App) scheduleNotifications(ctx context.Context) error {
	return a.transaction(ctx, func(tx *sql.Tx) error {
		s, e := a.settings(ctx, tx)
		if e != nil {
			return e
		}
		now := a.now().Unix()
		if e = cancelStaleNotifications(ctx, tx); e != nil {
			return e
		}
		if !s.ResendEnabled {
			return nil
		}
		rows, e := tx.QueryContext(ctx, "SELECT v.id,k.path,k.workspace_id,v.expires_at,v.expiry_revision FROM keys k JOIN key_versions v ON v.id=k.active_version_id WHERE k.disabled=0 AND k.deleted=0 AND v.expires_at IS NOT NULL")
		if e != nil {
			return e
		}
		items := []expiringKey{}
		for rows.Next() {
			var item expiringKey
			if e = rows.Scan(&item.Version, &item.Path, &item.Workspace, &item.Expiry, &item.Revision); e != nil {
				rows.Close()
				return e
			}
			items = append(items, item)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for _, item := range items {
			due, ok := threshold(item.Expiry, now, s.ReminderDays, s.NotifyOnExpiry)
			if !ok {
				continue
			}
			if _, e = tx.ExecContext(ctx, "UPDATE notifications SET status='cancelled',last_error='superseded_threshold' WHERE version_id=? AND expiry_revision=? AND threshold<>? AND attempts=0 AND status='pending'", item.Version, item.Revision, due); e != nil {
				return e
			}
			subject := "[CIVault] Key 即将到期：" + item.Path
			if due == 0 {
				subject = "[CIVault] Key 已到期：" + item.Path
			}
			payload := emailPayload{From: s.emailSender(), To: []string{s.OwnerEmail}, Subject: subject, Text: fmt.Sprintf("Key: %s\nWorkspace: %s\nVersion: %s\nExpires at: %s\n\n管理密钥：%s/#keys\n\n请更新第三方凭证，并创建新的 Key 版本。此邮件不包含凭证值。", item.Path, item.Workspace, item.Version, time.Unix(item.Expiry, 0).UTC().Format(time.RFC3339), s.PublicURL)}
			_, e = tx.ExecContext(ctx, `INSERT INTO notifications(id,version_id,expiry_revision,threshold,settings_revision,status,payload,next_attempt_at,created_at) VALUES(?,?,?,?,?,'pending',?,?,?) ON CONFLICT(version_id,expiry_revision,threshold) DO UPDATE SET status='pending',payload=excluded.payload,settings_revision=excluded.settings_revision,next_attempt_at=excluded.next_attempt_at,last_error='' WHERE notifications.status='cancelled' AND notifications.attempts=0`, newID("mail"), item.Version, item.Revision, due, s.Revision, jsonText(payload), now, now)
			if e != nil {
				return e
			}
		}
		return nil
	})
}

type sendResult struct {
	ID    string
	Code  string
	Retry bool
	Delay time.Duration
}

func (a *App) sendEmail(ctx context.Context, provider, key, payload, id string) sendResult {
	endpoint := "https://api.resend.com/emails"
	idempotencyKey := "civault/" + id
	switch provider {
	case "resend":
	case "agentmail":
		var body emailPayload
		if json.Unmarshal([]byte(payload), &body) != nil || body.From == "" {
			return sendResult{Code: "invalid_request"}
		}
		endpoint = "https://api.agentmail.to/v0/inboxes/" + url.PathEscape(body.From) + "/messages/send"
		body.From = ""
		payload = jsonText(body)
		idempotencyKey = "civault-" + id
	default:
		return sendResult{Code: "invalid_provider"}
	}
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(payload))
	if e != nil {
		return sendResult{Code: "invalid_request"}
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", idempotencyKey)
	resp, e := a.client.Do(req)
	if e != nil {
		return sendResult{Code: "network_error", Retry: true}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var body struct {
			ID        string `json:"id"`
			MessageID string `json:"message_id"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&body) != nil {
			return sendResult{Code: "invalid_response", Retry: true}
		}
		if provider == "agentmail" {
			body.ID = body.MessageID
		}
		if body.ID == "" {
			return sendResult{Code: "invalid_response", Retry: true}
		}
		return sendResult{ID: body.ID}
	}
	result := sendResult{Code: fmt.Sprintf("http_%d", resp.StatusCode), Retry: resp.StatusCode == 429 || resp.StatusCode >= 500}
	if resp.StatusCode == 409 {
		var b struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&b)
		result.Retry = provider == "agentmail" || b.Name == "concurrent_idempotent_requests"
	}
	if seconds, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil && seconds > 0 {
		result.Delay = time.Duration(seconds) * time.Second
	} else if t, e := http.ParseTime(resp.Header.Get("Retry-After")); e == nil {
		result.Delay = t.Sub(a.now())
	}
	return result
}

// ProcessNotifications is also used by deterministic integration tests with a mock HTTP transport.
func (a *App) ProcessNotifications(ctx context.Context) error {
	a.workerMu.Lock()
	defer a.workerMu.Unlock()
	if !a.initialized(ctx) {
		return nil
	}
	if e := a.scheduleNotifications(ctx); e != nil {
		return e
	}
	rows, e := a.db.QueryContext(ctx, "SELECT id FROM notifications WHERE status IN ('pending','retry','sending') AND next_attempt_at<=? ORDER BY created_at LIMIT 50", a.now().Unix())
	if e != nil {
		return e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, id := range ids {
		var payload, key, provider string
		var first int64
		var attempts int
		send := false
		e = a.transaction(ctx, func(tx *sql.Tx) error {
			if e := cancelStaleNotifications(ctx, tx); e != nil {
				return e
			}
			var status string
			var rev int
			var firstDB *int64
			if e := tx.QueryRowContext(ctx, "SELECT payload,status,settings_revision,first_attempt_at,attempts FROM notifications WHERE id=?", id).Scan(&payload, &status, &rev, &firstDB, &attempts); e != nil {
				return e
			}
			if !slices.Contains([]string{"pending", "retry", "sending"}, status) {
				return nil
			}
			s, e := a.settings(ctx, tx)
			if e != nil {
				return e
			}
			if !s.ResendEnabled || rev != s.Revision {
				return nil
			}
			first = a.now().Unix()
			if firstDB != nil {
				first = *firstDB
			}
			if a.now().Unix()-first >= 23*3600 {
				_, e = tx.ExecContext(ctx, "UPDATE notifications SET status='needs_attention',last_error='idempotency_window_closed' WHERE id=?", id)
				return e
			}
			provider = s.emailProvider()
			key, e = a.configSecret(ctx, tx, s.emailSecretName())
			if e != nil {
				return e
			}
			attempts++
			_, e = tx.ExecContext(ctx, "UPDATE notifications SET status='sending',attempts=?,first_attempt_at=?,next_attempt_at=? WHERE id=?", attempts, first, a.now().Add(time.Minute).Unix(), id)
			send = e == nil
			return e
		})
		if e != nil {
			return e
		}
		if !send {
			continue
		}
		result := a.sendEmail(ctx, provider, key, payload, id)
		status := "sent"
		var sent any = a.now().Unix()
		next := a.now().Unix()
		if result.ID == "" {
			sent = nil
			status = "failed"
			if result.Retry {
				status = "retry"
				delay := time.Duration(1<<min(attempts, 6)) * time.Minute
				if delay > time.Hour {
					delay = time.Hour
				}
				if result.Delay > delay {
					delay = result.Delay
				}
				next = a.now().Add(delay).Unix()
				if next-first >= 23*3600 {
					status = "needs_attention"
				}
			}
		}
		e = a.transaction(ctx, func(tx *sql.Tx) error {
			var current string
			if e := tx.QueryRowContext(ctx, "SELECT status FROM notifications WHERE id=?", id).Scan(&current); e != nil {
				return e
			}
			if result.ID == "" && current != "sending" {
				status = current
			}
			if _, e := tx.ExecContext(ctx, "UPDATE notifications SET status=?,sent_at=?,provider_id=?,last_error=?,next_attempt_at=? WHERE id=?", status, sent, result.ID, result.Code, next, id); e != nil {
				return e
			}
			decision := "allow"
			if result.ID == "" {
				decision = "deny"
			}
			return a.audit(ctx, tx, "notification.send", decision, "", map[string]any{"notification_id": id, "status": status, "provider_id": result.ID, "reason": result.Code})
		})
		if e != nil {
			return e
		}
	}
	return nil
}
func (a *App) testEmail(w http.ResponseWriter, r *http.Request) error {
	if e := a.rate(r, "test-email", 3); e != nil {
		return e
	}
	s, e := a.settings(r.Context(), a.db)
	if e != nil {
		return e
	}
	if !s.ResendEnabled {
		return bad("configure and enable email notifications first")
	}
	key, e := a.configSecret(r.Context(), a.db, s.emailSecretName())
	if e != nil {
		return e
	}
	id := newID("test")
	if e = a.audit(r.Context(), a.db, "notification.test_requested", "allow", "", map[string]string{"id": id}); e != nil {
		return e
	}
	result := a.sendEmail(r.Context(), s.emailProvider(), key, jsonText(emailPayload{From: s.emailSender(), To: []string{s.OwnerEmail}, Subject: "[CIVault] 通知配置测试", Text: "邮件服务已连接。此邮件不包含任何密钥。"}), id)
	decision := "allow"
	if result.ID == "" {
		decision = "deny"
	}
	if e = a.audit(r.Context(), a.db, "notification.test_result", decision, "", map[string]string{"reason": result.Code, "provider_id": result.ID}); e != nil {
		return e
	}
	if result.ID == "" {
		return &apiError{502, "email_failed", "test email failed: " + result.Code}
	}
	respond(w, 200, map[string]string{"provider_id": result.ID})
	return nil
}
func (a *App) cleanup(ctx context.Context) error {
	s, e := a.settings(ctx, a.db)
	if e != nil {
		return e
	}
	now := a.now().Unix()
	return a.transaction(ctx, func(tx *sql.Tx) error {
		for _, x := range []struct {
			q    string
			time int64
		}{{"DELETE FROM sessions WHERE expires_at<=?", now}, {"DELETE FROM oauth_flows WHERE expires_at<=?", now}, {"DELETE FROM oidc_requests WHERE expires_at<?", now}, {"DELETE FROM idempotency WHERE created_at<?", now - 86400}, {"DELETE FROM audit_events WHERE created_at<?", now - int64(s.AuditRetentionDays)*86400}} {
			if _, e := tx.ExecContext(ctx, x.q, x.time); e != nil {
				return e
			}
		}
		return nil
	})
}
func (a *App) RunWorker(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if a.initialized(ctx) {
			if e := a.ProcessNotifications(ctx); e != nil && ctx.Err() == nil {
				a.logger.Error("notification worker failed", "code", "worker_error")
			}
			if e := a.cleanup(ctx); e != nil && ctx.Err() == nil {
				a.logger.Error("cleanup failed", "code", "cleanup_error")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
