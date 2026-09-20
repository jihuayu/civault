package vault

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

func (a *App) getSettings(w http.ResponseWriter, r *http.Request) error {
	v, e := a.settings(r.Context(), a.db)
	if e != nil {
		return e
	}
	respond(w, 200, v)
	return nil
}
func (a *App) putSettings(w http.ResponseWriter, r *http.Request) error {
	var in SettingsUpdate
	if e := decode(w, r, &in); e != nil {
		return e
	}
	in.PublicURL = strings.TrimRight(in.PublicURL, "/")
	in.OwnerEmail = strings.ToLower(strings.TrimSpace(in.OwnerEmail))
	if in.ReminderDays == nil {
		in.ReminderDays = []int{}
	}
	if e := validateSettings(in.Settings); e != nil {
		return bad(e.Error())
	}
	for _, v := range []*string{in.GithubSecret, in.ResendKey, in.AgentMailKey} {
		if v != nil && (*v == "" || len(*v) > 4096 || strings.TrimSpace(*v) != *v || strings.ContainsAny(*v, "\x00\r\n") || strings.Contains(*v, "***") || strings.Contains(*v, "•••")) {
			return bad("secret replacement must be nonempty and must not be a mask; use explicit clear instead")
		}
	}
	if in.ClearGithubSecret && in.GithubSecret != nil || in.ClearResendKey && in.ResendKey != nil || in.ClearAgentMailKey && in.AgentMailKey != nil {
		return bad("cannot replace and clear the same secret")
	}
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	e := a.transaction(r.Context(), func(tx *sql.Tx) error {
		old, e := a.settings(r.Context(), tx)
		if e != nil {
			return e
		}
		if old.Revision != in.Revision {
			return conflict("settings changed; reload and retry")
		}
		gh := (old.GithubSecretConfigured && !in.ClearGithubSecret) || in.GithubSecret != nil
		re := (old.ResendKeyConfigured && !in.ClearResendKey) || in.ResendKey != nil
		if in.GithubEnabled && (!gh || in.GithubClientID == "") {
			return bad("GitHub login requires client ID and secret")
		}
		if in.ResendEnabled && in.emailProvider() == "resend" && (!re || in.ResendFrom == "") {
			return bad("Resend requires API key and sender")
		}
		am := (old.AgentMailKeyConfigured && !in.ClearAgentMailKey) || in.AgentMailKey != nil
		if in.ResendEnabled && in.emailProvider() == "agentmail" && (!am || in.AgentMailInboxID == "") {
			return bad("AgentMail requires API key and inbox ID")
		}
		in.EmailProvider = in.emailProvider()
		next := old.Revision + 1
		for _, x := range []struct {
			name  string
			value *string
			clear bool
		}{{"github_secret", in.GithubSecret, in.ClearGithubSecret}, {"resend_key", in.ResendKey, in.ClearResendKey}, {"agentmail_key", in.AgentMailKey, in.ClearAgentMailKey}} {
			if x.value != nil || x.clear {
				var blob []byte
				if x.value != nil {
					blob, e = a.box.Seal([]byte(*x.value), "settings", x.name, strconv.Itoa(next))
					if e != nil {
						return e
					}
				}
				if _, e = tx.ExecContext(r.Context(), "UPDATE settings SET "+x.name+"=?,"+x.name+"_revision=? WHERE id=1", blob, next); e != nil {
					return e
				}
			}
		}
		if _, e = tx.ExecContext(r.Context(), "UPDATE settings SET revision=?,data=? WHERE id=1", next, jsonText(in.Settings)); e != nil {
			return e
		}
		// An uncertain send is never automatically resent with changed provider settings.
		if _, e = tx.ExecContext(r.Context(), "UPDATE notifications SET status=CASE WHEN attempts=0 THEN 'cancelled' ELSE 'needs_attention' END,last_error='settings_changed' WHERE status IN ('pending','retry','sending')"); e != nil {
			return e
		}
		fields := []string{}
		operations := map[string]string{}
		before, after := map[string]any{}, map[string]any{}
		_ = json.Unmarshal([]byte(jsonText(old.Settings)), &before)
		_ = json.Unmarshal([]byte(jsonText(in.Settings)), &after)
		for k, v := range after {
			if jsonText(v) != jsonText(before[k]) {
				fields = append(fields, k)
			}
		}
		if in.GithubSecret != nil || in.ClearGithubSecret {
			fields = append(fields, "github_secret")
			operations["github_secret"] = "replace"
			if in.ClearGithubSecret {
				operations["github_secret"] = "clear"
			}
		}
		if in.ResendKey != nil || in.ClearResendKey {
			fields = append(fields, "resend_key")
			operations["resend_key"] = "replace"
			if in.ClearResendKey {
				operations["resend_key"] = "clear"
			}
		}
		if in.AgentMailKey != nil || in.ClearAgentMailKey {
			fields = append(fields, "agentmail_key")
			operations["agentmail_key"] = "replace"
			if in.ClearAgentMailKey {
				operations["agentmail_key"] = "clear"
			}
		}
		slices.Sort(fields)
		return a.audit(r.Context(), tx, "settings.updated", "allow", "", map[string]any{"revision": next, "fields": fields, "secret_operations": operations})
	})
	if e != nil {
		return e
	}
	a.setLevel(in.LogLevel)
	return a.getSettings(w, r)
}
func (a *App) listJSON(w http.ResponseWriter, r *http.Request, query string, args []any) error {
	rows, e := a.db.QueryContext(r.Context(), query, args...)
	if e != nil {
		return e
	}
	defer rows.Close()
	cols, e := rows.Columns()
	if e != nil {
		return e
	}
	out := []map[string]any{}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptr := make([]any, len(cols))
		for i := range vals {
			ptr[i] = &vals[i]
		}
		if e = rows.Scan(ptr...); e != nil {
			return e
		}
		obj := map[string]any{}
		for i, k := range cols {
			v := vals[i]
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			if k == "details" || k == "spec" {
				if s, ok := v.(string); ok {
					var j any
					if json.Unmarshal([]byte(s), &j) == nil {
						v = j
					}
				}
			}
			obj[k] = v
		}
		out = append(out, obj)
	}
	if e = rows.Err(); e != nil {
		return e
	}
	respond(w, 200, out)
	return nil
}
func (a *App) workspaces(w http.ResponseWriter, r *http.Request) error {
	return a.listJSON(w, r, "SELECT id,name,created_at FROM workspaces ORDER BY created_at,id", nil)
}
func (a *App) createWorkspace(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Name string `json:"name"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if !validName(in.Name) {
		return bad("invalid workspace name")
	}
	id := newID("ws")
	e := a.transaction(r.Context(), func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(r.Context(), "INSERT INTO workspaces(id,name,created_at) VALUES(?,?,?)", id, in.Name, a.now().Unix()); e != nil {
			return e
		}
		return a.audit(r.Context(), tx, "workspace.created", "allow", id, map[string]string{"name": in.Name})
	})
	if e != nil {
		return e
	}
	respond(w, 201, map[string]string{"id": id, "name": in.Name})
	return nil
}
func keyExists(ctx context.Context, q queryer, ws, id string) error {
	var n int
	e := q.QueryRowContext(ctx, "SELECT 1 FROM keys WHERE workspace_id=? AND id=? AND deleted=0", ws, id).Scan(&n)
	return e
}
func getKeys(ctx context.Context, q queryer, ws string) ([]Key, error) {
	rows, e := q.QueryContext(ctx, "SELECT k.id,k.workspace_id,k.path,k.active_version_id,k.disabled,k.created_at,v.expires_at,COALESCE(v.number,0) FROM keys k LEFT JOIN key_versions v ON v.id=k.active_version_id WHERE k.workspace_id=? AND k.deleted=0 ORDER BY k.path", ws)
	if e != nil {
		return nil, e
	}
	out := []Key{}
	for rows.Next() {
		var k Key
		k.Tags = []Tag{}
		if e = rows.Scan(&k.ID, &k.WorkspaceID, &k.Path, &k.ActiveVersionID, &k.Disabled, &k.CreatedAt, &k.ExpiresAt, &k.Version); e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, k)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	for i := range out {
		rows, e = q.QueryContext(ctx, "SELECT t.id,t.name FROM tags t JOIN key_tags kt ON kt.tag_id=t.id WHERE kt.key_id=? ORDER BY t.name", out[i].ID)
		if e != nil {
			return nil, e
		}
		for rows.Next() {
			var t Tag
			if e = rows.Scan(&t.ID, &t.Name); e != nil {
				rows.Close()
				return nil, e
			}
			out[i].Tags = append(out[i].Tags, t)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
	}
	return out, nil
}
func (a *App) listKeys(w http.ResponseWriter, r *http.Request) error {
	v, e := getKeys(r.Context(), a.db, r.PathValue("ws"))
	if e != nil {
		return e
	}
	respond(w, 200, v)
	return nil
}
func (a *App) putKey(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Path      string  `json:"path"`
		Value     string  `json:"value"`
		ExpiresAt *string `json:"expires_at"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if !validPath(in.Path) || in.Value == "" || len(in.Value) > 32768 || !utf8.ValidString(in.Value) || strings.ContainsRune(in.Value, 0) {
		return bad("key requires a valid path and 1–32768 bytes of UTF-8 text without NUL")
	}
	expiry, e := parseTime(in.ExpiresAt)
	if e != nil {
		return e
	}
	ws := r.PathValue("ws")
	idem := r.Header.Get("Idempotency-Key")
	if len(idem) > 200 {
		return bad("idempotency key is too long")
	}
	idemID := digest(jsonText([]any{r.Context().Value(actorContext), ws, idem}))
	fingerprint := a.box.MAC("write-request", []byte(jsonText(in)))
	var result any
	e = a.transaction(r.Context(), func(tx *sql.Tx) error {
		if idem != "" {
			var hash, body string
			e := tx.QueryRowContext(r.Context(), "SELECT request_hash,response FROM idempotency WHERE key=?", idemID).Scan(&hash, &body)
			if e == nil {
				if hash != fingerprint {
					return conflict("idempotency key used with different content")
				}
				return json.Unmarshal([]byte(body), &result)
			}
			if !errors.Is(e, sql.ErrNoRows) {
				return e
			}
		}
		id := newID("key")
		var existing string
		var deleted bool
		e := tx.QueryRowContext(r.Context(), "SELECT id,deleted FROM keys WHERE workspace_id=? AND path=?", ws, in.Path).Scan(&existing, &deleted)
		if e == nil {
			if deleted {
				return conflict("key path was deleted and cannot be reused")
			}
			id = existing
		} else if errors.Is(e, sql.ErrNoRows) {
			if _, e = tx.ExecContext(r.Context(), "INSERT INTO keys(id,workspace_id,path,created_at) VALUES(?,?,?,?)", id, ws, in.Path, a.now().Unix()); e != nil {
				return e
			}
		} else {
			return e
		}
		var number int
		if e = tx.QueryRowContext(r.Context(), "SELECT COALESCE(max(number),0)+1 FROM key_versions WHERE key_id=?", id).Scan(&number); e != nil {
			return e
		}
		version := newID("ver")
		blob, e := a.box.Seal([]byte(in.Value), "key", ws, id, version)
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(r.Context(), "INSERT INTO key_versions(id,workspace_id,key_id,number,encrypted,expires_at,created_at) VALUES(?,?,?,?,?,?,?)", version, ws, id, number, blob, expiry, a.now().Unix()); e != nil {
			return e
		}
		if _, e = tx.ExecContext(r.Context(), "UPDATE keys SET active_version_id=? WHERE id=?", version, id); e != nil {
			return e
		}
		if e = cancelStaleNotifications(r.Context(), tx); e != nil {
			return e
		}
		result = map[string]any{"id": id, "version_id": version, "number": number, "path": in.Path}
		if idem != "" {
			if _, e = tx.ExecContext(r.Context(), "INSERT INTO idempotency(key,request_hash,response,created_at) VALUES(?,?,?,?)", idemID, fingerprint, jsonText(result), a.now().Unix()); e != nil {
				return e
			}
		}
		return a.audit(r.Context(), tx, "key.version_created", "allow", ws, result)
	})
	if e != nil {
		return e
	}
	respond(w, 201, result)
	return nil
}
func (a *App) patchKey(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Disabled *bool `json:"disabled"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if in.Disabled == nil {
		return bad("disabled is required")
	}
	ws, id := r.PathValue("ws"), r.PathValue("key")
	e := a.transaction(r.Context(), func(tx *sql.Tx) error {
		res, e := tx.ExecContext(r.Context(), "UPDATE keys SET disabled=? WHERE workspace_id=? AND id=? AND deleted=0", in.Disabled, ws, id)
		if e = affected(res, e); e != nil {
			return e
		}
		if e = cancelStaleNotifications(r.Context(), tx); e != nil {
			return e
		}
		return a.audit(r.Context(), tx, "key.state_changed", "allow", ws, map[string]any{"key_id": id, "disabled": in.Disabled})
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) deleteKey(w http.ResponseWriter, r *http.Request) error {
	ws, id := r.PathValue("ws"), r.PathValue("key")
	e := a.transaction(r.Context(), func(tx *sql.Tx) error {
		res, e := tx.ExecContext(r.Context(), "UPDATE keys SET deleted=1,disabled=1 WHERE workspace_id=? AND id=? AND deleted=0", ws, id)
		if e = affected(res, e); e != nil {
			return e
		}
		if e = cancelStaleNotifications(r.Context(), tx); e != nil {
			return e
		}
		return a.audit(r.Context(), tx, "key.deleted", "allow", ws, map[string]string{"key_id": id})
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) keyVersions(w http.ResponseWriter, r *http.Request) error {
	return a.listJSON(w, r, "SELECT v.id,v.number,v.expires_at,v.expiry_revision,v.created_at,(k.active_version_id=v.id) AS active FROM key_versions v JOIN keys k ON k.id=v.key_id WHERE k.workspace_id=? AND k.id=? AND k.deleted=0 ORDER BY number DESC", []any{r.PathValue("ws"), r.PathValue("key")})
}
func (a *App) activateVersion(w http.ResponseWriter, r *http.Request) error {
	ws, id, version := r.PathValue("ws"), r.PathValue("key"), r.PathValue("version")
	e := a.transaction(r.Context(), func(tx *sql.Tx) error {
		var expiry *int64
		if e := tx.QueryRowContext(r.Context(), "SELECT expires_at FROM key_versions WHERE workspace_id=? AND key_id=? AND id=?", ws, id, version).Scan(&expiry); e != nil {
			return e
		}
		if expiry != nil && *expiry <= a.now().Unix() {
			return conflict("cannot activate an expired version")
		}
		res, e := tx.ExecContext(r.Context(), "UPDATE keys SET active_version_id=? WHERE workspace_id=? AND id=? AND deleted=0", version, ws, id)
		if e = affected(res, e); e != nil {
			return e
		}
		if e = cancelStaleNotifications(r.Context(), tx); e != nil {
			return e
		}
		return a.audit(r.Context(), tx, "key.version_activated", "allow", ws, map[string]string{"key_id": id, "version_id": version})
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) expireVersion(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		ExpiresAt json.RawMessage `json:"expires_at"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if len(in.ExpiresAt) == 0 {
		return bad("expires_at is required; use null to clear")
	}
	var timestamp *string
	if json.Unmarshal(in.ExpiresAt, &timestamp) != nil {
		return bad("expires_at must be RFC3339 or null")
	}
	expiry, e := parseTime(timestamp)
	if e != nil {
		return e
	}
	ws, id, v := r.PathValue("ws"), r.PathValue("key"), r.PathValue("version")
	e = a.transaction(r.Context(), func(tx *sql.Tx) error {
		if e := keyExists(r.Context(), tx, ws, id); e != nil {
			return e
		}
		res, e := tx.ExecContext(r.Context(), "UPDATE key_versions SET expiry_revision=expiry_revision+CASE WHEN expires_at IS ? THEN 0 ELSE 1 END,expires_at=? WHERE workspace_id=? AND key_id=? AND id=?", expiry, expiry, ws, id, v)
		if e = affected(res, e); e != nil {
			return e
		}
		if e = cancelStaleNotifications(r.Context(), tx); e != nil {
			return e
		}
		return a.audit(r.Context(), tx, "key.expiry_changed", "allow", ws, map[string]any{"key_id": id, "version_id": v, "expires_at": expiry})
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) tags(w http.ResponseWriter, r *http.Request) error {
	return a.listJSON(w, r, "SELECT id,name FROM tags WHERE workspace_id=? ORDER BY name", []any{r.PathValue("ws")})
}
func (a *App) createTag(w http.ResponseWriter, r *http.Request) error { return a.writeTag(w, r, false) }
func (a *App) renameTag(w http.ResponseWriter, r *http.Request) error { return a.writeTag(w, r, true) }
func (a *App) writeTag(w http.ResponseWriter, r *http.Request, rename bool) error {
	var in struct {
		Name string `json:"name"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if !validName(in.Name) {
		return bad("invalid tag name")
	}
	ws, id := r.PathValue("ws"), r.PathValue("tag")
	if !rename {
		id = newID("tag")
	}
	e := a.transaction(r.Context(), func(tx *sql.Tx) error {
		if rename {
			res, e := tx.ExecContext(r.Context(), "UPDATE tags SET name=? WHERE workspace_id=? AND id=?", in.Name, ws, id)
			if e = affected(res, e); e != nil {
				return e
			}
		} else {
			if _, e := tx.ExecContext(r.Context(), "INSERT INTO tags(id,workspace_id,name) VALUES(?,?,?)", id, ws, in.Name); e != nil {
				return e
			}
		}
		return a.audit(r.Context(), tx, "tag.saved", "allow", ws, map[string]string{"tag_id": id, "name": in.Name})
	})
	if e != nil {
		return e
	}
	respond(w, 200, Tag{ID: id, Name: in.Name})
	return nil
}
func (a *App) deleteTag(w http.ResponseWriter, r *http.Request) error {
	ws, id := r.PathValue("ws"), r.PathValue("tag")
	e := a.transaction(r.Context(), func(tx *sql.Tx) error {
		var count int
		if e := tx.QueryRowContext(r.Context(), "SELECT count(*) FROM policy_tag_targets WHERE tag_id=?", id).Scan(&count); e != nil {
			return e
		}
		if count > 0 {
			return conflict("tag is referenced by a policy version")
		}
		if _, e := tx.ExecContext(r.Context(), "DELETE FROM key_tags WHERE workspace_id=? AND tag_id=?", ws, id); e != nil {
			return e
		}
		res, e := tx.ExecContext(r.Context(), "DELETE FROM tags WHERE workspace_id=? AND id=?", ws, id)
		if e = affected(res, e); e != nil {
			return e
		}
		return a.audit(r.Context(), tx, "tag.deleted", "allow", ws, map[string]string{"tag_id": id})
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) setKeyTags(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		TagIDs []string `json:"tag_ids"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if in.TagIDs == nil {
		return bad("tag_ids is required; use an empty array to remove all tags")
	}
	if len(in.TagIDs) > 100 {
		return bad("too many tags")
	}
	ws, id := r.PathValue("ws"), r.PathValue("key")
	e := a.transaction(r.Context(), func(tx *sql.Tx) error {
		if e := keyExists(r.Context(), tx, ws, id); e != nil {
			return e
		}
		rows, e := tx.QueryContext(r.Context(), "SELECT tag_id FROM key_tags WHERE key_id=?", id)
		if e != nil {
			return e
		}
		old := []string{}
		for rows.Next() {
			var s string
			if e = rows.Scan(&s); e != nil {
				rows.Close()
				return e
			}
			old = append(old, s)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(r.Context(), "DELETE FROM key_tags WHERE key_id=?", id); e != nil {
			return e
		}
		for _, tag := range in.TagIDs {
			if _, e = tx.ExecContext(r.Context(), "INSERT INTO key_tags(workspace_id,key_id,tag_id) VALUES(?,?,?)", ws, id, tag); e != nil {
				return e
			}
		}
		return a.audit(r.Context(), tx, "key.tags_changed", "allow", ws, map[string]any{"key_id": id, "before": old, "after": in.TagIDs})
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"ok": true})
	return nil
}
