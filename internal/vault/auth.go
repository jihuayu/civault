package vault

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

func passwordHash(password string) (string, error) {
	if len(password) < 12 || len(password) > 256 {
		return "", bad("password must contain 12–256 bytes")
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	h := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return "$argon2id$v=19$m=65536,t=3,p=4$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(h), nil
}
func passwordOK(stored, password string) bool {
	if len(password) > 256 {
		return false
	}
	p := strings.Split(stored, "$")
	if len(p) != 6 || p[1] != "argon2id" || p[2] != "v=19" || p[3] != "m=65536,t=3,p=4" {
		return false
	}
	s, e := base64.RawStdEncoding.DecodeString(p[4])
	if e != nil || len(s) != 16 {
		return false
	}
	h, e := base64.RawStdEncoding.DecodeString(p[5])
	if e != nil || len(h) != 32 {
		return false
	}
	c := argon2.IDKey([]byte(password), s, 3, 64*1024, 4, 32)
	defer clear(c)
	return subtle.ConstantTimeCompare(c, h) == 1
}
func (a *App) status(w http.ResponseWriter, r *http.Request) error {
	initialized := a.initialized(r.Context())
	github := false
	if initialized {
		v, e := a.settings(r.Context(), a.db)
		if e != nil {
			return e
		}
		github = v.GithubEnabled
	}
	respond(w, 200, map[string]bool{"initialized": initialized, "github_enabled": github})
	return nil
}
func (a *App) setup(w http.ResponseWriter, r *http.Request) error {
	if e := a.rate(r, "setup", 5); e != nil {
		return e
	}
	var in struct {
		Code      string `json:"code"`
		Email     string `json:"email"`
		Password  string `json:"password"`
		PublicURL string `json:"public_url"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if a.initialized(r.Context()) {
		return conflict("already initialized")
	}
	code, e := os.ReadFile(filepath.Join(a.dataDir, "setup-token"))
	if e != nil {
		return denied()
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(in.Code)), code) != 1 {
		return denied()
	}
	s := Settings{OwnerEmail: strings.ToLower(strings.TrimSpace(in.Email)), PublicURL: strings.TrimRight(in.PublicURL, "/"), ReminderDays: []int{7, 3, 1}, NotifyOnExpiry: true, LogLevel: "info", AuditRetentionDays: 180}
	if e = validateSettings(s); e != nil {
		return bad(e.Error())
	}
	hash, e := passwordHash(in.Password)
	if e != nil {
		return e
	}
	e = a.transaction(r.Context(), func(tx *sql.Tx) error {
		var n int
		if e := tx.QueryRowContext(r.Context(), "SELECT count(*) FROM owner").Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			return conflict("already initialized")
		}
		if _, e := tx.ExecContext(r.Context(), "INSERT INTO owner(id,password_hash) VALUES(1,?)", hash); e != nil {
			return e
		}
		if _, e := tx.ExecContext(r.Context(), "INSERT INTO settings(id,revision,data) VALUES(1,1,?)", jsonText(s)); e != nil {
			return e
		}
		if _, e := tx.ExecContext(r.Context(), "INSERT INTO workspaces(id,name,created_at) VALUES('ws_default','默认工作区',?)", a.now().Unix()); e != nil {
			return e
		}
		return a.audit(r.Context(), tx, "system.initialized", "allow", "", map[string]string{})
	})
	if e != nil {
		return e
	}
	_ = os.Remove(filepath.Join(a.dataDir, "setup-token"))
	respond(w, 201, map[string]bool{"initialized": true})
	return nil
}
func (a *App) cookie(w http.ResponseWriter, s Settings, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: age, HttpOnly: true, Secure: strings.HasPrefix(s.PublicURL, "https://"), SameSite: http.SameSiteLaxMode})
}
func (a *App) newSession(ctx context.Context, q queryer) (string, string, error) {
	token, csrf := randomToken(), randomToken()
	_, e := q.ExecContext(ctx, "INSERT INTO sessions(hash,csrf,expires_at) VALUES(?,?,?)", digest(token), csrf, a.now().Add(8*time.Hour).Unix())
	return token, csrf, e
}
func (a *App) login(w http.ResponseWriter, r *http.Request) error {
	if e := a.rate(r, "login", 5); e != nil {
		return e
	}
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	s, e := a.settings(r.Context(), a.db)
	if e != nil {
		return unauthorized()
	}
	var hash string
	if e = a.db.QueryRowContext(r.Context(), "SELECT password_hash FROM owner WHERE id=1").Scan(&hash); e != nil {
		return e
	}
	ok := passwordOK(hash, in.Password)
	if !ok || !strings.EqualFold(in.Email, s.OwnerEmail) {
		if e = a.audit(r.Context(), a.db, "auth.login", "deny", "", map[string]string{"reason": "invalid_credentials"}); e != nil {
			return e
		}
		return unauthorized()
	}
	ctx := context.WithValue(r.Context(), actorContext, "owner")
	var token, csrf string
	e = a.transaction(ctx, func(tx *sql.Tx) error {
		var currentHash string
		if e := tx.QueryRowContext(ctx, "SELECT password_hash FROM owner WHERE id=1").Scan(&currentHash); e != nil {
			return e
		}
		current, e := a.settings(ctx, tx)
		if e != nil {
			return e
		}
		if currentHash != hash || current.Revision != s.Revision {
			return unauthorized()
		}
		token, csrf, e = a.newSession(ctx, tx)
		if e != nil {
			return e
		}
		return a.audit(ctx, tx, "auth.login", "allow", "", map[string]string{"method": "password"})
	})
	if e != nil {
		return e
	}
	a.cookie(w, s.Settings, "civault_session", token, 28800)
	respond(w, 200, map[string]string{"csrf_token": csrf, "email": s.OwnerEmail})
	return nil
}
func (a *App) admin(h endpoint) endpoint {
	return func(w http.ResponseWriter, r *http.Request) error {
		ctx := r.Context()
		auth := r.Header.Get("Authorization")
		if auth != "" {
			if !strings.HasPrefix(auth, "Bearer ") {
				return unauthorized()
			}
			raw := strings.TrimPrefix(auth, "Bearer ")
			var id string
			if e := a.db.QueryRowContext(ctx, "SELECT id FROM admin_tokens WHERE hash=? AND revoked=0 AND expires_at>?", digest(raw), a.now().Unix()).Scan(&id); e != nil {
				return unauthorized()
			}
			return h(w, r.WithContext(context.WithValue(ctx, actorContext, "token:"+id)))
		}
		c, e := r.Cookie("civault_session")
		if e != nil {
			return unauthorized()
		}
		var csrf string
		if e = a.db.QueryRowContext(ctx, "SELECT csrf FROM sessions WHERE hash=? AND expires_at>?", digest(c.Value), a.now().Unix()).Scan(&csrf); e != nil {
			return unauthorized()
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(csrf)) != 1 {
				return denied()
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				s, e := a.settings(ctx, a.db)
				if e != nil {
					return e
				}
				if origin != s.PublicURL {
					return denied()
				}
			}
		}
		return h(w, r.WithContext(context.WithValue(ctx, actorContext, "owner")))
	}
}
func (a *App) me(w http.ResponseWriter, r *http.Request) error {
	s, e := a.settings(r.Context(), a.db)
	if e != nil {
		return e
	}
	csrf := ""
	if c, e := r.Cookie("civault_session"); e == nil {
		_ = a.db.QueryRowContext(r.Context(), "SELECT csrf FROM sessions WHERE hash=? AND expires_at>?", digest(c.Value), a.now().Unix()).Scan(&csrf)
	}
	respond(w, 200, map[string]string{"email": s.OwnerEmail, "csrf_token": csrf, "github_id": s.GithubID})
	return nil
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) error {
	if c, e := r.Cookie("civault_session"); e == nil {
		if _, e = a.db.ExecContext(r.Context(), "DELETE FROM sessions WHERE hash=?", digest(c.Value)); e != nil {
			return e
		}
	}
	s, e := a.settings(r.Context(), a.db)
	if e != nil {
		return e
	}
	a.cookie(w, s.Settings, "civault_session", "", -1)
	respond(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) changePassword(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Current string `json:"current_password"`
		Next    string `json:"new_password"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if e := a.rate(r, "password", 5); e != nil {
		return e
	}
	var old string
	if e := a.db.QueryRowContext(r.Context(), "SELECT password_hash FROM owner WHERE id=1").Scan(&old); e != nil {
		return e
	}
	if !passwordOK(old, in.Current) {
		return denied()
	}
	next, e := passwordHash(in.Next)
	if e != nil {
		return e
	}
	e = a.transaction(r.Context(), func(tx *sql.Tx) error {
		res, e := tx.ExecContext(r.Context(), "UPDATE owner SET password_hash=? WHERE id=1 AND password_hash=?", next, old)
		if e != nil {
			return e
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return conflict("password changed concurrently")
		}
		for _, q := range []string{"DELETE FROM sessions", "UPDATE admin_tokens SET revoked=1"} {
			if _, e = tx.ExecContext(r.Context(), q); e != nil {
				return e
			}
		}
		return a.audit(r.Context(), tx, "owner.password_changed", "allow", "", map[string]bool{"sessions_revoked": true})
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) unlinkGithub(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Password string `json:"password"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if e := a.rate(r, "unlink", 5); e != nil {
		return e
	}
	var hash string
	if e := a.db.QueryRowContext(r.Context(), "SELECT password_hash FROM owner WHERE id=1").Scan(&hash); e != nil {
		return e
	}
	if !passwordOK(hash, in.Password) {
		return denied()
	}
	e := a.transaction(r.Context(), func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(r.Context(), "UPDATE owner SET github_id='' WHERE id=1"); e != nil {
			return e
		}
		return a.audit(r.Context(), tx, "owner.github_unlinked", "allow", "", map[string]string{})
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) githubStart(w http.ResponseWriter, r *http.Request) error {
	if e := a.rate(r, "oauth", 10); e != nil {
		return e
	}
	s, e := a.settings(r.Context(), a.db)
	if e != nil || !s.GithubEnabled {
		return denied()
	}
	state, verifier, browser := randomToken(), randomToken(), randomToken()
	sum := sha256.Sum256([]byte(verifier))
	_, e = a.db.ExecContext(r.Context(), "INSERT INTO oauth_flows(hash,browser_hash,verifier,settings_revision,expires_at) VALUES(?,?,?,?,?)", digest(state), digest(browser), verifier, s.Revision, a.now().Add(5*time.Minute).Unix())
	if e != nil {
		return e
	}
	a.cookie(w, s.Settings, "civault_oauth", browser, 300)
	q := url.Values{"client_id": {s.GithubClientID}, "redirect_uri": {s.PublicURL + "/v1/auth/github/callback"}, "scope": {"read:user user:email"}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "allow_signup": {"false"}}
	http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+q.Encode(), 302)
	return nil
}
func (a *App) githubCallback(w http.ResponseWriter, r *http.Request) error {
	if e := a.rate(r, "oauth-callback", 10); e != nil {
		return e
	}
	c, e := r.Cookie("civault_oauth")
	if e != nil {
		return a.oauthDenied(r, "missing_browser_state")
	}
	state, code := r.URL.Query().Get("state"), r.URL.Query().Get("code")
	if state == "" || code == "" {
		return a.oauthDenied(r, "incomplete_callback")
	}
	var verifier string
	var rev int
	e = a.transaction(r.Context(), func(tx *sql.Tx) error {
		if e := tx.QueryRowContext(r.Context(), "SELECT verifier,settings_revision FROM oauth_flows WHERE hash=? AND browser_hash=? AND expires_at>?", digest(state), digest(c.Value), a.now().Unix()).Scan(&verifier, &rev); e != nil {
			return denied()
		}
		_, e := tx.ExecContext(r.Context(), "DELETE FROM oauth_flows WHERE hash=?", digest(state))
		return e
	})
	if e != nil {
		return e
	}
	s, e := a.settings(r.Context(), a.db)
	if e != nil || !s.GithubEnabled || s.Revision != rev {
		return a.oauthDenied(r, "configuration_changed")
	}
	secret, e := a.configSecret(r.Context(), a.db, "github_secret")
	if e != nil {
		return e
	}
	form := url.Values{"client_id": {s.GithubClientID}, "client_secret": {secret}, "code": {code}, "redirect_uri": {s.PublicURL + "/v1/auth/github/callback"}, "code_verifier": {verifier}}
	req, _ := http.NewRequestWithContext(r.Context(), "POST", "https://github.com/login/oauth/access_token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if e = a.remoteJSON(req, &token); e != nil || token.AccessToken == "" {
		return a.oauthDenied(r, "exchange_failed")
	}
	get := func(path string, dst any) error {
		req, _ := http.NewRequestWithContext(r.Context(), "GET", "https://api.github.com"+path, nil)
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		req.Header.Set("Accept", "application/vnd.github+json")
		return a.remoteJSON(req, dst)
	}
	var user struct {
		ID json.Number `json:"id"`
	}
	if e = get("/user", &user); e != nil || !digits.MatchString(user.ID.String()) {
		return a.oauthDenied(r, "identity_failed")
	}
	id := user.ID.String()
	if s.GithubID == "" {
		var emails []struct {
			Email    string `json:"email"`
			Verified bool   `json:"verified"`
		}
		if e = get("/user/emails", &emails); e != nil {
			return a.oauthDenied(r, "email_lookup_failed")
		}
		ok := false
		for _, m := range emails {
			if m.Verified && strings.EqualFold(m.Email, s.OwnerEmail) {
				ok = true
			}
		}
		if !ok {
			return a.oauthDenied(r, "email_not_verified")
		}
	} else if id != s.GithubID {
		return a.oauthDenied(r, "owner_mismatch")
	}
	ctx := context.WithValue(r.Context(), actorContext, "owner")
	var raw string
	e = a.transaction(ctx, func(tx *sql.Tx) error {
		current, e := a.settings(ctx, tx)
		if e != nil {
			return e
		}
		if current.Revision != rev || current.GithubID != "" && current.GithubID != id {
			return denied()
		}
		if _, e = tx.ExecContext(ctx, "UPDATE owner SET github_id=? WHERE id=1", id); e != nil {
			return e
		}
		raw, _, e = a.newSession(ctx, tx)
		if e != nil {
			return e
		}
		return a.audit(ctx, tx, "auth.login", "allow", "", map[string]string{"method": "github", "github_id": id})
	})
	if e != nil {
		return e
	}
	a.cookie(w, s.Settings, "civault_session", raw, 28800)
	a.cookie(w, s.Settings, "civault_oauth", "", -1)
	http.Redirect(w, r, s.PublicURL+"/", 303)
	return nil
}
func (a *App) oauthDenied(r *http.Request, reason string) error {
	if e := a.audit(r.Context(), a.db, "auth.github", "deny", "", map[string]string{"reason": reason}); e != nil {
		return e
	}
	return denied()
}
func (a *App) remoteJSON(req *http.Request, dst any) error {
	resp, e := a.client.Do(req)
	if e != nil {
		return errors.New("remote service unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("remote status %d", resp.StatusCode)
	}
	d := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	d.UseNumber()
	return d.Decode(dst)
}
func (a *App) tokens(w http.ResponseWriter, r *http.Request) error {
	return a.listJSON(w, r, "SELECT id,name,created_at,expires_at,revoked FROM admin_tokens ORDER BY created_at DESC", nil)
}
func (a *App) createToken(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Name string `json:"name"`
		Days int    `json:"days"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if !validName(in.Name) {
		return bad("invalid token name")
	}
	if in.Days == 0 {
		in.Days = 30
	}
	if in.Days < 1 || in.Days > 365 {
		return bad("token lifetime must be 1–365 days")
	}
	raw := "cv_admin_" + randomToken()
	id := newID("tok")
	expires := a.now().Add(time.Duration(in.Days) * 24 * time.Hour).Unix()
	e := a.transaction(r.Context(), func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(r.Context(), "INSERT INTO admin_tokens(id,name,hash,created_at,expires_at) VALUES(?,?,?,?,?)", id, in.Name, digest(raw), a.now().Unix(), expires); e != nil {
			return e
		}
		return a.audit(r.Context(), tx, "token.created", "allow", "", map[string]string{"id": id})
	})
	if e != nil {
		return e
	}
	respond(w, 201, map[string]any{"id": id, "token": raw, "expires_at": expires})
	return nil
}
func (a *App) revokeToken(w http.ResponseWriter, r *http.Request) error {
	e := a.transaction(r.Context(), func(tx *sql.Tx) error {
		res, e := tx.ExecContext(r.Context(), "UPDATE admin_tokens SET revoked=1 WHERE id=?", r.PathValue("token"))
		if e = affected(res, e); e != nil {
			return e
		}
		return a.audit(r.Context(), tx, "token.revoked", "allow", "", map[string]string{"id": r.PathValue("token")})
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"ok": true})
	return nil
}
func affected(res sql.Result, e error) error {
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n == 0 {
		return notfound()
	}
	return nil
}
func parseTime(v *string) (any, error) {
	if v == nil || *v == "" {
		return nil, nil
	}
	t, e := time.Parse(time.RFC3339, *v)
	if e != nil {
		return nil, bad("expires_at must be an RFC3339 timestamp or null")
	}
	return t.Unix(), nil
}
func intParam(r *http.Request, name string, def, max int) int {
	v, e := strconv.Atoi(r.URL.Query().Get(name))
	if e != nil || v < 1 {
		return def
	}
	if v > max {
		return max
	}
	return v
}
