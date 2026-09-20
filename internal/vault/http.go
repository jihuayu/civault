package vault

import (
	"bytes"
	"civault/docs"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"
)

type contextKey string

const requestContext contextKey = "request_id"
const actorContext contextKey = "actor"

type apiError struct {
	status  int
	code    string
	message string
}

func (e *apiError) Error() string { return e.message }
func bad(s string) error          { return &apiError{400, "invalid_request", s} }
func conflict(s string) error     { return &apiError{409, "conflict", s} }
func denied() error               { return &apiError{403, "access_denied", "access denied"} }
func unauthorized() error         { return &apiError{401, "unauthorized", "authentication required"} }
func notfound() error             { return &apiError{404, "not_found", "resource not found"} }

type endpoint func(http.ResponseWriter, *http.Request) error
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(s int) {
	if w.status == 0 {
		w.status = s
		w.ResponseWriter.WriteHeader(s)
	}
}
func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}

func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return bad("Content-Type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return bad("invalid JSON body or request exceeds 64 KiB")
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' {
		return bad("request must contain one JSON object")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return bad("invalid JSON body or request exceeds 64 KiB")
	}
	if d.Decode(new(any)) != io.EOF {
		return bad("request must contain one JSON object")
	}
	return nil
}
func (a *App) wrap(h endpoint) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if e := h(w, r); e != nil {
			v := &apiError{500, "internal_error", "request could not be completed"}
			var ae *apiError
			if errors.As(e, &ae) {
				v = ae
			} else if errors.Is(e, sql.ErrNoRows) {
				v = &apiError{404, "not_found", "resource not found"}
			} else if strings.Contains(e.Error(), "constraint") || strings.Contains(e.Error(), "UNIQUE") || strings.Contains(e.Error(), "FOREIGN KEY") {
				v = &apiError{409, "conflict", "resource already exists or is still referenced"}
			} else {
				a.logger.Error("request failed", "request_id", r.Context().Value(requestContext), "code", "internal_error")
			}
			respond(w, v.status, map[string]any{"error": map[string]string{"code": v.code, "message": v.message}, "request_id": r.Context().Value(requestContext)})
		}
	}
}
func (a *App) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(docs.OpenAPI)
	})
	m.HandleFunc("GET /healthz", a.wrap(func(w http.ResponseWriter, r *http.Request) error {
		if e := a.db.PingContext(r.Context()); e != nil {
			return e
		}
		respond(w, 200, map[string]bool{"ok": true})
		return nil
	}))
	m.HandleFunc("GET /v1/status", a.wrap(a.status))
	m.HandleFunc("POST /v1/setup", a.wrap(a.setup))
	m.HandleFunc("POST /v1/auth/login", a.wrap(a.login))
	m.HandleFunc("GET /v1/auth/me", a.wrap(a.admin(a.me)))
	m.HandleFunc("POST /v1/auth/logout", a.wrap(a.admin(a.logout)))
	m.HandleFunc("GET /v1/auth/github", a.wrap(a.githubStart))
	m.HandleFunc("GET /v1/auth/github/callback", a.wrap(a.githubCallback))
	reg := func(pattern string, h endpoint) { m.HandleFunc(pattern, a.wrap(a.admin(h))) }
	reg("GET /v1/admin/settings", a.getSettings)
	reg("PUT /v1/admin/settings", a.putSettings)
	reg("POST /v1/admin/password", a.changePassword)
	reg("DELETE /v1/admin/github-binding", a.unlinkGithub)
	reg("GET /v1/admin/workspaces", a.workspaces)
	reg("POST /v1/admin/workspaces", a.createWorkspace)
	reg("GET /v1/admin/workspaces/{ws}/keys", a.listKeys)
	reg("POST /v1/admin/workspaces/{ws}/keys", a.putKey)
	reg("PATCH /v1/admin/workspaces/{ws}/keys/{key}", a.patchKey)
	reg("DELETE /v1/admin/workspaces/{ws}/keys/{key}", a.deleteKey)
	reg("PUT /v1/admin/workspaces/{ws}/keys/{key}/tags", a.setKeyTags)
	reg("GET /v1/admin/workspaces/{ws}/keys/{key}/versions", a.keyVersions)
	reg("POST /v1/admin/workspaces/{ws}/keys/{key}/versions/{version}/activate", a.activateVersion)
	reg("PATCH /v1/admin/workspaces/{ws}/keys/{key}/versions/{version}", a.expireVersion)
	reg("GET /v1/admin/workspaces/{ws}/tags", a.tags)
	reg("POST /v1/admin/workspaces/{ws}/tags", a.createTag)
	reg("PATCH /v1/admin/workspaces/{ws}/tags/{tag}", a.renameTag)
	reg("DELETE /v1/admin/workspaces/{ws}/tags/{tag}", a.deleteTag)
	reg("GET /v1/admin/workspaces/{ws}/policies", a.policies)
	reg("POST /v1/admin/workspaces/{ws}/policies", a.putPolicy)
	reg("PATCH /v1/admin/workspaces/{ws}/policies/{policy}", a.patchPolicy)
	reg("GET /v1/admin/workspaces/{ws}/policies/{policy}/versions", a.policyVersions)
	reg("POST /v1/admin/workspaces/{ws}/policy-preview", a.previewPolicy)
	reg("GET /v1/admin/tokens", a.tokens)
	reg("POST /v1/admin/tokens", a.createToken)
	reg("DELETE /v1/admin/tokens/{token}", a.revokeToken)
	reg("GET /v1/admin/audit-events", a.auditEvents)
	reg("GET /v1/admin/notifications", a.notifications)
	reg("POST /v1/admin/notifications/test", a.testEmail)
	m.HandleFunc("POST /v1/runtime/github-actions/resolve", a.wrap(a.resolve))
	m.HandleFunc("/v1/", a.wrap(func(w http.ResponseWriter, r *http.Request) error { return notfound() }))
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			w.WriteHeader(405)
			return
		}
		if a.assets == nil {
			http.Error(w, "Build the web assets first", 503)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, e := fs.Stat(a.assets, path); e != nil {
			r = r.Clone(r.Context())
			r.URL.Path = "/index.html"
		}
		if r.URL.Path == "/index.html" {
			b, e := fs.ReadFile(a.assets, "index.html")
			if e != nil {
				http.Error(w, "UI unavailable", 503)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(b)
			return
		}
		http.FileServer(http.FS(a.assets)).ServeHTTP(w, r)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := a.now()
		rid := newID("req")
		r = r.WithContext(context.WithValue(r.Context(), requestContext, rid))
		w.Header().Set("X-Request-ID", rid)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			if recover() != nil {
				if sw.status == 0 {
					respond(sw, 500, map[string]any{"error": map[string]string{"code": "internal_error", "message": "request could not be completed"}, "request_id": rid})
				}
				a.logger.Error("request panic", "request_id", rid)
			}
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			a.logger.Info("http request", "request_id", rid, "method", r.Method, "route", route, "status", sw.status, "duration_ms", a.now().Sub(start).Milliseconds())
		}()
		m.ServeHTTP(sw, r)
	})
}

type limitEntry struct {
	Count int
	Until time.Time
}

func (a *App) rate(r *http.Request, bucket string, max int) error {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	key := bucket + ":" + ip
	a.limitsMu.Lock()
	defer a.limitsMu.Unlock()
	now := a.now()
	for k, v := range a.limits {
		if now.After(v.Until) {
			delete(a.limits, k)
		}
	}
	v := a.limits[key]
	if v.Count == 0 {
		v.Until = now.Add(time.Minute)
	}
	v.Count++
	a.limits[key] = v
	if v.Count > max || len(a.limits) > 10000 {
		return &apiError{429, "rate_limited", "too many requests"}
	}
	return nil
}
