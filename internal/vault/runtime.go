package vault

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

func (a *App) resolve(w http.ResponseWriter, r *http.Request) error {
	if e := a.rate(r, "resolve", 120); e != nil {
		return e
	}
	var in ResolveRequest
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if in.WorkspaceID == "" || len(in.References) == 0 || len(in.References) > 32 {
		return bad("provide a workspace and 1–32 key references")
	}
	paths := map[string]string{}
	seen := map[string]bool{}
	for name, ref := range in.References {
		if !validEnv(name) || seen[strings.ToUpper(name)] {
			return bad("invalid, reserved, or case-colliding environment variable")
		}
		seen[strings.ToUpper(name)] = true
		u, e := url.Parse(ref)
		if e != nil || u.Scheme != "cv" || u.Host != in.WorkspaceID || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/") || !validPath(strings.TrimPrefix(u.Path, "/")) {
			return bad("invalid or cross-workspace key reference")
		}
		paths[name] = strings.TrimPrefix(u.Path, "/")
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		if er := a.audit(r.Context(), a.db, "runtime.resolve", "deny", "", map[string]string{"reason": "missing_oidc"}); er != nil {
			return er
		}
		return unauthorized()
	}
	c, e := a.oidc.verify(r.Context(), strings.TrimPrefix(auth, "Bearer "), in.WorkspaceID)
	if e != nil {
		if er := a.audit(r.Context(), a.db, "runtime.resolve", "deny", "", map[string]string{"reason": "invalid_oidc"}); er != nil {
			return er
		}
		return e
	}
	ctx := context.WithValue(r.Context(), actorContext, "github:"+c.RepositoryID)
	requestHash := a.box.MAC("resolve-request", []byte(jsonText(in)))
	jti := a.box.MAC("oidc-replay", []byte(c.ID))
	values := map[string]string{}
	auditVersions := map[string]string{}
	matches := map[string][]map[string]any{}
	e = a.transaction(ctx, func(tx *sql.Tx) error {
		var n int
		if e := tx.QueryRowContext(ctx, "SELECT 1 FROM workspaces WHERE id=?", in.WorkspaceID).Scan(&n); e != nil {
			return denied()
		}
		policies, e := readPolicies(ctx, tx, in.WorkspaceID)
		if e != nil {
			return e
		}
		keys, e := getKeys(ctx, tx, in.WorkspaceID)
		if e != nil {
			return e
		}
		byPath := map[string]Key{}
		for _, k := range keys {
			byPath[k.Path] = k
		}
		pinned := map[string]string{}
		var oldHash, oldVersions string
		var first int64
		var attempts int
		retry := false
		e = tx.QueryRowContext(ctx, "SELECT request_hash,versions,first_at,attempts FROM oidc_requests WHERE jti_hash=?", jti).Scan(&oldHash, &oldVersions, &first, &attempts)
		if e == nil {
			retry = true
			if oldHash != requestHash || attempts >= 3 || a.now().Unix()-first > 60 {
				return &apiError{409, "replay_rejected", "OIDC token already used or retry window closed"}
			}
			if e = json.Unmarshal([]byte(oldVersions), &pinned); e != nil {
				return e
			}
		} else if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		names := make([]string, 0, len(paths))
		for name := range paths {
			names = append(names, name)
		}
		slices.Sort(names)
		total := 0
		for _, name := range names {
			k, ok := byPath[paths[name]]
			if !ok || k.Disabled || k.ActiveVersionID == nil || k.ExpiresAt != nil && *k.ExpiresAt <= a.now().Unix() {
				return denied()
			}
			matched := []map[string]any{}
			for _, p := range policies {
				if !p.Disabled && targetMatches(p.Rule, k) && claimsMatch(p.Rule, c) {
					matched = append(matched, map[string]any{"id": p.ID, "version": p.Version})
				}
			}
			if len(matched) == 0 {
				return denied()
			}
			version := *k.ActiveVersionID
			if retry {
				version = pinned[k.ID]
				if version == "" {
					return denied()
				}
			}
			var blob []byte
			var expiry *int64
			if e := tx.QueryRowContext(ctx, "SELECT encrypted,expires_at FROM key_versions WHERE workspace_id=? AND key_id=? AND id=?", in.WorkspaceID, k.ID, version).Scan(&blob, &expiry); e != nil {
				return e
			}
			if expiry != nil && *expiry <= a.now().Unix() {
				return denied()
			}
			plain, e := a.box.Open(blob, "key", in.WorkspaceID, k.ID, version)
			if e != nil {
				return e
			}
			total += len(plain)
			if total > 256<<10 {
				clear(plain)
				return bad("resolved values exceed 256 KiB")
			}
			values[name] = string(plain)
			clear(plain)
			auditVersions[k.ID] = version
			matches[k.ID] = matched
		}
		if retry {
			if _, e = tx.ExecContext(ctx, "UPDATE oidc_requests SET attempts=attempts+1 WHERE jti_hash=?", jti); e != nil {
				return e
			}
		} else {
			if _, e = tx.ExecContext(ctx, "INSERT INTO oidc_requests(jti_hash,request_hash,versions,first_at,attempts,expires_at) VALUES(?,?,?,?,1,?)", jti, requestHash, jsonText(auditVersions), a.now().Unix(), c.ExpiresAt.Unix()+30); e != nil {
				return e
			}
		}
		return a.audit(ctx, tx, "runtime.resolve", "allow", in.WorkspaceID, map[string]any{"repository_id": c.RepositoryID, "repository_owner_id": c.OwnerID, "repository": c.Repository, "run_id": c.RunID, "run_attempt": c.RunAttempt, "workflow_ref": c.WorkflowRef, "workflow_sha": c.WorkflowSHA, "ref": c.Ref, "environment": c.Environment, "versions": auditVersions, "policies": matches, "jti_hash": jti})
	})
	if e != nil {
		clear(values)
		reason := "unavailable"
		var ae *apiError
		if errors.As(e, &ae) {
			reason = ae.code
		}
		if auditErr := a.audit(ctx, a.db, "runtime.resolve", "deny", in.WorkspaceID, map[string]string{"reason": reason, "repository_id": c.RepositoryID, "run_id": c.RunID, "workflow_ref": c.WorkflowRef, "jti_hash": jti}); auditErr != nil {
			return auditErr
		}
		return e
	}
	defer clear(values)
	rid, _ := r.Context().Value(requestContext).(string)
	respond(w, 200, ResolveResponse{RequestID: rid, Values: values})
	return nil
}
