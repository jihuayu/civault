package vault

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
)

func readPolicies(ctx context.Context, q queryer, ws string) ([]Policy, error) {
	rows, e := q.QueryContext(ctx, "SELECT p.id,p.name,p.active_version,p.disabled,v.spec FROM policies p JOIN policy_versions v ON v.policy_id=p.id AND v.version=p.active_version WHERE p.workspace_id=? ORDER BY p.name", ws)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Policy{}
	for rows.Next() {
		var p Policy
		var data string
		if e = rows.Scan(&p.ID, &p.Name, &p.Version, &p.Disabled, &data); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(data), &p.Rule); e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (a *App) policies(w http.ResponseWriter, r *http.Request) error {
	v, e := readPolicies(r.Context(), a.db, r.PathValue("ws"))
	if e != nil {
		return e
	}
	respond(w, 200, v)
	return nil
}
func (a *App) putPolicy(w http.ResponseWriter, r *http.Request) error {
	var in PolicyInput
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if !validName(in.Name) {
		return bad("invalid policy name")
	}
	if e := validateRule(in.Rule); e != nil {
		return bad(e.Error())
	}
	ws, id, version := r.PathValue("ws"), newID("pol"), 1
	e := a.transaction(r.Context(), func(tx *sql.Tx) error {
		for _, key := range in.Rule.KeyIDs {
			if e := keyExists(r.Context(), tx, ws, key); e != nil {
				return bad("key target is outside workspace or does not exist")
			}
		}
		var currentID string
		var current int
		e := tx.QueryRowContext(r.Context(), "SELECT id,active_version FROM policies WHERE workspace_id=? AND name=?", ws, in.Name).Scan(&currentID, &current)
		if e == nil {
			id = currentID
			version = current + 1
			if _, e = tx.ExecContext(r.Context(), "UPDATE policies SET active_version=? WHERE id=?", version, id); e != nil {
				return e
			}
		} else if errors.Is(e, sql.ErrNoRows) {
			if _, e = tx.ExecContext(r.Context(), "INSERT INTO policies(id,workspace_id,name,active_version) VALUES(?,?,?,?)", id, ws, in.Name, version); e != nil {
				return e
			}
		} else {
			return e
		}
		if _, e = tx.ExecContext(r.Context(), "INSERT INTO policy_versions(policy_id,version,spec,created_at) VALUES(?,?,?,?)", id, version, jsonText(in.Rule), a.now().Unix()); e != nil {
			return e
		}
		for _, key := range in.Rule.KeyIDs {
			if _, e = tx.ExecContext(r.Context(), "INSERT INTO policy_key_targets(workspace_id,policy_id,version,key_id) VALUES(?,?,?,?)", ws, id, version, key); e != nil {
				return e
			}
		}
		for _, tag := range in.Rule.TagIDs {
			if _, e = tx.ExecContext(r.Context(), "INSERT INTO policy_tag_targets(workspace_id,policy_id,version,tag_id) VALUES(?,?,?,?)", ws, id, version, tag); e != nil {
				return e
			}
		}
		return a.audit(r.Context(), tx, "policy.version_created", "allow", ws, map[string]any{"policy_id": id, "version": version, "rule": in.Rule})
	})
	if e != nil {
		return e
	}
	respond(w, 201, map[string]any{"id": id, "version": version})
	return nil
}
func (a *App) patchPolicy(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Disabled *bool `json:"disabled"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if in.Disabled == nil {
		return bad("disabled is required")
	}
	ws, id := r.PathValue("ws"), r.PathValue("policy")
	e := a.transaction(r.Context(), func(tx *sql.Tx) error {
		res, e := tx.ExecContext(r.Context(), "UPDATE policies SET disabled=? WHERE workspace_id=? AND id=?", in.Disabled, ws, id)
		if e = affected(res, e); e != nil {
			return e
		}
		return a.audit(r.Context(), tx, "policy.state_changed", "allow", ws, map[string]any{"policy_id": id, "disabled": in.Disabled})
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) policyVersions(w http.ResponseWriter, r *http.Request) error {
	return a.listJSON(w, r, "SELECT v.version,v.spec,v.created_at FROM policy_versions v JOIN policies p ON p.id=v.policy_id WHERE p.workspace_id=? AND p.id=? ORDER BY v.version DESC", []any{r.PathValue("ws"), r.PathValue("policy")})
}
func targetMatches(rule Rule, k Key) bool {
	if slices.Contains(rule.KeyIDs, k.ID) {
		return true
	}
	for _, tag := range k.Tags {
		if slices.Contains(rule.TagIDs, tag.ID) {
			return true
		}
	}
	return false
}
func claimsMatch(rule Rule, c *githubClaims) bool {
	if rule.OwnerID != c.OwnerID || rule.RepositoryID != "" && rule.RepositoryID != c.RepositoryID {
		return false
	}
	if rule.WorkflowPath != "" {
		prefix := c.Repository + "/" + rule.WorkflowPath + "@"
		if !strings.HasPrefix(c.WorkflowRef, prefix) || len(c.WorkflowRef) <= len(prefix) {
			return false
		}
	}
	if rule.WorkflowSHA != "" && rule.WorkflowSHA != c.WorkflowSHA {
		return false
	}
	for _, x := range []struct {
		allowed []string
		value   string
	}{{rule.Refs, c.Ref}, {rule.Environments, c.Environment}, {rule.Events, c.Event}, {rule.Runners, c.Runner}} {
		if len(x.allowed) > 0 && !slices.Contains(x.allowed, x.value) {
			return false
		}
	}
	return true
}
func (a *App) previewPolicy(w http.ResponseWriter, r *http.Request) error {
	var rule Rule
	if e := decode(w, r, &rule); e != nil {
		return e
	}
	if e := validateRule(rule); e != nil {
		return bad(e.Error())
	}
	keys, e := getKeys(r.Context(), a.db, r.PathValue("ws"))
	if e != nil {
		return e
	}
	out := []Key{}
	for _, key := range keys {
		if targetMatches(rule, key) {
			out = append(out, key)
		}
	}
	respond(w, 200, out)
	return nil
}
