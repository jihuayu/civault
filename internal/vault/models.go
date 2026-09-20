package vault

import (
	"encoding/json"
	"errors"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

type Settings struct {
	PublicURL          string `json:"public_url"`
	OwnerEmail         string `json:"owner_email"`
	GithubEnabled      bool   `json:"github_enabled"`
	GithubClientID     string `json:"github_client_id"`
	ResendEnabled      bool   `json:"resend_enabled"`
	ResendFrom         string `json:"resend_from"`
	ReminderDays       []int  `json:"reminder_days"`
	NotifyOnExpiry     bool   `json:"notify_on_expiry"`
	LogLevel           string `json:"log_level"`
	AuditRetentionDays int    `json:"audit_retention_days"`
}
type SettingsView struct {
	Settings
	Revision               int    `json:"revision"`
	GithubSecretConfigured bool   `json:"github_secret_configured"`
	ResendKeyConfigured    bool   `json:"resend_key_configured"`
	GithubID               string `json:"github_id"`
}
type SettingsUpdate struct {
	Settings
	Revision          int     `json:"revision"`
	GithubSecret      *string `json:"github_secret,omitempty"`
	ResendKey         *string `json:"resend_key,omitempty"`
	ClearGithubSecret bool    `json:"clear_github_secret"`
	ClearResendKey    bool    `json:"clear_resend_key"`
}
type Rule struct {
	KeyIDs       []string `json:"key_ids,omitempty" yaml:"key_ids,omitempty"`
	TagIDs       []string `json:"tag_ids,omitempty" yaml:"tag_ids,omitempty"`
	OwnerID      string   `json:"repository_owner_id" yaml:"repository_owner_id"`
	RepositoryID string   `json:"repository_id,omitempty" yaml:"repository_id,omitempty"`
	WorkflowPath string   `json:"workflow_path,omitempty" yaml:"workflow_path,omitempty"`
	WorkflowSHA  string   `json:"workflow_sha,omitempty" yaml:"workflow_sha,omitempty"`
	Refs         []string `json:"refs,omitempty" yaml:"refs,omitempty"`
	Environments []string `json:"environments,omitempty" yaml:"environments,omitempty"`
	Events       []string `json:"events,omitempty" yaml:"events,omitempty"`
	Runners      []string `json:"runner_environments,omitempty" yaml:"runner_environments,omitempty"`
}
type PolicyInput struct {
	Name string `json:"name" yaml:"name"`
	Rule Rule   `json:"rule" yaml:"rule"`
}
type Key struct {
	ID              string  `json:"id"`
	WorkspaceID     string  `json:"workspace_id"`
	Path            string  `json:"path"`
	ActiveVersionID *string `json:"active_version_id"`
	Disabled        bool    `json:"disabled"`
	CreatedAt       int64   `json:"created_at"`
	Tags            []Tag   `json:"tags"`
	ExpiresAt       *int64  `json:"expires_at"`
	Version         int     `json:"version"`
}
type Tag struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Policy struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Version  int    `json:"version"`
	Disabled bool   `json:"disabled"`
	Rule     Rule   `json:"rule"`
}
type ResolveRequest struct {
	WorkspaceID string            `json:"workspace_id"`
	References  map[string]string `json:"references"`
}
type ResolveResponse struct {
	RequestID string            `json:"request_id"`
	Values    map[string]string `json:"values"`
}

var digits = regexp.MustCompile(`^[0-9]+$`)
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var shaPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

func validName(s string) bool {
	return s != "" && len(s) <= 200 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}
func validPath(s string) bool {
	if !validName(s) || strings.HasPrefix(s, "/") || strings.ContainsAny(s, "?#\\") {
		return false
	}
	for _, p := range strings.Split(s, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return true
}
func validEnv(s string) bool {
	u := strings.ToUpper(s)
	return len(s) <= 200 && envName.MatchString(s) && !strings.HasPrefix(u, "GITHUB_") && !strings.HasPrefix(u, "RUNNER_") && !strings.HasPrefix(u, "ACTIONS_") && !slices.Contains([]string{"__PROTO__", "CONSTRUCTOR", "PROTOTYPE", "NODE_OPTIONS", "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "ENV", "COMSPEC", "SHELLOPTS"}, u)
}
func validateSettings(s Settings) error {
	u, e := url.Parse(s.PublicURL)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return errors.New("public_url must be an HTTPS origin (HTTP is allowed on loopback only)")
	}
	a, e := mail.ParseAddress(s.OwnerEmail)
	if e != nil || a.Address != s.OwnerEmail {
		return errors.New("invalid owner email")
	}
	if s.ResendFrom != "" {
		if _, e := mail.ParseAddress(s.ResendFrom); e != nil {
			return errors.New("invalid sender address")
		}
	}
	if !slices.Contains([]string{"debug", "info", "warn", "error"}, s.LogLevel) || s.AuditRetentionDays < 1 || s.AuditRetentionDays > 3650 {
		return errors.New("invalid log settings")
	}
	if len(s.ReminderDays) > 12 {
		return errors.New("too many reminder thresholds")
	}
	seen := map[int]bool{}
	for _, d := range s.ReminderDays {
		if d < 1 || d > 365 || seen[d] {
			return errors.New("reminder days must be unique integers between 1 and 365")
		}
		seen[d] = true
	}
	return nil
}
func validateRule(r Rule) error {
	if (len(r.KeyIDs) == 0) == (len(r.TagIDs) == 0) || len(r.KeyIDs)+len(r.TagIDs) > 100 {
		return errors.New("select either key_ids or tag_ids, with 1–100 targets")
	}
	if !digits.MatchString(r.OwnerID) || r.RepositoryID != "" && !digits.MatchString(r.RepositoryID) {
		return errors.New("GitHub owner and repository IDs must be numeric")
	}
	if r.WorkflowPath != "" && (!strings.HasPrefix(r.WorkflowPath, ".github/workflows/") || !validPath(r.WorkflowPath) || r.RepositoryID == "" || !(strings.HasSuffix(r.WorkflowPath, ".yml") || strings.HasSuffix(r.WorkflowPath, ".yaml"))) {
		return errors.New("workflow_path requires a repository and an exact workflow YAML path")
	}
	if r.WorkflowSHA != "" && !shaPattern.MatchString(r.WorkflowSHA) {
		return errors.New("workflow_sha must be a full commit SHA")
	}
	for _, a := range [][]string{r.KeyIDs, r.TagIDs, r.Refs, r.Environments, r.Events, r.Runners} {
		seen := map[string]bool{}
		for _, v := range a {
			if !validName(v) || seen[v] || strings.Contains(v, "*") {
				return errors.New("rule values must be distinct exact values")
			}
			seen[v] = true
		}
	}
	for _, v := range r.Runners {
		if v != "github-hosted" && v != "self-hosted" {
			return errors.New("invalid runner environment")
		}
	}
	return nil
}
func jsonText(v any) string { b, _ := json.Marshal(v); return string(b) }
