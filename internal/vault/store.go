package vault

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"civault/internal/cryptobox"
	_ "modernc.org/sqlite"
)

//go:embed migrations/001_init.sql
var schema string

//go:embed migrations/002_email_providers.sql
var emailProviderSchema string

type App struct {
	db         *sql.DB
	box        *cryptobox.Box
	dataDir    string
	now        func() time.Time
	client     *http.Client
	logger     *slog.Logger
	level      *slog.LevelVar
	oidc       *githubVerifier
	assets     fs.FS
	limitsMu   sync.Mutex
	limits     map[string]limitEntry
	workerMu   sync.Mutex
	settingsMu sync.Mutex
}
type queryer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func Open(dataDir, master string, assets fs.FS, logOutput io.Writer) (*App, error) {
	box, e := cryptobox.New(master)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(dataDir, 0700); e != nil {
		return nil, e
	}
	abs, e := filepath.Abs(filepath.Join(dataDir, "civault.db"))
	if e != nil {
		return nil, e
	}
	uriPath := filepath.ToSlash(abs)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	q := u.Query()
	for _, p := range []string{"foreign_keys(1)", "journal_mode(WAL)", "synchronous(FULL)", "busy_timeout(5000)"} {
		q.Add("_pragma", p)
	}
	q.Set("_txlock", "immediate")
	u.RawQuery = q.Encode()
	db, e := sql.Open("sqlite", u.String())
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ok := false
	defer func() {
		if !ok {
			db.Close()
		}
	}()
	var hasMigrations int
	if e = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'").Scan(&hasMigrations); e != nil {
		return nil, e
	}
	if hasMigrations != 0 {
		var current int
		if e = db.QueryRow("SELECT COALESCE(max(version),0) FROM schema_migrations").Scan(&current); e != nil {
			return nil, e
		}
		if current > 2 {
			return nil, errors.New("database schema is newer than this server; refusing downgrade")
		}
	}
	tx, e := db.Begin()
	if e != nil {
		return nil, e
	}
	if _, e = tx.Exec(schema); e != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("database migration failed: %w", e)
	}
	var current int
	if e = tx.QueryRow("SELECT COALESCE(max(version),0) FROM schema_migrations").Scan(&current); e != nil {
		_ = tx.Rollback()
		return nil, e
	}
	if current < 2 {
		if _, e = tx.Exec(emailProviderSchema); e != nil {
			_ = tx.Rollback()
			return nil, fmt.Errorf("email provider migration failed: %w", e)
		}
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	var migration int
	if e = db.QueryRow("SELECT max(version) FROM schema_migrations").Scan(&migration); e != nil || migration != 2 {
		return nil, errors.New("unsupported database schema")
	}
	_ = os.Chmod(abs, 0600)
	var check []byte
	e = db.QueryRow("SELECT value FROM metadata WHERE name='master_check'").Scan(&check)
	if errors.Is(e, sql.ErrNoRows) {
		check, e = box.Seal([]byte("civault master key check v1"), "system", "master_check", "1")
		if e == nil {
			_, e = db.Exec("INSERT INTO metadata(name,value) VALUES('master_check',?)", check)
		}
	} else if e == nil {
		var plain []byte
		plain, e = box.Open(check, "system", "master_check", "1")
		if e == nil && string(plain) != "civault master key check v1" {
			e = errors.New("invalid master check")
		}
		clear(plain)
	}
	if e != nil {
		return nil, errors.New("master key does not match database or database is unreadable")
	}
	level := new(slog.LevelVar)
	a := &App{db: db, box: box, dataDir: dataDir, now: time.Now, client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, level: level, logger: slog.New(slog.NewJSONHandler(logOutput, &slog.HandlerOptions{Level: level})), assets: assets, limits: map[string]limitEntry{}}
	a.oidc = newGithubVerifier(a.client, a.now)
	if !a.initialized(context.Background()) {
		p := filepath.Join(dataDir, "setup-token")
		if _, e = os.Stat(p); errors.Is(e, os.ErrNotExist) {
			e = os.WriteFile(p, []byte(randomToken()), 0600)
		}
		if e != nil {
			return nil, e
		}
	} else {
		_ = os.Remove(filepath.Join(dataDir, "setup-token"))
		if v, e := a.settings(context.Background(), db); e == nil {
			a.setLevel(v.LogLevel)
		}
	}
	ok = true
	return a, nil
}
func (a *App) Close() error { return a.db.Close() }
func randomToken() string {
	v := make([]byte, 32)
	if _, e := rand.Read(v); e != nil {
		panic("system random source unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(v)
}
func newID(prefix string) string {
	v := make([]byte, 16)
	if _, e := rand.Read(v); e != nil {
		panic("system random source unavailable")
	}
	return prefix + "_" + hex.EncodeToString(v)
}
func digest(s string) string { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }
func (a *App) initialized(ctx context.Context) bool {
	var n int
	return a.db.QueryRowContext(ctx, "SELECT count(*) FROM owner").Scan(&n) == nil && n == 1
}
func (a *App) settings(ctx context.Context, q queryer) (SettingsView, error) {
	var v SettingsView
	var data string
	e := q.QueryRowContext(ctx, "SELECT s.revision,s.data,s.github_secret IS NOT NULL,s.resend_key IS NOT NULL,s.agentmail_key IS NOT NULL,o.github_id FROM settings s JOIN owner o ON o.id=s.id WHERE s.id=1").Scan(&v.Revision, &data, &v.GithubSecretConfigured, &v.ResendKeyConfigured, &v.AgentMailKeyConfigured, &v.GithubID)
	if e != nil {
		return v, e
	}
	e = json.Unmarshal([]byte(data), &v.Settings)
	v.EmailProvider = v.emailProvider()
	return v, e
}
func (a *App) configSecret(ctx context.Context, q queryer, name string) (string, error) {
	if name != "github_secret" && name != "resend_key" && name != "agentmail_key" {
		return "", errors.New("unknown secret field")
	}
	var b []byte
	var revision int
	e := q.QueryRowContext(ctx, "SELECT "+name+","+name+"_revision FROM settings WHERE id=1").Scan(&b, &revision)
	if e != nil {
		return "", e
	}
	if b == nil {
		return "", nil
	}
	v, e := a.box.Open(b, "settings", name, strconv.Itoa(revision))
	defer clear(v)
	return string(v), e
}
func (a *App) setLevel(s string) {
	var l slog.Level
	if l.UnmarshalText([]byte(s)) == nil {
		a.level.Set(l)
	}
}
func (a *App) transaction(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, e := a.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = fn(tx); e != nil {
		return e
	}
	return tx.Commit()
}
func (a *App) audit(ctx context.Context, q queryer, event, decision, workspace string, details any) error {
	actor, _ := ctx.Value(actorContext).(string)
	if actor == "" {
		actor = "anonymous"
	}
	rid, _ := ctx.Value(requestContext).(string)
	_, e := q.ExecContext(ctx, "INSERT INTO audit_events(id,created_at,request_id,actor,event,decision,workspace_id,details) VALUES(?,?,?,?,?,?,?,?)", newID("aud"), a.now().Unix(), rid, actor, event, decision, workspace, jsonText(details))
	return e
}

// Backup uses SQLite's consistent snapshot mechanism, not a live copy of .db alone.
func (a *App) Backup(ctx context.Context, destination string) error {
	_, e := a.db.ExecContext(ctx, "VACUUM INTO ?", destination)
	return e
}
