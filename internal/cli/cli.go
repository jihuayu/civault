package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"civault/internal/vault"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type config struct {
	Server    string `json:"server"`
	Workspace string `json:"workspace"`
}
type client struct {
	config
	token       string
	idempotency string
	http        *http.Client
	in          io.Reader
	out         io.Writer
}

func (c *client) request(method, path string, body any) (json.RawMessage, error) {
	u, e := url.Parse(c.Server)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return nil, errors.New("set --server to the server origin")
	}
	ip := net.ParseIP(u.Hostname())
	local := u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, errors.New("HTTPS is required except for loopback")
	}
	var b []byte
	if body != nil {
		b, e = json.Marshal(body)
		if e != nil {
			return nil, e
		}
	}
	req, e := http.NewRequest(method, strings.TrimRight(c.Server, "/")+path, bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	if method == "POST" && strings.HasSuffix(path, "/keys") {
		id := c.idempotency
		if id == "" {
			id = fmt.Sprintf("cli-%d", time.Now().UnixNano())
		}
		req.Header.Set("Idempotency-Key", id)
	}
	resp, e := c.http.Do(req)
	if e != nil {
		return nil, errors.New("cannot reach server")
	}
	defer resp.Body.Close()
	data, e := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if e != nil {
		return nil, e
	}
	if resp.StatusCode >= 300 {
		var b struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(data, &b)
		return nil, fmt.Errorf("HTTP %d: %s %s", resp.StatusCode, b.Error.Code, b.Error.Message)
	}
	return data, nil
}
func (c *client) run(method, path string, body any) error {
	v, e := c.request(method, path, body)
	if e != nil {
		return e
	}
	var p bytes.Buffer
	if json.Indent(&p, v, "", "  ") == nil {
		_, e = fmt.Fprintln(c.out, p.String())
	} else {
		_, e = c.out.Write(v)
	}
	return e
}
func (c *client) base() string { return "/v1/admin/workspaces/" + url.PathEscape(c.Workspace) }
func (c *client) key(path string) (vault.Key, error) {
	var keys []vault.Key
	b, e := c.request("GET", c.base()+"/keys", nil)
	if e != nil {
		return vault.Key{}, e
	}
	if e = json.Unmarshal(b, &keys); e != nil {
		return vault.Key{}, e
	}
	for _, k := range keys {
		if k.Path == path || k.ID == path {
			return k, nil
		}
	}
	return vault.Key{}, errors.New("key not found")
}
func (c *client) keyBase(path string) (string, vault.Key, error) {
	k, e := c.key(path)
	return c.base() + "/keys/" + url.PathEscape(k.ID), k, e
}
func configFile() string {
	p, e := os.UserConfigDir()
	if e != nil {
		return ""
	}
	return filepath.Join(p, "civault", "config.json")
}
func New(in io.Reader, out, errOut io.Writer) *cobra.Command {
	c := &client{in: in, out: out, http: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if b, e := os.ReadFile(configFile()); e == nil {
		_ = json.Unmarshal(b, &c.config)
	}
	if c.Workspace == "" {
		c.Workspace = "ws_default"
	}
	var tokenStdin bool
	root := &cobra.Command{Use: "civault", Short: "CI 密钥管理 HTTP 客户端", SilenceUsage: true, PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		c.token = os.Getenv("CIVAULT_ADMIN_TOKEN")
		if tokenStdin {
			if v, _ := cmd.Flags().GetBool("stdin"); v {
				return errors.New("token and key value cannot both use stdin")
			}
			b, e := io.ReadAll(io.LimitReader(in, 4096))
			if e != nil {
				return e
			}
			c.token = strings.TrimSpace(string(b))
		}
		return nil
	}}
	root.SetIn(in)
	root.SetOut(out)
	root.SetErr(errOut)
	root.PersistentFlags().StringVar(&c.Server, "server", c.Server, "service URL")
	root.PersistentFlags().StringVar(&c.Workspace, "workspace", c.Workspace, "workspace ID")
	root.PersistentFlags().BoolVar(&tokenStdin, "token-stdin", false, "read admin token from stdin")
	root.AddCommand(&cobra.Command{Use: "config", Short: "保存服务地址和默认工作区（不保存令牌）", RunE: func(*cobra.Command, []string) error {
		p := configFile()
		if p == "" {
			return errors.New("cannot locate user config directory")
		}
		if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			return e
		}
		b, _ := json.MarshalIndent(c.config, "", "  ")
		return os.WriteFile(p, b, 0600)
	}})
	workspace := &cobra.Command{Use: "workspace", Short: "工作区管理"}
	workspace.AddCommand(&cobra.Command{Use: "list", RunE: func(*cobra.Command, []string) error { return c.run("GET", "/v1/admin/workspaces", nil) }}, &cobra.Command{Use: "create NAME", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return c.run("POST", "/v1/admin/workspaces", map[string]string{"name": args[0]})
	}})
	root.AddCommand(workspace)
	key := &cobra.Command{Use: "key", Short: "密钥和版本管理（不提供明文读取）"}
	root.AddCommand(key)
	key.AddCommand(&cobra.Command{Use: "list", RunE: func(*cobra.Command, []string) error { return c.run("GET", c.base()+"/keys", nil) }})
	var stdin bool
	var expiry string
	put := &cobra.Command{Use: "put PATH --stdin", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		if !stdin {
			return errors.New("key values must be supplied through --stdin")
		}
		value, e := io.ReadAll(io.LimitReader(in, 32769))
		if e != nil {
			return e
		}
		defer clear(value)
		if len(value) > 32768 {
			return errors.New("key value exceeds 32 KiB")
		}
		return c.run("POST", c.base()+"/keys", map[string]any{"path": args[0], "value": string(value), "expires_at": nullable(expiry)})
	}}
	put.Flags().BoolVar(&stdin, "stdin", false, "read value without changing whitespace")
	put.Flags().StringVar(&expiry, "expires-at", "", "RFC3339 expiry")
	put.Flags().StringVar(&c.idempotency, "idempotency-key", "", "reuse this identifier when retrying the same version write (24h)")
	key.AddCommand(put)
	for _, name := range []string{"disable", "enable", "delete", "versions"} {
		name := name
		key.AddCommand(&cobra.Command{Use: name + " PATH", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
			p, _, e := c.keyBase(args[0])
			if e != nil {
				return e
			}
			switch name {
			case "delete":
				return c.run("DELETE", p, nil)
			case "versions":
				return c.run("GET", p+"/versions", nil)
			default:
				return c.run("PATCH", p, map[string]bool{"disabled": name == "disable"})
			}
		}})
	}
	var at string
	var clearExpiry bool
	exp := &cobra.Command{Use: "expiry PATH", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		if (at == "") == !clearExpiry {
			return errors.New("use --at TIMESTAMP or --clear")
		}
		p, k, e := c.keyBase(args[0])
		if e != nil {
			return e
		}
		if k.ActiveVersionID == nil {
			return errors.New("key has no active version")
		}
		return c.run("PATCH", p+"/versions/"+*k.ActiveVersionID, map[string]any{"expires_at": nullable(at)})
	}}
	exp.Flags().StringVar(&at, "at", "", "RFC3339 expiry")
	exp.Flags().BoolVar(&clearExpiry, "clear", false, "remove expiry")
	key.AddCommand(exp)
	key.AddCommand(&cobra.Command{Use: "activate PATH VERSION", Args: cobra.ExactArgs(2), RunE: func(_ *cobra.Command, args []string) error {
		p, _, e := c.keyBase(args[0])
		if e != nil {
			return e
		}
		b, e := c.request("GET", p+"/versions", nil)
		if e != nil {
			return e
		}
		var versions []struct {
			ID     string `json:"id"`
			Number int    `json:"number"`
		}
		if e = json.Unmarshal(b, &versions); e != nil {
			return e
		}
		for _, v := range versions {
			if v.ID == args[1] || strconv.Itoa(v.Number) == args[1] {
				return c.run("POST", p+"/versions/"+v.ID+"/activate", nil)
			}
		}
		return errors.New("version not found")
	}})
	tag := &cobra.Command{Use: "tag", Short: "标签管理"}
	root.AddCommand(tag)
	tag.AddCommand(&cobra.Command{Use: "list", RunE: func(*cobra.Command, []string) error { return c.run("GET", c.base()+"/tags", nil) }}, &cobra.Command{Use: "create NAME", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return c.run("POST", c.base()+"/tags", map[string]string{"name": args[0]})
	}}, &cobra.Command{Use: "rename ID NAME", Args: cobra.ExactArgs(2), RunE: func(_ *cobra.Command, args []string) error {
		return c.run("PATCH", c.base()+"/tags/"+url.PathEscape(args[0]), map[string]string{"name": args[1]})
	}}, &cobra.Command{Use: "delete ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return c.run("DELETE", c.base()+"/tags/"+url.PathEscape(args[0]), nil)
	}})
	kt := &cobra.Command{Use: "tag"}
	key.AddCommand(kt)
	for _, mode := range []string{"add", "remove"} {
		mode := mode
		kt.AddCommand(&cobra.Command{Use: mode + " PATH TAG...", Args: cobra.MinimumNArgs(2), RunE: func(_ *cobra.Command, args []string) error {
			p, k, e := c.keyBase(args[0])
			if e != nil {
				return e
			}
			b, e := c.request("GET", c.base()+"/tags", nil)
			if e != nil {
				return e
			}
			var tags []vault.Tag
			if e = json.Unmarshal(b, &tags); e != nil {
				return e
			}
			selected := map[string]bool{}
			for _, t := range k.Tags {
				selected[t.ID] = true
			}
			for _, name := range args[1:] {
				id := ""
				for _, t := range tags {
					if t.ID == name || t.Name == name {
						id = t.ID
						break
					}
				}
				if id == "" && mode == "add" {
					b, e = c.request("POST", c.base()+"/tags", map[string]string{"name": name})
					if e != nil {
						return e
					}
					var t vault.Tag
					if e = json.Unmarshal(b, &t); e != nil {
						return e
					}
					id = t.ID
				}
				if mode == "add" {
					selected[id] = true
				} else {
					delete(selected, id)
				}
			}
			ids := []string{}
			for id := range selected {
				ids = append(ids, id)
			}
			return c.run("PUT", p+"/tags", map[string]any{"tag_ids": ids})
		}})
	}
	policy := &cobra.Command{Use: "policy", Short: "授权规则管理"}
	root.AddCommand(policy)
	policy.AddCommand(&cobra.Command{Use: "list", RunE: func(*cobra.Command, []string) error { return c.run("GET", c.base()+"/policies", nil) }})
	var policyFile string
	apply := &cobra.Command{Use: "apply --file policy.yaml", RunE: func(*cobra.Command, []string) error {
		f, e := os.Open(policyFile)
		if e != nil {
			return e
		}
		defer f.Close()
		var p vault.PolicyInput
		d := yaml.NewDecoder(io.LimitReader(f, 65537))
		d.KnownFields(true)
		if e = d.Decode(&p); e != nil {
			return e
		}
		if d.Decode(new(any)) != io.EOF {
			return errors.New("provide one policy document")
		}
		return c.run("POST", c.base()+"/policies", p)
	}}
	apply.Flags().StringVar(&policyFile, "file", "", "YAML or JSON policy file")
	_ = apply.MarkFlagRequired("file")
	policy.AddCommand(apply)
	for _, mode := range []string{"disable", "enable"} {
		mode := mode
		policy.AddCommand(&cobra.Command{Use: mode + " ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
			return c.run("PATCH", c.base()+"/policies/"+url.PathEscape(args[0]), map[string]bool{"disabled": mode == "disable"})
		}})
	}
	settings := &cobra.Command{Use: "settings"}
	root.AddCommand(settings)
	settings.AddCommand(&cobra.Command{Use: "get", RunE: func(*cobra.Command, []string) error { return c.run("GET", "/v1/admin/settings", nil) }})
	var settingsFile string
	sa := &cobra.Command{Use: "apply --file settings.json", RunE: func(*cobra.Command, []string) error {
		b, e := os.ReadFile(settingsFile)
		if e != nil {
			return e
		}
		var v map[string]any
		if e = json.Unmarshal(b, &v); e != nil {
			return e
		}
		for _, k := range []string{"github_id", "github_secret_configured", "resend_key_configured"} {
			delete(v, k)
		}
		return c.run("PUT", "/v1/admin/settings", v)
	}}
	sa.Flags().StringVar(&settingsFile, "file", "", "settings JSON, including revision")
	_ = sa.MarkFlagRequired("file")
	settings.AddCommand(sa)
	audit := &cobra.Command{Use: "audit"}
	root.AddCommand(audit)
	params := map[string]*string{}
	var limit, offset int
	al := &cobra.Command{Use: "list", RunE: func(*cobra.Command, []string) error {
		q := url.Values{"limit": {strconv.Itoa(limit)}, "offset": {strconv.Itoa(offset)}}
		for k, p := range params {
			if *p != "" {
				q.Set(strings.ReplaceAll(k, "-", "_"), *p)
			}
		}
		return c.run("GET", "/v1/admin/audit-events?"+q.Encode(), nil)
	}}
	for _, name := range []string{"decision", "event", "repository-id", "workspace-id", "request-id", "from", "to"} {
		params[name] = al.Flags().String(name, "", "filter "+name)
	}
	al.Flags().IntVar(&limit, "limit", 100, "maximum rows (1000)")
	al.Flags().IntVar(&offset, "offset", 0, "pagination offset")
	audit.AddCommand(al)
	export := &cobra.Command{Use: "export", Short: "导出全部匹配审计记录为 JSON", RunE: func(*cobra.Command, []string) error {
		q := url.Values{"limit": {"1000"}}
		for name, value := range params {
			if *value != "" {
				q.Set(strings.ReplaceAll(name, "-", "_"), *value)
			}
		}
		if q.Get("to") == "" {
			q.Set("to", time.Now().UTC().Format(time.RFC3339))
		}
		all := []json.RawMessage{}
		for offset := 0; ; offset += 1000 {
			if offset > 1000000 {
				return errors.New("export exceeds pagination limit; narrow the time range")
			}
			q.Set("offset", strconv.Itoa(offset))
			data, e := c.request("GET", "/v1/admin/audit-events?"+q.Encode(), nil)
			if e != nil {
				return e
			}
			var page []json.RawMessage
			if e := json.Unmarshal(data, &page); e != nil {
				return e
			}
			all = append(all, page...)
			if len(page) < 1000 {
				break
			}
		}
		encoder := json.NewEncoder(c.out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(all)
	}}
	for name, value := range params {
		export.Flags().StringVar(value, name, "", "filter "+name)
	}
	audit.AddCommand(export)
	notify := &cobra.Command{Use: "notifications"}
	root.AddCommand(notify)
	notify.AddCommand(&cobra.Command{Use: "list", RunE: func(*cobra.Command, []string) error { return c.run("GET", "/v1/admin/notifications", nil) }}, &cobra.Command{Use: "test", Short: "发送测试邮件到 Owner", RunE: func(*cobra.Command, []string) error {
		return c.run("POST", "/v1/admin/notifications/test", map[string]any{})
	}})
	tokens := &cobra.Command{Use: "token"}
	root.AddCommand(tokens)
	tokens.AddCommand(&cobra.Command{Use: "list", RunE: func(*cobra.Command, []string) error { return c.run("GET", "/v1/admin/tokens", nil) }}, &cobra.Command{Use: "create NAME", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return c.run("POST", "/v1/admin/tokens", map[string]any{"name": args[0], "days": 30})
	}}, &cobra.Command{Use: "revoke ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return c.run("DELETE", "/v1/admin/tokens/"+url.PathEscape(args[0]), nil)
	}})
	return root
}
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
