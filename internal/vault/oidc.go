package vault

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const githubIssuer = "https://token.actions.githubusercontent.com"
const githubJWKS = githubIssuer + "/.well-known/jwks"

type githubClaims struct {
	jwt.RegisteredClaims
	OwnerID      string `json:"repository_owner_id"`
	RepositoryID string `json:"repository_id"`
	Repository   string `json:"repository"`
	Ref          string `json:"ref"`
	Environment  string `json:"environment"`
	Event        string `json:"event_name"`
	Runner       string `json:"runner_environment"`
	WorkflowRef  string `json:"workflow_ref"`
	WorkflowSHA  string `json:"workflow_sha"`
	RunID        string `json:"run_id"`
	RunAttempt   string `json:"run_attempt"`
}
type githubVerifier struct {
	mu                   sync.Mutex
	client               *http.Client
	now                  func() time.Time
	keys                 map[string]*rsa.PublicKey
	fetched, lastAttempt time.Time
}

func newGithubVerifier(c *http.Client, now func() time.Time) *githubVerifier {
	return &githubVerifier{client: c, now: now, keys: map[string]*rsa.PublicKey{}}
}
func (v *githubVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	if k := v.keys[kid]; k != nil && now.Sub(v.fetched) < time.Hour {
		return k, nil
	}
	if !v.lastAttempt.IsZero() && now.Sub(v.lastAttempt) < 10*time.Second {
		return nil, errors.New("key refresh rate limited")
	}
	v.lastAttempt = now
	req, _ := http.NewRequestWithContext(ctx, "GET", githubJWKS, nil)
	resp, e := v.client.Do(req)
	if e != nil {
		return nil, errors.New("JWKS unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("JWKS unavailable")
	}
	var body struct {
		Keys []struct {
			KID string `json:"kid"`
			KTY string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); e != nil {
		return nil, errors.New("invalid JWKS")
	}
	keys := map[string]*rsa.PublicKey{}
	for _, j := range body.Keys {
		if j.KTY != "RSA" || j.Alg != "RS256" || j.Use != "sig" {
			continue
		}
		n, e := base64.RawURLEncoding.DecodeString(j.N)
		if e != nil {
			continue
		}
		eb, e := base64.RawURLEncoding.DecodeString(j.E)
		if e != nil || len(eb) > 4 {
			continue
		}
		exponent := 0
		for _, b := range eb {
			exponent = exponent*256 + int(b)
		}
		modulus := new(big.Int).SetBytes(n)
		if modulus.BitLen() < 2048 || exponent < 3 || exponent%2 == 0 {
			continue
		}
		keys[j.KID] = &rsa.PublicKey{N: modulus, E: exponent}
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS has no usable keys")
	}
	v.keys = keys
	v.fetched = now
	if k := keys[kid]; k != nil {
		return k, nil
	}
	return nil, errors.New("unknown signing key")
}
func (v *githubVerifier) verify(ctx context.Context, raw, workspace string) (*githubClaims, error) {
	if len(raw) > 16384 {
		return nil, unauthorized()
	}
	c := new(githubClaims)
	t, e := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodRS256 {
			return nil, errors.New("invalid algorithm")
		}
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" || len(kid) > 200 {
			return nil, errors.New("invalid kid")
		}
		return v.key(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(githubIssuer), jwt.WithAudience("urn:civault:workspace:"+workspace), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(30*time.Second), jwt.WithTimeFunc(v.now))
	if e != nil || !t.Valid {
		return nil, unauthorized()
	}
	if len(c.Audience) != 1 || c.IssuedAt == nil || c.NotBefore == nil || c.ExpiresAt == nil || c.Subject == "" || c.ID == "" || len(c.ID) > 256 || !digits.MatchString(c.OwnerID) || !digits.MatchString(c.RepositoryID) || !digits.MatchString(c.RunID) || !digits.MatchString(c.RunAttempt) || c.Repository == "" || c.WorkflowRef == "" || c.Ref == "" || c.Event == "" || c.Runner == "" || !c.ExpiresAt.After(c.IssuedAt.Time) {
		return nil, unauthorized()
	}
	return c, nil
}
