package vault

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWKSRotationThrottlingAndStaleKeyFailure(t *testing.T) {
	now := time.Now()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	kid, calls, available := "first", 0, true
	v := newGithubVerifier(&http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != githubJWKS {
			t.Fatal("untrusted JWKS URL")
		}
		if !available {
			return response(503, "{}"), nil
		}
		return response(200, jsonText(map[string]any{"keys": []any{map[string]string{"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})), nil
	})}, func() time.Time { return now })
	token := func(id string) string {
		j := jwt.NewWithClaims(jwt.SigningMethodRS256, claims(now))
		j.Header["kid"] = id
		j.Header["jku"] = "https://attacker.invalid/jwks"
		s, e := j.SignedString(key)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	verify := func(raw string, want bool) {
		t.Helper()
		_, e := v.verify(context.Background(), raw, "ws_default")
		if (e == nil) != want {
			t.Fatalf("verification accepted=%v want=%v", e == nil, want)
		}
	}
	verify(token("first"), true)
	verify(token("first"), true)
	verify(token("unknown"), false)
	if calls != 1 {
		t.Fatal("cache or unknown-kid throttle not respected")
	}
	now = now.Add(11 * time.Second)
	kid = "rotated"
	verify(token("rotated"), true)
	if calls != 2 {
		t.Fatal("rotation did not refresh")
	}
	now = now.Add(time.Hour + time.Second)
	available = false
	verify(token("rotated"), false)
	if calls != 3 {
		t.Fatal("expired key was used without successful refresh")
	}
}

func TestOIDCRejectsAlgorithmConfusionAndMissingClaims(t *testing.T) {
	f := newFixture(t)
	key, _ := f.signer()
	now := time.Now()
	for _, mutate := range []func(*githubClaims){
		func(c *githubClaims) { c.ID = "" }, func(c *githubClaims) { c.NotBefore = nil },
		func(c *githubClaims) { c.Audience = append(c.Audience, "other-audience") }, func(c *githubClaims) { c.RunID = "" },
	} {
		c := claims(now)
		mutate(&c)
		if _, e := f.a.oidc.verify(context.Background(), sign(t, key, c), "ws_default"); e == nil {
			t.Fatal("invalid claims accepted")
		}
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims(now))
	tok.Header["kid"] = "test-key"
	raw, e := tok.SignedString(key.N.Bytes())
	if e != nil {
		t.Fatal(e)
	}
	if _, e := f.a.oidc.verify(context.Background(), raw, "ws_default"); e == nil {
		t.Fatal("algorithm confusion accepted")
	}
}
