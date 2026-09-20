package cryptobox

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestEnvelopeAuthenticationAndRandomness(t *testing.T) {
	b, _ := New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	context := []string{"key", "ws_1", "key_1", "ver_1"}
	plain := []byte("not-a-real-token\nline two")
	one, e := b.Seal(plain, context...)
	if e != nil {
		t.Fatal(e)
	}
	two, _ := b.Seal(plain, context...)
	if bytes.Equal(one, two) {
		t.Fatal("encryption must be randomized")
	}
	if bytes.Contains(one, plain) {
		t.Fatal("plaintext in encrypted record")
	}
	got, e := b.Open(one, context...)
	if e != nil || !bytes.Equal(got, plain) {
		t.Fatal("roundtrip failed", e)
	}
	for i := range context {
		other := append([]string{}, context...)
		other[i] += "x"
		if _, e = b.Open(one, other...); e == nil {
			t.Fatalf("context %d not authenticated", i)
		}
	}
	other, _ := New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))
	if _, e = other.Open(one, context...); e == nil {
		t.Fatal("wrong key accepted")
	}
	one[len(one)/2] ^= 1
	if _, e = b.Open(one, context...); e == nil {
		t.Fatal("tampering accepted")
	}
	if b.MAC("a", plain) == b.MAC("b", plain) {
		t.Fatal("MAC domains not separated")
	}
}
func TestAmbiguousContextEncoding(t *testing.T) {
	if bytes.Equal(aad("value", []string{"a:b", "c"}), aad("value", []string{"a", "b:c"})) {
		t.Fatal("ambiguous AAD")
	}
	for _, s := range []string{"", "password", base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		if _, e := New(s); e == nil {
			t.Fatal("invalid key accepted")
		}
	}
}
