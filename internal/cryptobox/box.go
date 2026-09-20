// Package cryptobox implements versioned, domain-separated envelope encryption.
package cryptobox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

type Box struct{ master []byte }
type envelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
	WrapNonce  []byte `json:"wrap_nonce"`
	WrappedKey []byte `json:"wrapped_key"`
}

func New(encoded string) (*Box, error) {
	k, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(k) != 32 {
		return nil, errors.New("CIVAULT_MASTER_KEY must be a base64-encoded 32-byte key")
	}
	return &Box{master: k}, nil
}

func aad(purpose string, parts []string) []byte {
	var out bytes.Buffer
	for _, p := range append([]string{"civault", "1", purpose}, parts...) {
		_ = binary.Write(&out, binary.BigEndian, uint32(len(p)))
		out.WriteString(p)
	}
	return out.Bytes()
}

func aead(k []byte) (cipher.AEAD, error) {
	b, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}

func (b *Box) Seal(value []byte, context ...string) ([]byte, error) {
	dek := make([]byte, 32)
	if _, e := rand.Read(dek); e != nil {
		return nil, e
	}
	defer clear(dek)
	d, e := aead(dek)
	if e != nil {
		return nil, e
	}
	w, e := aead(b.master)
	if e != nil {
		return nil, e
	}
	x := envelope{Version: 1, Nonce: make([]byte, d.NonceSize()), WrapNonce: make([]byte, w.NonceSize())}
	if _, e = rand.Read(x.Nonce); e != nil {
		return nil, e
	}
	if _, e = rand.Read(x.WrapNonce); e != nil {
		return nil, e
	}
	x.Ciphertext = d.Seal(nil, x.Nonce, value, aad("value", context))
	x.WrappedKey = w.Seal(nil, x.WrapNonce, dek, aad("dek", context))
	return json.Marshal(x)
}

func (b *Box) Open(blob []byte, context ...string) ([]byte, error) {
	var x envelope
	if json.Unmarshal(blob, &x) != nil || x.Version != 1 {
		return nil, errors.New("invalid encrypted record")
	}
	w, e := aead(b.master)
	if e != nil {
		return nil, e
	}
	if len(x.WrapNonce) != w.NonceSize() {
		return nil, errors.New("invalid encrypted record")
	}
	dek, e := w.Open(nil, x.WrapNonce, x.WrappedKey, aad("dek", context))
	if e != nil {
		return nil, errors.New("encrypted record authentication failed")
	}
	defer clear(dek)
	d, e := aead(dek)
	if e != nil {
		return nil, e
	}
	if len(x.Nonce) != d.NonceSize() {
		return nil, errors.New("invalid encrypted record")
	}
	v, e := d.Open(nil, x.Nonce, x.Ciphertext, aad("value", context))
	if e != nil {
		return nil, errors.New("encrypted record authentication failed")
	}
	return v, nil
}

func (b *Box) MAC(purpose string, value []byte) string {
	k := make([]byte, 32)
	_, _ = io.ReadFull(hkdf.New(sha256.New, b.master, nil, []byte("civault/"+purpose+"/v1")), k)
	defer clear(k)
	m := hmac.New(sha256.New, k)
	m.Write(value)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
