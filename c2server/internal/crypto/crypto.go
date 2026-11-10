/*
 * ARES C2 — M-TLS + AES-GCM Crypto Module (v5.0 Overhaul)
 *
 * - M-TLS: Accept ONLY Cloudflare-authenticated connections
 * - AES-GCM: Mandatory at-rest encryption for all stored data
 * - Key derivation from master key for per-bot encryption
 */

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// ── M-TLS Server Configuration ──

// CreateMTLSServer creates an HTTPS server that ONLY accepts connections
// from clients presenting a valid Cloudflare Origin CA certificate.
func CreateMTLSServer(addr string, handler http.Handler,
	certFile, keyFile, cfCAFile string) (*http.Server, error) {

	// Load Cloudflare CA certificate
	cfCA, err := os.ReadFile(cfCAFile)
	if err != nil {
		return nil, fmt.Errorf("read CF CA cert: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(cfCA) {
		return nil, fmt.Errorf("failed to parse CF CA certificate")
	}

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	server := &http.Server{
		Addr:           addr,
		Handler:        handler,
		TLSConfig:      tlsConfig,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	log.Printf("[MTLS] Server configured: only Cloudflare-authenticated connections accepted")
	return server, nil
}

// CreateStandardTLSServer creates a standard TLS server (for non-MTLS mode)
func CreateStandardTLSServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:           addr,
		Handler:        handler,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
}

// ── AES-GCM At-Rest Encryption ──

// MasterKey manages the encryption master key
type MasterKey struct {
	key []byte
}

// LoadOrGenerateMasterKey loads the master encryption key from file,
// or generates a new one if it doesn't exist.
func LoadOrGenerateMasterKey(path string) (*MasterKey, error) {
	if data, err := os.ReadFile(path); err == nil && len(data) >= 32 {
		log.Printf("[CRYPTO] Loaded master key from %s", path)
		return &MasterKey{key: data[:32]}, nil
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, fmt.Errorf("save master key: %w", err)
	}
	log.Printf("[CRYPTO] Generated new master key → %s", path)
	return &MasterKey{key: key}, nil
}

// DeriveKey derives a per-bot key from master key + bot ID using SHA-256
func (mk *MasterKey) DeriveKey(botID string) []byte {
	h := sha256.New()
	h.Write(mk.key)
	h.Write([]byte(botID))
	return h.Sum(nil) // 32 bytes
}

// Encrypt encrypts plaintext using AES-256-GCM
func (mk *MasterKey) Encrypt(plaintext []byte, botID string) ([]byte, error) {
	key := mk.DeriveKey(botID)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts AES-256-GCM ciphertext
func (mk *MasterKey) Decrypt(ciphertext []byte, botID string) ([]byte, error) {
	key := mk.DeriveKey(botID)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

// EncryptGlobal encrypts data using master key directly (not per-bot)
func (mk *MasterKey) EncryptGlobal(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(mk.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptGlobal decrypts data using master key directly
func (mk *MasterKey) DecryptGlobal(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(mk.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}
