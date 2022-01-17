package sshauth

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/ssh"
)

func validatePubkey(pubkey string, role *sshRole) error {
	found := false

	pkParsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
	if err != nil {
		return fmt.Errorf("key parsing failed: %s", err)
	}

	pk := strings.TrimRight(string(ssh.MarshalAuthorizedKey(pkParsed)), "\n")

	for _, key := range role.PublicKeys {
		if key != pk {

			continue
		}

		found = true

		break
	}

	if !found {
		return logical.ErrPermissionDenied
	}

	return nil
}

// Detect the first valid principal from the certificate, if any is present
func detectPrincipal(pubkey ssh.PublicKey, validPrincipals []string) string {
	cert, ok := pubkey.(*ssh.Certificate)
	if !ok {
		// Not a certificate - no principal to detect
		return ""
	}

	if len(cert.ValidPrincipals) == 0 {
		// Certificate is not valid for any principal
		return ""
	}

	// Return the first valid principal found in the certificate
	for _, p := range validPrincipals {
		for _, vp := range cert.ValidPrincipals {
			if p == vp || vp == "*" {
				return p
			}
		}
	}

	// No valid principal was found in the certificate
	return ""
}

func validatePrincipal(principal string, validPrincipals []string) error {
	if principal == "*" || principal == "" {
		return errors.New("invalid principal")
	}

	for _, vp := range validPrincipals {
		if vp == principal || vp == "*" {
			return nil
		}
	}

	return errors.New("no matching principal found")
}

func validateCert(pubkey ssh.PublicKey, principal string, config *ConfigEntry) error {
	cert, ok := pubkey.(*ssh.Certificate)
	if !ok {
		return errors.New("not a certificate")
	}

	if len(cert.ValidPrincipals) == 0 {
		return errors.New("refusing certificate without principal list")
	}

	c := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			for _, caKey := range config.SSHCAPublicKeys {
				pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caKey))
				if err != nil {
					return false
				}

				if bytes.Equal(auth.Marshal(), pubKey.Marshal()) {
					return true
				}
			}

			return false
		},
	}

	// check the CA of the cert
	if !c.IsUserAuthority(cert.SignatureKey) {
		return errors.New("CA doesn't match")
	}

	// check cert validity
	if err := c.CheckCert(principal, cert); err != nil {
		return fmt.Errorf("certificate validation failed: %s", err)
	}

	return nil
}

func parsePubkey(pubkey string) (ssh.PublicKey, error) {
	certParsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
	if err != nil {
		return nil, fmt.Errorf("parsing failed %s", err)
	}

	parsedPubkey, err := ssh.ParsePublicKey(certParsed.Marshal())
	if err != nil {
		return nil, fmt.Errorf("pubkey parsing failed %s", err)
	}

	return parsedPubkey, nil
}

func verifySignature(pubkey ssh.PublicKey, nonce, signature []byte) error {
	if cert, ok := pubkey.(*ssh.Certificate); ok {
		pubkey = cert.Key
	}

	cryptoPubkey := pubkey.(ssh.CryptoPublicKey).CryptoPublicKey()

	switch key := cryptoPubkey.(type) {
	case ed25519.PublicKey:
		if !verifyEd25519(key, nonce, signature) {
			return errors.New("signature verification failed")
		}
	case *rsa.PublicKey:
		if !verifyRSA(key, nonce, signature) {
			return errors.New("signature verification failed")
		}
	default:
		return fmt.Errorf("invalid type %#v not supported", key)
	}

	return nil
}

func verifyEd25519(key ed25519.PublicKey, nonce, signature []byte) bool {
	return ed25519.Verify(key, nonce, signature)
}

func verifyRSA(key *rsa.PublicKey, nonce, signature []byte) bool {
	hash := crypto.SHA1
	h := hash.New()

	h.Write(nonce)

	digest := h.Sum(nil)

	return rsa.VerifyPKCS1v15(key, hash, digest, signature) == nil
}

func validNonceTime(nonce []byte) bool {
	t := time.Time{}
	t.UnmarshalBinary(nonce)

	return time.Since(t) <= time.Second*30
}
