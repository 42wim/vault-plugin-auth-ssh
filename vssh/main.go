package main

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	// talk to the agent
	ag, err := getAgent()
	if err != nil {
		log.Fatalf("ssh agent failed: %s", err)
	}

	// get all our agent keys
	sshsigners, err := ag.Signers()
	if err != nil {
		log.Fatalf("getting signers failed: %s", err)
	}

	principal := os.Getenv("VSSH_PRINCIPAL")
	role := os.Getenv("VSSH_ROLE")

	if principal == "" || role == "" {
		log.Fatalf("VSSH_ROLE or VSSH_PRINCIPAL is empty")
	}

	// find the specific certificate containing the principal we need
	signer := findCertSigner(sshsigners, principal)
	if signer == nil {
		log.Fatalf("no ssh key found: %s", err)
	}

	nonce, err := getNonce()
	if err != nil {
		log.Fatalf("nonce failed: %s", err)
	}

	token, err := getToken(nonce, role, signer)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(token)
}

func getNonce() (string, error) {
	v, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return "", err
	}

	// now login
	secret, err := v.Logical().Read("auth/ssh/nonce")
	if err != nil {
		return "", err
	}

	if secret == nil {
		return "", fmt.Errorf("empty response from credential provider")
	}

	return secret.Data["nonce"].(string), nil
}

func getToken(nonce, role string, signer ssh.Signer) (string, error) {
	v, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return "", err
	}

	signBytes := []byte(nonce)

	// now sign this with our private key of the certificate
	res, _ := signer.Sign(rand.Reader, signBytes)

	signatureBlob := res.Blob

	// fill in all our required settings
	options := map[string]interface{}{
		"role":      role,
		"nonce":     base64.StdEncoding.EncodeToString(signBytes),
		"signature": base64.StdEncoding.EncodeToString(signatureBlob),
		"cert":      string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
	}

	// now login
	secret, err := v.Logical().Write("auth/ssh/login", options)
	if err != nil {
		return "", err
	}

	if secret == nil {
		return "", fmt.Errorf("empty response from credential provider")
	}

	return secret.Auth.ClientToken, nil
}

// getAgent returns a ssh agent
func getAgent() (agent.Agent, error) {
	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, err
	}

	return agent.NewClient(sshAgent), nil
}

// findCertSigner returns the signer containing a valid certificate containing the specified principal
func findCertSigner(sshsigners []ssh.Signer, principal string) ssh.Signer {
	for _, s := range sshsigners {
		// ignore non-certificate keys
		if !strings.Contains(s.PublicKey().Type(), "cert-v01@openssh.com") {
			continue
		}

		mpubkey, _ := ssh.ParsePublicKey(s.PublicKey().Marshal())
		cryptopub := mpubkey.(crypto.PublicKey)
		cert := cryptopub.(*ssh.Certificate)
		t := time.Unix(int64(cert.ValidBefore), 0)

		if time.Until(t) <= time.Second*10 {
			continue
		}

		for _, p := range cert.ValidPrincipals {
			if principal == p {
				return s
			}
		}
	}

	return nil
}
