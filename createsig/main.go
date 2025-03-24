package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

func genSig(nonce, privatekey, password, rsa_algo_signer string) {
	var (
		signer ssh.Signer
		err    error
	)

	pemBytes, err := ioutil.ReadFile(privatekey)
	if err != nil {
		log.Fatal(err)
	}

	if password == "" {
		signer, err = ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			log.Fatalf("parse key failed:%v", err)
		}
	} else {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(password))
	}

	var signBytes []byte

	if nonce == "" {
		t := time.Now()
		timeBytes, _ := t.MarshalBinary()
		signBytes = append(signBytes, timeBytes...)
	} else {
		signBytes = append(signBytes, []byte(nonce)...)
	}

	var res *ssh.Signature

	if signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		signeralgo, err := ssh.NewSignerWithAlgorithms(signer.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA})
		if err != nil {
			log.Fatalf("NewSignerWithAlgorithms failed: %s", err)
		}

		res, err = signeralgo.SignWithAlgorithm(rand.Reader, signBytes, rsa_algo_signer)
		if err != nil {
			log.Fatalf("SignWithAlgorithm failed: %s", err)
		}
	} else {
		res, err = signer.Sign(rand.Reader, signBytes)
		if err != nil {
			log.Fatalf("Sign failed: %s", err)
		}
	}

	signatureBlob := res.Blob

	fmt.Println("signature=" + base64.StdEncoding.EncodeToString(signatureBlob) + " nonce=" + base64.StdEncoding.EncodeToString(signBytes))
}

func printHelp() {
	fmt.Println("This tool will print out a signature based on a nonce to be used with vault-plugin-auth-ssh")
	fmt.Println("You can get a nonce by running \"vault read auth/ssh/nonce\"")
	fmt.Println("")
	fmt.Println("Need " + os.Args[0] + " <nonce> <key-path> <password>")
	fmt.Println("eg. " + os.Args[0] + " anonce ~/.ssh/id_rsa mypassword")
	fmt.Println("")
	fmt.Println("If you don't have a password just omit it")
	fmt.Println("eg. " + os.Args[0] + " anonce ~/.ssh/id_rsa")
}

func main() {
	switch len(os.Args) {
	case 2:
		genSig(os.Args[1], "", "", "")
	case 3:
		genSig(os.Args[1], os.Args[2], "", "")
	case 4:
		genSig(os.Args[1], os.Args[2], os.Args[3], "")
	case 5:
		genSig(os.Args[1], os.Args[2], os.Args[3], os.Args[4])
	default:
		printHelp()
	}
}
