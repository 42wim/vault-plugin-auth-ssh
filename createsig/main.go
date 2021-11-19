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

func genSig(nonce, privatekey, password string) {
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

	res, _ := signer.Sign(rand.Reader, signBytes)

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
		genSig(os.Args[1], "", "")
	case 3:
		genSig(os.Args[1], os.Args[2], "")
	case 4:
		genSig(os.Args[1], os.Args[2], os.Args[3])
	default:
		printHelp()
	}
}
