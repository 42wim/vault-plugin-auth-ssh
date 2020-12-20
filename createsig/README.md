# Createsig

```text
This tool will print out a signature and nonce to be used with vault-plugin-auth-ssh

Need createsig <key-path> <password>
eg. createsig id_rsa mypassword

If you don't have a password just omit it
eg. createsig id_rsa
```

## building

Use `go get`, resulting binary will be in `~/go/bin/createsig`

```sh
go get github.com/42wim/vault-plugin-auth-ssh/createsig
```
