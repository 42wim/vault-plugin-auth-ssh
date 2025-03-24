#!/bin/bash
export VAULT_ADDR="http://127.0.0.1:8200"
mkdir tmp
mkdir -p vault/plugins

set -e
echo "generating sshkey"
rm -f tmp/sshkey
rm -f tmp/sshkeyrsa
ssh-keygen -t ed25519 -f tmp/sshkey -N ""
ssh-keygen -t rsa -f tmp/sshkeyrsa -N ""

echo "building plugin"
go build -o vault/plugins/vault-plugin-auth-ssh cmd/vault-plugin-auth-ssh/main.go

echo "building createsig"
go build -o createsig/createsig createsig/main.go

vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins &
sleep 5

vault login root
vault secrets enable -path=ssh-client-signer ssh
vault write -field=public_key ssh-client-signer/config/ca generate_signing_key=true >tmp/sshca
vault write ssh-client-signer/roles/my-role - <<"EOH"
{
  "allow_user_certificates": true,
  "allowed_users": "*",
  "allowed_extensions": "permit-pty,permit-port-forwarding",
  "default_extensions": [
    {
      "permit-pty": ""
    }
  ],
  "key_type": "ca",
  "default_user": "ubuntu",
  "ttl": "30m0s"
}
EOH
vault write -field=signed_key ssh-client-signer/sign/my-role public_key=@tmp/sshkey.pub >tmp/sshkey-cert.pub
vault write -field=signed_key ssh-client-signer/sign/my-role public_key=@tmp/sshkeyrsa.pub >tmp/sshkeyrsa-cert.pub
vault auth enable -path=ssh vault-plugin-auth-ssh
vault write auth/ssh/config ssh_ca_public_keys=@tmp/sshca
vault write auth/ssh/role/ubuntu token_policies="ssh-policy" principals="ubuntu"
vault write auth/ssh/role/ubuntu2 token_policies="ssh-policy" public_keys=@tmp/sshkey.pub
vault write auth/ssh/role/ubuntu-rsa token_policies="ssh-policy" principals="ubuntu" rsa_algo_signer="default"
vault write auth/ssh/role/ubuntu2-rsa token_policies="ssh-policy" public_keys=@tmp/sshkeyrsa.pub rsa_algo_signer="rsa-sha2-512"
vault write auth/ssh/role/ubuntu3-rsa token_policies="ssh-policy" public_keys=@tmp/sshkeyrsa.pub rsa_algo_signer="ssh-rsa"

echo ""
echo ""
echo "You can now login with certificate via:"
echo "vault write auth/ssh/login role=ubuntu cert=@tmp/sshkey-cert.pub $(createsig/createsig $(vault read -field nonce auth/ssh/nonce) tmp/sshkey)"
echo "vault write auth/ssh/login role=ubuntu cert=@tmp/sshkeyrsa-cert.pub $(createsig/createsig $(vault read -field nonce auth/ssh/nonce) tmp/sshkeyrsa '' rsa-sha2-256)"
echo ""
echo ""
echo "You can now login with publickey via:"
echo "vault write auth/ssh/login role=ubuntu2 public_key=@tmp/sshkey.pub $(createsig/createsig $(vault read -field nonce auth/ssh/nonce) tmp/sshkey)"
echo "vault write auth/ssh/login role=ubuntu-rsa cert=@tmp/sshkeyrsa-cert.pub $(createsig/createsig $(vault read -field nonce auth/ssh/nonce) tmp/sshkeyrsa '' rsa-sha2-256)"
echo "vault write auth/ssh/login role=ubuntu2-rsa public_key=@tmp/sshkeyrsa.pub $(createsig/createsig $(vault read -field nonce auth/ssh/nonce) tmp/sshkeyrsa '' rsa-sha2-512)"
echo "vault write auth/ssh/login role=ubuntu3-rsa public_key=@tmp/sshkeyrsa.pub $(createsig/createsig $(vault read -field nonce auth/ssh/nonce) tmp/sshkeyrsa '' ssh-rsa)"
echo ""
echo ""
echo "run killall -9 vault-plugin-auth-ssh && killall -9 vault to kill running dev"
