# pylogin

This is a python code example which uses vault-plugin-auth-ssh set up
with ssh public keys in ssh-agent to get a vault token.

Requirements:

- ssh-agent which contains your ssh public key or keys.
- $VAULT_ADDR which contains the URL to your vault server.
- python3, including the paramiko module (installable for example
  through pip).

If there are multiple keys in ssh-agent it will try each until success.
If successful, stdout will have the json response including the vault
token.  You can extract it by piping it to `jq -r .auth.client_token`.

The "-V" option will show the parameters it is sending to vault, and
metadata keys and values may optionally be passed.

## Example

Create a role `yourrole` which with known public_key and gives you the
`apolicy` policy on this token.  This has to be done using a privileged
vault token.

```
$ vault write auth/ssh/role/yourrole token_policies="apolicy" public_keys=@id_rsa.pub
```

Now run login.py giving the role name and piping to jq:
```
$ ./login.py yourrole | jq -r .auth.client_token
s.j0Sf3qCXxMRDqXXxWpxBuwgm
```
