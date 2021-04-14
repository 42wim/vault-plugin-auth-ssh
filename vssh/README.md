# vssh

This is a quick code example which uses the vault-plugin-auth-ssh setup with ssh certificates to get a token.
(You'll need something like this because we can't integrate directly with vault because this needs modifications of the vault source).

Requirements:

- ssh-agent which contains your ssh certificate.
- VSSH_ROLE environment variable which contains the role you are going to use in auth/ssh/role/yourrole
- VSSH_PRINCIPAL environment variable which contains the principal that is need to authenticate against the role in VSSH_ROLE
  - vssh will check every key in your ssh-agent to see if it matches a valid certificate containing this principal
- the normal vault settings like VAULT_ADDR which contains the URL to your vault server.

Then just run ./vssh and it'll output you a vault token that'll contain the policy you set on the role in auth/ssh/role/yourrole

## Example

First add your ssh CA key (see <https://github.com/42wim/vault-plugin-auth-ssh#global-configuration>)

```
$ vault write auth/ssh/config ssh_ca_public_keys=@sshca
```

Create a role `yourrole` which needs a principal `ubuntu` in it's certificate and gives you the `apolicy` on this token.

```
$ vault write auth/ssh/role/yourrole token_policies="apolicy" principals="ubuntu"
```

Now run vssh

```
$ VSSH_ROLE=yourrole" VSSH_PRINCIPAL="ubuntu" vssh
s.r4dGTu4tMvacKTEAXlKlRGtK
```
