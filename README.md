# Vault Plugin: SSH Auth Backend

This is a standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin allows for SSH public keys and SSH certificates to authenticate with Vault.

<!-- TOC -->

- [Vault Plugin: SSH Auth Backend](#vault-plugin-ssh-auth-backend)
  - [Getting Started](#getting-started)
  - [Usage](#usage)
  - [Developing](#developing)
    - [Dev setup](#dev-setup)
  - [Using the plugin](#using-the-plugin)
    - [Global configuration](#global-configuration)
      - [ssh_ca_public_keys](#ssh_ca_public_keys)
      - [secure_nonce](#secure_nonce)
    - [Roles](#roles)
      - [SSH certificate](#ssh-certificate)
      - [SSH public keys](#ssh-public-keys)
    - [Logging in](#logging-in)
      - [SSH certificate](#ssh-certificate-1)
      - [SSH public key](#ssh-public-key)
      - [Using templated policies](#using-templated-policies)
    - [Creating signatures](#creating-signatures)
    - [Using ssh-agent](#using-ssh-agent)

<!-- /TOC -->

## Getting Started

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with Vault](https://www.vaultproject.io/intro/getting-started/install.html).

To learn specifically about how plugins work, see documentation on [Vault plugins](https://www.vaultproject.io/docs/internals/plugins.html).

## Usage

```sh
$ vault auth enable -path=ssh vault-plugin-auth-ssh
Success! Enabled vault-plugin-auth-ssh auth method at: ssh/
```

## Developing

If you wish to work on this plugin, you'll first need
[Go](https://www.golang.org) installed on your machine.

Next, clone this repository into `vault-plugin-auth-ssh`.

To compile a development version of this plugin, run `make build`.
This will put the plugin binary in the `./vault/plugins` folders.

Run `make start` to start a development version of vault with this plugin.

Enable the auth plugin backend using the SSH auth plugin:

```sh
$ vault auth enable -path=ssh vault-plugin-auth-ssh
Success! Enabled vault-plugin-auth-ssh auth method at: ssh/
```

### Dev setup

Look into the `devsetup.sh` script, this will build the plugin, build certsig and setup a test environment with ssh-client signing, ssh certificate and public key test.

## Using the plugin

### Global configuration

You may optionally set any of the
[standard Vault token parameters](https://pkg.go.dev/github.com/hashicorp/vault/sdk/helper/tokenutil#TokenParams)
which will be used as defaults if not overridden in a role.

#### ssh_ca_public_keys

If you want to use ssh certificates you'll need to configure the ssh CA's which the certificates will validate against.

sshca in this example is a file containing your SSH CA. You can specify multiple CA's.

```sh
$ vault write auth/ssh/config ssh_ca_public_keys=@sshca

$ vault read auth/ssh/config
Key                   Value
---                   -----
secure_nonce          true
ssh_ca_public_keys    [ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDrLFN/LCDOjPw327hWfHXMOk9+GmP+pOl2JEG7eSfkzwVhumDU12swjnPQ9H1tZVWzcfufTg+PgMd/hP19ADkRxQ2CTbz7YUPdD6LvJOCRK8TK+tKliaFL9/lWFtlitERyk91ZSqGbROjtCyGlnetxY1+tF5NqLFtQ1tsPrxjjdRQoUMHlF8yv/VUxMOCjAmuqxKrEl5mfZJcnYpnfEBgWoZNTKAXkp6KJWLAxyiHPVTt7azyMzivCTZc8eCKXIInRpOMR7TvHGxPG8tHn2XrI01ni9zXQ+xG1sqxecPBSWU8fekKxwg5bikrWw4/9kCNvxrwBpf1IzlIKhugig8MP3+Jlrjp5BFXFuaQatIk6zLMkzDpE/iZwDZv5qicXdLK/nbKHmGqFWupcvfHUe6rh16TOYFbpnRMOEvTYpR/PfLlnQKcbkQgbDR01N8DfLetxt635C+ANU4N1ebQqjKkwb8ZPr2ryF/Y8Z1PV0x5H25r8UZyoGAXIsP3zkP0Ev40Bx3umlU/jR8nF6QQmXdbs2McfZFO2g0VsXSzUOR0L5s5Sd/uoUCcpz9nmKlgRIqHIhVGF3+FjrIaj3tXT7ucyPAsVVk/l4yhMQSuNtFi0eqZRPcdMiKff5W9PfVyEkpXTcSFweGPdVehZxPnM7DfH7axpg73OLWxvwVzkah31WQ==]
token_bound_cidrs          []
token_explicit_max_ttl     0s
token_max_ttl              0s
token_no_default_policy    false
token_num_uses             0
token_period               0s
token_policies             []
token_ttl                  0s
token_type                 default
```

#### secure_nonce

By default the `secure_nonce` config option is enabled.
This means vault will generate a nonce for you with a lifetime of 30 seconds.  
You can get this nonce by doing `vault read auth/ssh/nonce` the resulting nonce must be used to create a signature over. (see [Creating signatures](#creating-signatures))

If you disable `secure_nonce` you can use timebased nonces. (this is a possible security risk)

### Roles

You can create / list / delete roles which are used to link your certificate or public keys to Vault policies.

You may optionally set any of the
[standard Vault token parameters](https://pkg.go.dev/github.com/hashicorp/vault/sdk/helper/tokenutil#TokenParams)
to override default values.

#### SSH certificate

Create a role with the policy `ssh-policy` bound to a certificate with the principal `ubuntu`.  
(prerequisite: a SSH CA needs to be configured in auth/ssh/config)

```sh
$ vault write auth/ssh/role/ubuntu token_policies="ssh-policy" principals="ubuntu"

$ vault read auth/ssh/role/ubuntu
Key                        Value
---                        -----
principals                 [ubuntu]
public_keys                <nil>
token_bound_cidrs          []
token_explicit_max_ttl     0s
token_max_ttl              0s
token_no_default_policy    false
token_num_uses             0
token_period               0s
token_policies             [ssh-policy]
token_ttl                  0s
token_type                 default
```

#### SSH public keys

Create a role with the policy `ssh-policy` bound to a specific publickey.

```sh
$ vault write auth/ssh/role/ubuntu token_policies="ssh-policy" public_keys=@sshkey.pub

$ vault read auth/ssh/role/ubuntu
Key                        Value
---                        -----
principals                 <nil>
public_keys                [ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGg0xzFrvEYbZGkF5vWlHUutACUTLH7WMUG09NOi6skL]
token_bound_cidrs          []
token_explicit_max_ttl     0s
token_max_ttl              0s
token_no_default_policy    false
token_num_uses             0
token_period               0s
token_policies             [ssh-policy]
token_ttl                  0s
token_type                 default
```

#### SSH public key self-registration

If your Vault has another authentication method that users can use,
perhaps one that requires more user interaction such as 
[OIDC authentication](https://learn.hashicorp.com/tutorials/vault/oidc-auth),
it is possible to use that other authentication method to securely
enable users to register their own public keys for SSH authentication.

First, configure default standard token parameters for SSH
authentication as above, so users do not have to choose them,
especially the `token_policies` parameter.
Next, configure the other authentication method with a policy that
enables writing public keys to the `auth/ssh/role` path but doesn't
allow other parameters. 
For example use a
[templated policy](https://www.vaultproject.io/docs/concepts/policies#templated-policies)
like this:
```
path "auth/ssh/role/{{identity.entity.aliases.<mount accessor>.name}}" {
    capabilities = ["create", "update"]
    denied_parameters = {
        "public_keys"   = ["@*"]
    }
    allowed_parameters = {
        "public_keys"    = []
    }
}
```

### Logging in

#### SSH certificate

```sh
nonce=$(vault read -field nonce auth/ssh/nonce)
vault write auth/ssh/login role=<role> cert=@<certfile> nonce=$nonce signature=<base64encoded ssh signature over $nonce>
```

For example

```sh
vault write auth/ssh/login role=ubuntu cert=@id_rsa-cert.pub signature=7ou2bupUMNmMqcorurOnbKnpbh9Kc7aBrF7nk6li0AhgnYAzhgfgGB3qJqI4qmf9TIc/x3JoNzo+Xq7KqXOXCA== nonce=AQAAAA7XdbPVKJn3uwA8

Key                  Value
---                  -----
token                s.TpHP2eRCZNhuOENZUMas6YmV
token_accessor       7FFAcAnxKOyM8BYWEN2KfYzR
token_duration       768h
token_renewable      true
token_policies       ["default" "ssh-policy"]
identity_policies    []
policies             ["default" "ssh-policy"]
token_meta_role      ubuntu
```

See [Creating signatures](#creating-signatures) about how to create those.

#### SSH public key

```sh
nonce=$(vault read -field nonce auth/ssh/nonce)
vault write auth/ssh/login role=<role> public_key=@<publickey> nonce=$nonce signature=<base64encoded ssh signature over $nonce>
```

For example

```sh
$ vault write auth/ssh/login role=ubuntu public_key=@id_rsa.pub signature=fiEHdDHClYJIlRNWMC6c5QpM3ePi1xJh1KB90NI7CedZh0Siya5SG8ohy6zOk7e5l8Mdhx/FelykL43KH+OwBw== nonce=AQAAAA7XdbTAIytAhQA8

Key                  Value
---                  -----
token                s.8L1uONTtaLHzZEtNw2oKmurk
token_accessor       SQ6jWOYKblSBFqywTezcdqVk
token_duration       768h
token_renewable      true
token_policies       ["default" "ssh-policy"]
identity_policies    []
policies             ["default" "ssh-policy"]
token_meta_role      ubuntu
```

See [Creating signatures](#creating-signatures) about how to create those.

#### Using templated policies

This plugin makes aliases available for use in Vault
[templated policies](https://www.vaultproject.io/docs/concepts/policies#templated-policies).
These can be used to limit what secrets a policy makes available while
sharing one policy between multiple roles.
The defined role is always available in policies as
`{{identity.entity.aliases.<mount accessor>.name}}`.
In addition, a login can add any metadata keys with values to further
limit secrets paths via the `metadata` parameter available as
`{{identity.entity.aliases.<mount accessor>.metadata.<metadata key>}}`.
The metadata parameter is a mapping of keys to values which should be
input as JSON, for example:

For example

```sh
echo '{ "metadata": { "key1" : "val1", "key2": "val2" } }' | \
  vault write auth/ssh/login role=<role> public_key=@<publickey> nonce=<nonce> signature=<signature> -
```

will create the metadata keys "key1" and key2" with values "val1" and
"val2", respectively.

### Creating signatures

For now you can use the [createsig](createsig/README.md) tool to generate your signature and nonce.

```text
This tool will print out a signature based on a nonce to be used with vault-plugin-auth-ssh

Need createsig <nonce> <key-path> <password>
eg. createsig 5f780af8-75ff-f209-cd31-500879e18640 id_rsa mypassword

If you don't have a password just omit it
eg. createsig 5f780af8-75ff-f209-cd31-500879e18640 id_rsa
```

You must get the nonce from `vault read auth/ssh/nonce`

For example:

```sh
$ vault write auth/ssh/login role=ubuntu public_key=@id_rsa.pub $(createsig $(vault read -field nonce auth/ssh/nonce) vaultid_rsa)
```

```sh
$ vault write auth/ssh/login role=ubuntu cert=@id_rsa-cert.pub $(createsig $(vault read -field nonce auth/ssh/nonce) id_rsa)
```

With a pass

```sh
$ vault write auth/ssh/login role=ubuntu public_key=@id_rsa.pub $(createsig $(vault read -field nonce auth/ssh/nonce) id_rsa yourpass)
```

### Using ssh-agent

Signatures can also be created using ssh-agent.
See the [vssh README](vssh/README.md) and [pylogin README](pylogin/README.md)
for examples of how to do that.

### Running in Containerized Environments (Docker, Kubernetes, etc)

Vault will attempt to lock its memory to avoid swapping unencrypted secrets to disk.

This is explained in some detail here: [https://support.hashicorp.com/hc/en-us/articles/115012787688-Vault-and-mlock](https://support.hashicorp.com/hc/en-us/articles/115012787688-Vault-and-mlock)

When running in Kubernetes, this is achieved by setting the _securityContext_ in the container spec by adding the following to the container definition:

          securityContext:
            capabilities:
              add:
                - IPC_LOCK

However, this only gives the ability of a file to use mlock through Kubernetes.  The executable files themselves need this to be set as well.

The Vault binary itself is distributed with the capabilities (which are stored via extensions on the file itself) enabled for Vault to use mlock.  Any _plugins_ however, must have this set as well to work outside of "dev mode" (which disables mlock).

You can do this in your Dockerfile when creating your own images, or at any other point before Vault attempts to use the plugin.

When creating container images using Vault plugins like this one, be sure to add the following steps to your Dockerfile:

    RUN chown vault:vault /path/to/vault-plugins/vault-plugin-auth-ssh

    RUN chmod 700 /path/to/vault-plugins/vault-plugin-auth-ssh

    RUN setcap cap_ipc_lock=+ep /path/to/vault-plugins/vault-plugin-auth-ssh

Setting the owner/group and mode will prevent problems when using setting `VAULT_ENABLE_FILE_PERMISSIONS_CHECK` to true.

Running the final `setcap` command will allow the plugin to function when Vault is using mlock.