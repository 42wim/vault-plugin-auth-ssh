package sshauth

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: `config`,
		Fields: map[string]*framework.FieldSchema{
			"ssh_ca_public_keys": {
				Type:        framework.TypeCommaStringSlice,
				Description: `SSH CA public keys where ssh certificates are checked against.`,
			},
			"secure_nonce": {
				Type:        framework.TypeBool,
				Description: `Whether to use secure nonce generation.`,
				Default:     true,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
				Summary:  "Read the current SSH authentication backend configuration.",
			},

			logical.UpdateOperation: &framework.PathOperation{
				Callback:    b.pathConfigWrite,
				Summary:     "Configure the SSH authentication backend.",
				Description: confHelpDesc,
			},
		},

		HelpSynopsis:    confHelpSyn,
		HelpDescription: confHelpDesc,
	}
}

func (b *backend) config(ctx context.Context, s logical.Storage) (*ConfigEntry, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := &ConfigEntry{}

	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}

	return config, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"ssh_ca_public_keys": config.SSHCAPublicKeys,
			"secure_nonce":       config.SecureNonce,
		},
	}

	return resp, nil
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config := &ConfigEntry{
		SSHCAPublicKeys: d.Get("ssh_ca_public_keys").([]string),
		SecureNonce:     d.Get("secure_nonce").(bool),
	}

	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

const (
	confHelpSyn = `
Configures the SSH authentication backend.
`
	confHelpDesc = `
The SSH authentication backend validates ssh certificates and public keys.
`
)
