package sshauth

import (
	"context"
	"encoding/base64"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Role to use",
			},
			"metadata": {
				Type:        framework.TypeKVPairs,
				Description: "Keys and values to set for alias metadata",
			},
			"cert": {
				Type:        framework.TypeString,
				Description: "SSH certificate (base64 encoded)",
			},
			"public_key": {
				Type:        framework.TypeString,
				Description: "SSH public key (base64 encoded)",
			},
			"signature": {
				Type:        framework.TypeString,
				Description: "Signature over the nonce (base64 encoded)",
			},
			"nonce": {
				Type:        framework.TypeString,
				Description: "Nonce (base64 encoded)",
			},
			"username": {
				Type:        framework.TypeString,
				Description: "Principal to use when authenticating using ssh certificate (otherwise autodiscovered)",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.handleLogin,
				Summary:                     "Log in using ssh certificates",
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
			logical.AliasLookaheadOperation: &framework.PathOperation{
				Callback:                    b.handleLogin,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},
	}
}

func (b *backend) handleLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return logical.ErrorResponse("could not load configuration"), nil
	}

	roleName := data.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse("role must be provided"), nil
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return logical.ErrorResponse("role %q could not be found", roleName), nil
	}

	validPrincipals := []string{roleName}

	// if we have explicit principals we must check those
	if len(role.Principals) > 0 {
		validPrincipals = role.Principals
	}

	if len(role.TokenBoundCIDRs) > 0 {
		if req.Connection == nil {
			b.Logger().Warn("token bound CIDRs found but no connection information available for validation")
			return nil, logical.ErrPermissionDenied
		}

		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, role.TokenBoundCIDRs) {
			return nil, logical.ErrPermissionDenied
		}
	}

	signature := data.Get("signature").(string)
	if signature == "" {
		return logical.ErrorResponse("signature must be provided"), nil
	}

	cert := data.Get("cert").(string)

	pubkey := data.Get("public_key").(string)

	if pubkey == "" && cert == "" {
		return logical.ErrorResponse("cert or pubkey must be provided"), nil
	}

	nonce := data.Get("nonce").(string)
	if nonce == "" {
		return logical.ErrorResponse("nonce must be provided"), nil
	}

	sigDecode, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return logical.ErrorResponse("decoding signature failed"), nil
	}

	nonceDecode, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return logical.ErrorResponse("decoding nonce failed"), nil
	}

	toParseKey := cert
	if toParseKey == "" {
		toParseKey = pubkey
	}

	if !b.nonceValidate(config, nonceDecode) {
		return logical.ErrorResponse("nonce time expired or invalid"), nil
	}

	pk, err := parsePubkey(toParseKey)
	if err != nil {
		return logical.ErrorResponse("decoding public_key/cert failed: " + err.Error()), err
	}

	if err := verifySignature(pk, nonceDecode, sigDecode); err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	// Name for the logical.Alias to set
	aliasName := roleName

	if cert != "" {
		principal := data.Get("username").(string)

		if principal == "" {
			// Select the first valid principal in the certificate, if any listed
			principal = detectPrincipal(pk, validPrincipals)
		}

		if err := validatePrincipal(principal, validPrincipals); err != nil {
			return logical.ErrorResponse("validation cert failed: " + err.Error()), err
		}

		if err := validateCert(pk, principal, config); err != nil {
			return logical.ErrorResponse("validation cert failed: " + err.Error()), err
		}

		// Take the principal as the alias name
		aliasName = principal
	} else {
		if err := validatePubkey(pubkey, role); err != nil {
			return logical.ErrorResponse("validation public_key failed: " + err.Error()), err
		}
	}

	metadata := map[string]string{}
	if metadataRaw, ok := data.GetOk("metadata"); ok {
		for key, value := range metadataRaw.(map[string]string) {
			metadata[key] = value
		}
	}
	// Set role last in case need to override something user set
	metadata["role"] = roleName

	// Compose the response
	resp := &logical.Response{}
	auth := &logical.Auth{
		InternalData: map[string]interface{}{
			"role": roleName,
		},
		Metadata:    metadata,
		DisplayName: aliasName,
		Alias: &logical.Alias{
			Name:     aliasName,
			Metadata: metadata,
		},
	}

	role.PopulateTokenAuth(auth)

	resp.Auth = auth

	return resp, nil
}
