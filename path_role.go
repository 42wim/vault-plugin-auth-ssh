package sshauth

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/ssh"
)

func (b *backend) pathRoleList() *framework.Path {
	return &framework.Path{
		Pattern: "role/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback:    b.doPathRoleList,
				Summary:     strings.TrimSpace(roleHelp["role-list"][0]),
				Description: strings.TrimSpace(roleHelp["role-list"][1]),
			},
		},
		HelpSynopsis:    strings.TrimSpace(roleHelp["role-list"][0]),
		HelpDescription: strings.TrimSpace(roleHelp["role-list"][1]),
	}
}

// pathRole returns the path configurations for the CRUD operations on roles
func (b *backend) pathRole() *framework.Path {
	p := &framework.Path{
		Pattern: "role/" + framework.GenericNameWithAtRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role.",
			},
			"public_keys": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Public keys allowed for this role.",
			},
			"principals": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Principals allowed for this role. A * means every principal is accepted.",
			},
		},
		ExistenceCheck: b.pathRoleExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathRoleRead,
				Summary:  "Read an existing role.",
			},

			logical.UpdateOperation: &framework.PathOperation{
				Callback:    b.pathRoleCreateUpdate,
				Summary:     strings.TrimSpace(roleHelp["role"][0]),
				Description: strings.TrimSpace(roleHelp["role"][1]),
			},

			logical.CreateOperation: &framework.PathOperation{
				Callback:    b.pathRoleCreateUpdate,
				Summary:     strings.TrimSpace(roleHelp["role"][0]),
				Description: strings.TrimSpace(roleHelp["role"][1]),
			},

			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathRoleDelete,
				Summary:  "Delete an existing role.",
			},
		},
		HelpSynopsis:    strings.TrimSpace(roleHelp["role"][0]),
		HelpDescription: strings.TrimSpace(roleHelp["role"][1]),
	}

	tokenutil.AddTokenFields(p.Fields)

	return p
}

type sshRole struct {
	tokenutil.TokenParams

	PublicKeys []string `json:"public_keys"`
	Principals []string `json:"principals"`
}

// role takes a storage backend and the name and returns the role's storage
// entry
func (b *backend) role(ctx context.Context, s logical.Storage, name string) (*sshRole, error) {
	raw, err := s.Get(ctx, rolePrefix+name)
	if err != nil {
		return nil, err
	}

	if raw == nil {
		return nil, nil
	}

	role := new(sshRole)
	if err := raw.DecodeJSON(role); err != nil {
		return nil, err
	}

	return role, nil
}

// pathRoleExistenceCheck returns whether the role with the given name exists or not.
func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.role(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}

	return role != nil, nil
}

// pathRoleList is used to list all the Roles registered with the backend.
func (b *backend) doPathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, rolePrefix)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(roles), nil
}

// pathRoleRead grabs a read lock and reads the options set on the role from the storage
func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return nil, nil
	}

	// Create a map of data to be returned
	d := map[string]interface{}{
		"principals":  role.Principals,
		"public_keys": role.PublicKeys,
	}

	role.PopulateTokenData(d)

	return &logical.Response{
		Data: d,
	}, nil
}

// pathRoleDelete removes the role from storage
func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("role name required"), nil
	}

	// Delete the role itself
	if err := req.Storage.Delete(ctx, rolePrefix+roleName); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathRoleCreateUpdate registers a new role with the backend or updates the options
// of an existing role
func (b *backend) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	// Check if the role already exists
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	// Create a new entry object if this is a CreateOperation
	if role == nil {
		if req.Operation == logical.UpdateOperation {
			return logical.ErrorResponse("role entry not found during update operation"), nil
		}

		role = new(sshRole)

		// set defaults for token parameters
		config, err := b.config(ctx, req.Storage)
		if err != nil {
			return nil, err
		}

		if config != nil {
			role.TokenParams = config.TokenParams
		}
	}

	if publicKeys, ok := data.GetOk("public_keys"); ok {
		role.PublicKeys = publicKeys.([]string)
	}

	for idx, key := range role.PublicKeys {
		certParsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
		if err != nil {
			return logical.ErrorResponse("public_keys parsing failed: %s", err), nil
		}

		role.PublicKeys[idx] = strings.TrimRight(string(ssh.MarshalAuthorizedKey(certParsed)), "\n")
	}

	if principals, ok := data.GetOk("principals"); ok {
		role.Principals = principals.([]string)
	}

	if len(role.Principals) > 0 && len(role.PublicKeys) > 0 {
		return logical.ErrorResponse("public_keys and principals option are mutually exclusive"), nil
	}

	if err = role.ParseTokenFields(req, data); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	if role.TokenPeriod > b.System().MaxLeaseTTL() {
		return logical.ErrorResponse(fmt.Sprintf("'period' of '%q' is greater than the backend's maximum lease TTL of '%q'", role.TokenPeriod.String(), b.System().MaxLeaseTTL().String())), nil
	}

	// Check that the TTL value provided is less than the MaxTTL.
	// Sanitizing the TTL and MaxTTL is not required now and can be performed
	// at credential issue time.
	if role.TokenMaxTTL > 0 && role.TokenTTL > role.TokenMaxTTL {
		return logical.ErrorResponse("ttl should not be greater than max ttl"), nil
	}

	resp := &logical.Response{}

	if role.TokenMaxTTL > b.System().MaxLeaseTTL() {
		resp.AddWarning("token max ttl is greater than the system or backend mount's maximum TTL value; issued tokens' max TTL value will be truncated")
	}

	// Store the entry.
	entry, err := logical.StorageEntryJSON(rolePrefix+roleName, role)
	if err != nil {
		return nil, err
	}

	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return resp, nil
}

// roleStorageEntry stores all the options that are set on an role
var roleHelp = map[string][2]string{
	"role-list": {
		"Lists all the roles registered with the backend.",
		"The list will contain the names of the roles.",
	},
	"role": {
		"Register an role with the backend.",
		`A role is required to authenticate with this backend. The role binds
		ssh information with token policies and settings.
		The bindings, token polices and token settings can all be configured
		using this endpoint`,
	},
}
