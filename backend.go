package sshauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	rolePrefix string = "role/"
)

// backend wraps the backend framework and adds a map for storing key value pairs.
type backend struct {
	*framework.Backend
	nonces    map[string]time.Time
	nonceLock sync.RWMutex
}

type ConfigEntry struct {
	tokenutil.TokenParams

	SSHCAPublicKeys []string `json:"ssh_ca_public_keys"`
	SecureNonce     bool     `json:"secure_nonce"`
}

var _ logical.Factory = Factory

// Factory configures and returns Mock backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func newBackend() *backend {
	b := &backend{}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeCredential,
		AuthRenew:   b.pathAuthRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
				"nonce",
			},
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				b.pathLogin(),
				b.pathNonce(),
				b.pathConfig(),
				b.pathRoleList(),
				b.pathRole(),
			},
		),
		PeriodicFunc: b.periodicFunc,
	}

	b.nonces = make(map[string]time.Time)

	return b
}

func (b *backend) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := req.Auth.InternalData["role"].(string)
	if roleName == "" {
		return nil, errors.New("failed to fetch role_name during renewal")
	}

	// Ensure that the Role still exists.
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("failed to validate role %s during renewal: {{err}}", roleName), err)
	}

	if role == nil {
		return nil, fmt.Errorf("role %s does not exist during renewal", roleName)
	}

	resp := &logical.Response{
		Auth: req.Auth,
	}

	resp.Auth.TTL = role.TokenTTL
	resp.Auth.MaxTTL = role.TokenMaxTTL
	resp.Auth.Period = role.TokenPeriod

	return resp, nil
}

func (b *backend) periodicFunc(ctx context.Context, req *logical.Request) error {
	b.nonceCleanup()

	return nil
}

const (
	backendHelp = `
The SSH backend plugin allows authentication using SSH certificates and public keys.
`
)
