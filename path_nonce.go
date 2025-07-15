package sshauth

import (
	"context"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathNonce() *framework.Path {
	return &framework.Path{
		Pattern: "nonce$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback:                    b.pathNonceRead,
				Summary:                     "Generates a new nonce",
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},
	}
}

func (b *backend) pathNonceRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	nonce, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	b.nonceLock.Lock()
	b.nonces[nonce] = time.Now()
	b.nonceLock.Unlock()

	return &logical.Response{
		Data: map[string]interface{}{
			"nonce": nonce,
		},
	}, nil
}

func (b *backend) nonceValidate(config *ConfigEntry, nonce []byte) bool {
	b.nonceLock.RLock()
	defer b.nonceLock.RUnlock()

	if t, ok := b.nonces[string(nonce)]; ok {
		delete(b.nonces, string(nonce))
		return time.Since(t) <= time.Second*30
	}

	if config.SecureNonce {
		return false
	}

	return validNonceTime([]byte(nonce))
}

func (b *backend) nonceCleanup() {
	b.nonceLock.Lock()
	defer b.nonceLock.Unlock()

	for k, v := range b.nonces {
		if time.Since(v) > time.Second*30 {
			delete(b.nonces, k)
		}
	}
}
