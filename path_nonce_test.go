package sshauth

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestNonceValidate_ConcurrentConsumption(t *testing.T) {
	t.Parallel()

	b, storage := getBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "nonce",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("issuing nonce: response = %#v, error = %v", resp, err)
	}

	nonce := []byte(resp.Data["nonce"].(string))
	config := &ConfigEntry{SecureNonce: true}
	const consumers = 64
	start := make(chan struct{})
	results := make(chan bool, consumers)
	for range consumers {
		go func() {
			<-start
			results <- b.(*backend).nonceValidate(config, nonce)
		}()
	}
	close(start)

	accepted := 0
	for range consumers {
		if <-results {
			accepted++
		}
	}
	if accepted != 1 {
		t.Errorf("nonce accepted %d times, want exactly once", accepted)
	}
	if b.(*backend).nonceValidate(config, nonce) {
		t.Error("consumed nonce accepted again")
	}
}
