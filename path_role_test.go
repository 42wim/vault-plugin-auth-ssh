package sshauth

import (
	"context"
	"reflect"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-sockaddr"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func getBackend(t *testing.T) (logical.Backend, logical.Storage) {
	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24

	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.Trace),

		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
		StorageView: &logical.InmemStorage{},
	}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView
}

func TestPath_Create(t *testing.T) {
	t.Run("happy path principals", func(t *testing.T) {
		b, storage := getBackend(t)

		data := map[string]interface{}{
			"token_bound_cidrs": "127.0.0.1/8",
			"token_policies":    "test",
			"token_period":      "3s",
			"token_ttl":         "1s",
			"token_num_uses":    12,
			"token_max_ttl":     "5s",
			"principals":        "ubuntu,ubuntu2",
		}

		expectedSockAddr, err := sockaddr.NewSockAddr("127.0.0.1/8")
		if err != nil {
			t.Fatal(err)
		}

		expected := &sshRole{
			TokenParams: tokenutil.TokenParams{
				TokenPolicies:   []string{"test"},
				TokenPeriod:     3 * time.Second,
				TokenTTL:        1 * time.Second,
				TokenMaxTTL:     5 * time.Second,
				TokenNumUses:    12,
				TokenBoundCIDRs: []*sockaddr.SockAddrMarshaler{{SockAddr: expectedSockAddr}},
			},
			Principals: []string{"ubuntu", "ubuntu2"},
			PublicKeys: []string(nil),
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "role/plugin-test",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}
		actual, err := b.(*backend).role(context.Background(), storage, "plugin-test")
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(expected, actual) {
			t.Fatalf("Unexpected role data: expected %#v\n got %#v\n", expected, actual)
		}
	})

	t.Run("happy path public key", func(t *testing.T) {
		b, storage := getBackend(t)

		data := map[string]interface{}{
			"token_bound_cidrs": "2001:0db8::/64",
			"token_policies":    "test",
			"token_period":      "3s",
			"token_ttl":         "1s",
			"token_num_uses":    12,
			"token_max_ttl":     "5s",
			"public_keys":       []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGg0xzFrvEYbZGkF5vWlHUutACUTLH7WMUG09NOi6skL"},
		}

		expectedSockAddr, err := sockaddr.NewSockAddr("2001:0db8::/64")
		if err != nil {
			t.Fatal(err)
		}

		expected := &sshRole{
			TokenParams: tokenutil.TokenParams{
				TokenPolicies:   []string{"test"},
				TokenPeriod:     3 * time.Second,
				TokenTTL:        1 * time.Second,
				TokenMaxTTL:     5 * time.Second,
				TokenNumUses:    12,
				TokenBoundCIDRs: []*sockaddr.SockAddrMarshaler{{SockAddr: expectedSockAddr}},
			},
			PublicKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGg0xzFrvEYbZGkF5vWlHUutACUTLH7WMUG09NOi6skL"},
			Principals: []string(nil),
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "role/plugin-test2",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}
		actual, err := b.(*backend).role(context.Background(), storage, "plugin-test2")
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(expected, actual) {
			t.Fatalf("Unexpected role data: expected %#v\n got %#v\n", expected, actual)
		}
	})

	t.Run("publickey and cert", func(t *testing.T) {
		b, storage := getBackend(t)
		data := map[string]interface{}{
			"policies":    "test",
			"public_keys": []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGg0xzFrvEYbZGkF5vWlHUutACUTLH7WMUG09NOi6skL"},
			"principals":  []string{"ubuntu", "ubuntu2"},
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "role/test2",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp != nil && !resp.IsError() {
			t.Fatalf("expected error")
		}
		if resp.Error().Error() != "public_keys and principals option are mutually exclusive" {
			t.Fatalf("unexpected err: %v", resp)
		}
	})

	t.Run("invalid public key", func(t *testing.T) {
		b, storage := getBackend(t)
		data := map[string]interface{}{
			"policies":    "test",
			"public_keys": []string{"ssh-ed25519 AAXAAC3NzaC1lZDI1NTE5AAAAIGg0xzFrvEYbZGkF5vWlHUutACUTLH7WMUG09NOi6skL"},
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "role/test3",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp != nil && !resp.IsError() {
			t.Fatalf("expected error")
		}
		if resp.Error().Error() != "public_keys parsing failed: ssh: no key found" {
			t.Fatalf("unexpected err: %v", resp)
		}
	})

	t.Run("invalid public key one", func(t *testing.T) {
		b, storage := getBackend(t)
		data := map[string]interface{}{
			"policies": "test",
			"public_keys": []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGg0xzFrvEYbZGkF5vWlHUutACUTLH7WMUG09NOi6skL",
				"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGg0xzFrvEYbZGkF5vWlHUutACUTLH7WMUG09NOi6skLX"},
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "role/test4",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp != nil && !resp.IsError() {
			t.Fatalf("expected error")
		}
		if resp.Error().Error() != "public_keys parsing failed: ssh: no key found" {
			t.Fatalf("unexpected err: %v", resp)
		}
	})
}
