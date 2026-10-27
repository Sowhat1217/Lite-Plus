package jsonrpc

import (
	"testing"

	"github.com/nuomiiiii/lite/nodemgt/models"
)

func TestResolveInboundSortIndexKeepsZero(t *testing.T) {
	next := func() int {
		t.Fatal("explicit sort must not auto-assign")
		return 0
	}
	zero := 0
	if got := resolveInboundSortIndex("", &zero, nil, next); got != 0 {
		t.Fatalf("explicit 0 must stay 0, got %d", got)
	}
	eight := 8
	if got := resolveInboundSortIndex("", &eight, nil, next); got != 8 {
		t.Fatalf("explicit 8 must stay 8, got %d", got)
	}
	existing := &models.Inbound{SortIndex: 3}
	if got := resolveInboundSortIndex("id-1", nil, existing, next); got != 3 {
		t.Fatalf("edit without sort must keep existing, got %d", got)
	}
	called := false
	got := resolveInboundSortIndex("", nil, nil, func() int {
		called = true
		return 7
	})
	if !called || got != 7 {
		t.Fatalf("omitted sort on create must auto-assign, got %d", got)
	}
}
