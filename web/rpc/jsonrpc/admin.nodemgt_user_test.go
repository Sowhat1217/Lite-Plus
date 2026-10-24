package jsonrpc

import (
	"os"
	"strings"
	"testing"
)

func TestNodemgtUserListKeepsGoingIfResetSyncFails(t *testing.T) {
	src, err := os.ReadFile("admin.nodemgt.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if !strings.Contains(text, `logger.Warnf("nodemgt", "traffic reset sync: %v", err)`) {
		t.Fatal("user.list must not fail the whole list when monthly reset sync errors")
	}
	if strings.Contains(text, `if _, err := nodemgtOps().SyncDueTrafficResets(time.Now().UTC()); err != nil {
		return nil, nodemgtErr(err)
	}`) {
		t.Fatal("user.list still returns the traffic reset error")
	}
}

func TestNodemgtShouldClearPlan(t *testing.T) {
	if nodemgtShouldClearPlan("", false) {
		t.Fatal("new user with no plan must not unassign")
	}
	if nodemgtShouldClearPlan("plan-1", true) {
		t.Fatal("keeping or switching a plan must not unassign")
	}
	if nodemgtShouldClearPlan("plan-1", false) {
		t.Fatal("assigning a plan to a user without one must not unassign")
	}
	if !nodemgtShouldClearPlan("", true) {
		t.Fatal("clearing an existing plan must unassign")
	}
}
