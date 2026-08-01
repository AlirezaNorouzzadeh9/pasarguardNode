//go:build linux

package wireguard

import (
	"strings"
	"testing"

	"github.com/pasarguard/node/backend/hostroute"
)

func TestNFTMasqueradeRule(t *testing.T) {
	if got := nftMasqueradeRule("wg0", "eth0", true); got != `oifname "eth0" masquerade` {
		t.Fatalf("unexpected egress-only rule: %s", got)
	}

	if got := nftMasqueradeRule("wg0", "eth0", false); got != `iifname "wg0" oifname "eth0" masquerade` {
		t.Fatalf("unexpected interface-scoped rule: %s", got)
	}

	if got := strings.Join(nftMasqueradeRuleArgs("wg0", "eth0", false), " "); got != `iifname "wg0" oifname "eth0" masquerade` {
		t.Fatalf("unexpected masquerade args: %s", got)
	}
}

func TestNFTAlreadyExists(t *testing.T) {
	if nftAlreadyExists(nil) {
		t.Fatalf("nil error must not be treated as already exists")
	}

	if !nftAlreadyExists(staticError("File exists")) {
		t.Fatalf("expected File exists error to be treated as already exists")
	}

	if nftAlreadyExists(staticError("permission denied")) {
		t.Fatalf("unexpected already exists match")
	}
}

func TestNFTMasqueradeConfigIsScoped(t *testing.T) {
	cfg := nftMasqueradeConfig(`oifname "eth0" masquerade`, nftNATRuleComment("owner-1", "wg0", "eth0", true))

	for _, want := range []string{
		"table ip pg_node_wg_nat",
		"chain postrouting",
		"type nat hook postrouting priority 100; policy accept;",
		`oifname "eth0" masquerade`,
		`comment "pg_node_wg owner=owner-1 type=nat iface=wg0 out=eth0 scope=egress"`,
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("config missing %q:\n%s", want, cfg)
		}
	}

	if strings.Contains(cfg, "flush ruleset") {
		t.Fatalf("managed config must not flush the global nft ruleset:\n%s", cfg)
	}
}

func TestNFTForwardConfigIsScoped(t *testing.T) {
	cfg := nftForwardConfig("wg0", "eth0")

	for _, want := range []string{
		`iifname "wg0" oifname "eth0" accept comment "pg_node_wg owner=test-owner type=forward iface=wg0 out=eth0 direction=outbound"`,
		`iifname "eth0" oifname "wg0" ct state established,related accept comment "pg_node_wg owner=test-owner type=forward iface=wg0 out=eth0 direction=return"`,
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("config missing %q:\n%s", want, cfg)
		}
	}

	if strings.Contains(cfg, "flush ruleset") {
		t.Fatalf("managed config must not flush the global nft ruleset:\n%s", cfg)
	}
	if strings.Contains(cfg, "type filter hook forward") || strings.Contains(cfg, "policy accept") {
		t.Fatalf("forward config must not create a catch-all base chain:\n%s", cfg)
	}
}

func TestParseNFTForwardBaseChains(t *testing.T) {
	const ruleset = `{
		"nftables": [
			{"metainfo": {"version": "1.0.9"}},
			{"table": {"family": "ip", "name": "filter"}},
			{"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
			{"chain": {"family": "inet", "table": "firewalld", "name": "filter_FORWARD", "type": "filter", "hook": "forward", "prio": 10, "policy": "accept"}},
			{"chain": {"family": "ip6", "table": "filter", "name": "FORWARD", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
			{"chain": {"family": "ip", "table": "filter", "name": "INPUT", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}}
		]
	}`

	chains, err := parseNFTForwardBaseChains([]byte(ruleset))
	if err != nil {
		t.Fatalf("parseNFTForwardBaseChains returned error: %v", err)
	}

	if len(chains) != 2 {
		t.Fatalf("expected 2 supported forward chains, got %#v", chains)
	}

	if chains[0] != (nftBaseChain{family: "ip", table: "filter", name: "FORWARD"}) {
		t.Fatalf("unexpected first chain: %#v", chains[0])
	}
	if chains[1] != (nftBaseChain{family: "inet", table: "firewalld", name: "filter_FORWARD"}) {
		t.Fatalf("unexpected second chain: %#v", chains[1])
	}
}

func TestNFTString(t *testing.T) {
	if got := nftString("pg_node_wg_forward wg0 eth0 outbound"); got != `"pg_node_wg_forward wg0 eth0 outbound"` {
		t.Fatalf("unexpected quoted nft string: %s", got)
	}
}

func TestNFTRuleHandlesWithComment(t *testing.T) {
	const chain = `table ip filter {
	chain FORWARD {
		iifname "wg0" oifname "eth0" accept comment "pg_node_wg owner=owner-1 type=forward iface=wg0 out=eth0 direction=outbound" # handle 12
		iifname "eth0" oifname "wg0" ct state established,related accept comment "pg_node_wg owner=owner-1 type=forward iface=wg0 out=eth0 direction=return" # handle 14
		iifname "wg2" oifname "eth0" accept comment "pg_node_wg owner=owner-2 type=forward iface=wg2 out=eth0 direction=outbound" # handle 18
		counter packets 0 bytes 0 # handle 20
	}
}`

	handles := nftRuleHandlesWithComment([]byte(chain), nftOwnerCommentPrefix("owner-1"))
	if strings.Join(handles, ",") != "12,14" {
		t.Fatalf("unexpected handles: %#v", handles)
	}
}

func TestNFTOwnerCommentPrefix(t *testing.T) {
	if got := nftOwnerCommentPrefix("owner-1"); got != "pg_node_wg owner=owner-1 " {
		t.Fatalf("unexpected owner prefix: %q", got)
	}
}

func TestSanitizeNFTOwnerPart(t *testing.T) {
	if got := sanitizeNFTOwnerPart(" wg/1:bad "); got != "wg_1_bad" {
		t.Fatalf("unexpected sanitized owner part: %q", got)
	}
	if got := sanitizeNFTOwnerPart(" "); got != "wg" {
		t.Fatalf("unexpected empty sanitized owner part: %q", got)
	}
}

type staticError string

func (e staticError) Error() string { return string(e) }

// The MSS clamp chain is hooked to forward too, so this enumerator would
// happily prepend an accept into it — and an accept ends its chain, leaving
// peers unclamped. That presents as "the tunnel connects, Telegram works, no
// website loads", which is a miserable thing to trace back to a rule order.
func TestParseNFTForwardBaseChainsSkipsMSSClampTable(t *testing.T) {
	ruleset := []byte(`{
		"nftables": [
			{"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "hook": "forward"}},
			{"chain": {"family": "ip", "table": "` + hostroute.MSSTable + `", "name": "clamp", "hook": "forward"}}
		]
	}`)

	chains, err := parseNFTForwardBaseChains(ruleset)
	if err != nil {
		t.Fatalf("parseNFTForwardBaseChains: %v", err)
	}
	for _, c := range chains {
		if c.table == hostroute.MSSTable {
			t.Fatalf("accept rules must never be installed into the clamp chain %s/%s", c.table, c.name)
		}
	}
	if len(chains) != 1 || chains[0].table != "filter" {
		t.Fatalf("expected only the filter FORWARD chain, got %+v", chains)
	}
}
