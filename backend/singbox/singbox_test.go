package singbox

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

func testCert(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"test.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

func jsonLines(s string) string {
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		out = append(out, `"`+strings.TrimRight(l, "\r")+`"`)
	}
	return strings.Join(out, ",")
}

func hysteriaConfig(t *testing.T, port int) string {
	t.Helper()
	certPEM, keyPEM := testCert(t)
	return fmt.Sprintf(`{
  "log": {"level": "error"},
  "inbounds": [{
    "type": "hysteria2", "tag": "hy2", "listen": "127.0.0.1", "listen_port": %d,
    "users": [],
    "tls": {"enabled": true, "server_name": "test.local", "certificate": [%s], "key": [%s]}
  }],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}`, port, jsonLines(certPEM), jsonLines(keyPEM))
}

func hysteriaUser(email, auth string) *common.User {
	return &common.User{
		Email:   email,
		Proxies: &common.Proxy{Hysteria: &common.Hysteria{Auth: auth}},
	}
}

// A config with no stats service of its own still gets one, because per-user
// traffic is the only way the panel can bill anything.
func TestNewConfigEnablesStatsAPI(t *testing.T) {
	cfg, err := NewConfig(hysteriaConfig(t, 21443))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if cfg.Options.Experimental == nil || cfg.Options.Experimental.V2RayAPI == nil {
		t.Fatal("stats api was not added")
	}
	if !cfg.Options.Experimental.V2RayAPI.Stats.Enabled {
		t.Fatal("stats not enabled")
	}
	if !strings.HasPrefix(cfg.APIAddr, apiListenHost+":") {
		t.Fatalf("stats api should listen on loopback, got %q", cfg.APIAddr)
	}
	if len(cfg.InboundTags) != 1 || cfg.InboundTags[0] != "hy2" {
		t.Fatalf("inbound tags = %v", cfg.InboundTags)
	}
}

// An inbound without a tag would leave the panel unable to attach hosts or
// users to it, so it is rejected rather than silently accepted.
func TestNewConfigRejectsUntaggedInbound(t *testing.T) {
	_, err := NewConfig(`{"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":21999}],
	                      "outbounds":[{"type":"direct"}]}`)
	if err == nil {
		t.Fatal("expected an error for an inbound with no tag")
	}
}

// Users are matched to the protocol's own credential: a user with no hysteria
// secret must not become a broken entry.
func TestApplyUsersOnlyTakesMatchingCredentials(t *testing.T) {
	cfg, err := NewConfig(hysteriaConfig(t, 21444))
	if err != nil {
		t.Fatal(err)
	}
	in, ok := cfg.InboundOptions("hy2")
	if !ok {
		t.Fatal("inbound not found")
	}

	users := []*common.User{
		hysteriaUser("alice", "secret-a"),
		{Email: "bob", Proxies: &common.Proxy{}}, // no hysteria credential
		hysteriaUser("carol", "secret-c"),
	}
	applied, err := applyUsers(in, users)
	if err != nil {
		t.Fatal(err)
	}
	opts := applied.Options.(*option.Hysteria2InboundOptions)
	if len(opts.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(opts.Users))
	}
	got := map[string]string{}
	for _, u := range opts.Users {
		got[u.Name] = u.Password
	}
	if got["alice"] != "secret-a" || got["carol"] != "secret-c" {
		t.Fatalf("credentials not carried through: %v", got)
	}
	if _, present := got["bob"]; present {
		t.Fatal("a user without a hysteria credential must be skipped")
	}
}

// The whole point of embedding sing-box: a user change must not require
// restarting the instance.
func TestSyncUsersRebuildsInboundWithoutRestart(t *testing.T) {
	cfg, err := NewConfig(hysteriaConfig(t, 21445))
	if err != nil {
		t.Fatal(err)
	}
	sb, err := New(&config.Config{LogBufferSize: 16}, cfg, nil)
	if err != nil {
		t.Skipf("sing-box could not start (build tags?): %v", err)
	}
	defer sb.Shutdown()

	if !sb.Started() {
		t.Fatal("backend did not start")
	}
	instance := sb.instance
	before, ok := instance.Inbound().Get("hy2")
	if !ok {
		t.Fatal("inbound missing after start")
	}

	if err := sb.SyncUsers(context.Background(), []*common.User{hysteriaUser("alice", "secret-a")}); err != nil {
		t.Fatalf("SyncUsers: %v", err)
	}

	if sb.instance != instance {
		t.Fatal("the instance was replaced; a user change must not restart sing-box")
	}
	after, ok := instance.Inbound().Get("hy2")
	if !ok {
		t.Fatal("inbound missing after sync")
	}
	if after == before {
		t.Fatal("the inbound was not rebuilt, so the new user cannot be active")
	}
}

// A user sync arrives on a gRPC request context that is cancelled the moment
// the RPC returns. Rebuilding the inbound with that context made the fresh
// listener close immediately ("listener closed: context canceled") and the
// protocol went dead until the next restart.
func TestSyncSurvivesTheCallerCancellingItsContext(t *testing.T) {
	cfg, err := NewConfig(hysteriaConfig(t, 21446))
	if err != nil {
		t.Fatal(err)
	}
	sb, err := New(&config.Config{LogBufferSize: 16}, cfg, nil)
	if err != nil {
		t.Skipf("sing-box could not start (build tags?): %v", err)
	}
	defer sb.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	if err := sb.SyncUsers(ctx, []*common.User{hysteriaUser("alice", "secret-a")}); err != nil {
		t.Fatalf("SyncUsers: %v", err)
	}
	cancel() // the RPC returns; its context dies

	time.Sleep(300 * time.Millisecond)

	inbound, ok := sb.instance.Inbound().Get("hy2")
	if !ok {
		t.Fatal("the inbound disappeared after the caller's context was cancelled")
	}

	// A second sync must still work against that inbound.
	if err := sb.SyncUsers(context.Background(), []*common.User{hysteriaUser("bob", "secret-b")}); err != nil {
		t.Fatalf("second SyncUsers: %v", err)
	}
	if after, ok := sb.instance.Inbound().Get("hy2"); !ok || after == inbound {
		t.Fatal("the inbound was not rebuilt on the second sync")
	}
}
