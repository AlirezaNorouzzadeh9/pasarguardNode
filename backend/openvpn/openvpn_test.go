package openvpn

import (
	"testing"

	"github.com/pasarguard/node/common"
)

func openvpnUser(email, serial string, inbounds ...string) *common.User {
	return &common.User{
		Email:    email,
		Inbounds: inbounds,
		Proxies: &common.Proxy{
			Openvpn: &common.Openvpn{Serial: serial},
		},
	}
}

func TestParseStatusLine(t *testing.T) {
	line := "CLIENT_LIST\t42\t1.2.3.4:1194\t10.29.0.2\t\t1000\t2000\tThu Jul 10\t1720000000\tUNDEF\t7\t0\tAES-256-GCM"
	cs, ok := parseStatusLine(line)
	if !ok {
		t.Fatal("expected parse ok")
	}
	if cs.CommonName != "42" {
		t.Errorf("cn = %q", cs.CommonName)
	}
	if cs.BytesReceived != 1000 || cs.BytesSent != 2000 {
		t.Errorf("bytes rx=%d tx=%d", cs.BytesReceived, cs.BytesSent)
	}
	if cs.ClientID != "7" {
		t.Errorf("clientID = %q", cs.ClientID)
	}
}

func TestParseStatusLineRejectsNonClientList(t *testing.T) {
	if _, ok := parseStatusLine("ROUTING_TABLE\t10.29.0.2\t42"); ok {
		t.Fatal("should reject non CLIENT_LIST line")
	}
}

func TestUserStoreAuthorize(t *testing.T) {
	s := newUserStore("ovpn")
	s.replaceAll([]*common.User{openvpnUser("42", "12345", "ovpn")})

	// known CN, matching serial
	if !s.authorize("42", "12345") {
		t.Error("expected authorize for matching serial")
	}
	// known CN, wrong serial
	if s.authorize("42", "99999") {
		t.Error("expected deny for wrong serial")
	}
	// unknown CN
	if s.authorize("7", "12345") {
		t.Error("expected deny for unknown cn")
	}
}

func TestUserStoreEmptySerialAllowsAny(t *testing.T) {
	s := newUserStore("ovpn")
	s.replaceAll([]*common.User{openvpnUser("42", "", "ovpn")})
	if !s.authorize("42", "anything") {
		t.Error("empty pinned serial should allow any connecting serial")
	}
}

func TestUserStoreMembershipRequiresInbound(t *testing.T) {
	s := newUserStore("ovpn")
	// user not in the openvpn inbound -> not authorized
	s.replaceAll([]*common.User{openvpnUser("42", "1", "other-inbound")})
	if s.authorize("42", "1") {
		t.Error("user without the openvpn inbound should be denied")
	}
}

func TestApplyUserRemoveAndReissue(t *testing.T) {
	s := newUserStore("ovpn")
	s.replaceAll([]*common.User{openvpnUser("42", "1", "ovpn")})

	// reissue: same CN, new serial -> changedSerial
	_, changed, removed := s.applyUser(openvpnUser("42", "2", "ovpn"))
	if !changed || removed {
		t.Errorf("expected changedSerial, got changed=%v removed=%v", changed, removed)
	}
	if !s.authorize("42", "2") || s.authorize("42", "1") {
		t.Error("store should now pin the new serial only")
	}

	// removal: user drops the inbound -> removed
	_, _, removed = s.applyUser(openvpnUser("42", "2", "other"))
	if !removed {
		t.Error("expected removed when inbound dropped")
	}
	if s.has("42") {
		t.Error("cn should be gone after removal")
	}
}

func TestReplaceAllReportsRemoved(t *testing.T) {
	s := newUserStore("ovpn")
	s.replaceAll([]*common.User{
		openvpnUser("1", "a", "ovpn"),
		openvpnUser("2", "b", "ovpn"),
	})
	removed := s.replaceAll([]*common.User{openvpnUser("1", "a", "ovpn")})
	if len(removed) != 1 || removed[0] != "2" {
		t.Errorf("expected [2] removed, got %v", removed)
	}
}

func TestConfigDefaultsAndValidation(t *testing.T) {
	_, err := NewConfig(`{"port":1194,"server_subnet":"10.29.0.0/16","ca_cert":"x","server_cert":"y","server_key":"z"}`)
	if err == nil {
		t.Error("expected error for missing inbound_tag")
	}

	cfg, err := NewConfig(`{"inbound_tag":"ovpn","port":1194,"server_subnet":"10.29.0.0/16","ca_cert":"x","server_cert":"y","server_key":"z"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Proto != "udp" || cfg.Cipher != "AES-256-GCM" || cfg.MaxClients != 1024 {
		t.Errorf("defaults not applied: %+v", cfg)
	}
}

func TestRenderServerConf(t *testing.T) {
	cfg := &Config{
		InboundTag:   "ovpn",
		Port:         1194,
		Proto:        "udp",
		Device:       "tun",
		ServerSubnet: "10.29.0.0/16",
		Cipher:       "AES-256-GCM",
		DataCiphers:  []string{"AES-256-GCM", "CHACHA20-POLY1305"},
		Auth:         "SHA256",
		Keepalive:    "10 60",
		MaxClients:   1024,
		DuplicateCN:  true,
		DNS:          []string{"1.1.1.1"},
		TLSCryptKey:  "-----BEGIN OpenVPN Static key V1-----\nx\n-----END OpenVPN Static key V1-----\n",
		workDir:      "/tmp/ovpn",
	}
	conf, err := cfg.renderServerConf()
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	for _, want := range []string{
		"port 1194",
		"proto udp",
		"server 10.29.0.0 255.255.0.0",
		"topology subnet",
		"management-client-auth",
		"verify-client-cert require",
		"status-version 3",
		"duplicate-cn",
		"tls-crypt tc.key",
		"data-ciphers AES-256-GCM:CHACHA20-POLY1305",
		"push \"dhcp-option DNS 1.1.1.1\"",
	} {
		if !contains(conf, want) {
			t.Errorf("server.conf missing %q\n---\n%s", want, conf)
		}
	}
}

func TestExtractIP(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4:1194":   "1.2.3.4",
		"[2001:db8::1]:5": "2001:db8::1",
		"":               "",
	}
	for in, want := range cases {
		if got := extractIP(in); got != want {
			t.Errorf("extractIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
