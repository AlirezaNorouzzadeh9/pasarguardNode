package wireguard

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAmneziaEnabled(t *testing.T) {
	cases := []struct {
		name string
		cfg  *AmneziaConfig
		want bool
	}{
		{"nil is plain wireguard", nil, false},
		{"empty is plain wireguard", &AmneziaConfig{}, false},
		{"junk packets alone enable it", &AmneziaConfig{Jc: 4, Jmin: 40, Jmax: 70}, true},
		{"padding alone enables it", &AmneziaConfig{S1: 30}, true},
		{"headers alone enable it", &AmneziaConfig{H1: 10, H2: 11, H3: 12, H4: 13}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.Enabled(); got != tc.want {
				t.Fatalf("Enabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAmneziaValidate(t *testing.T) {
	valid := AmneziaConfig{Jc: 4, Jmin: 40, Jmax: 70, S1: 30, S2: 40, H1: 10, H2: 11, H3: 12, H4: 13}

	cases := []struct {
		name    string
		mutate  func(*AmneziaConfig)
		wantErr string
	}{
		{"a sane profile passes", func(*AmneziaConfig) {}, ""},
		{"jmax is required with junk packets", func(c *AmneziaConfig) { c.Jmax = 0 }, "jmax is required"},
		{"jmin above jmax is rejected", func(c *AmneziaConfig) { c.Jmin = 100 }, "must not exceed jmax"},
		{"oversized junk is rejected", func(c *AmneziaConfig) { c.Jmax = 2000 }, "must not exceed 1280"},
		{"too many junk packets", func(c *AmneziaConfig) { c.Jc = 500 }, "between 0 and 128"},
		{"headers below 5 collide with real message types", func(c *AmneziaConfig) { c.H1 = 3 }, "must be 5 or greater"},
		{"duplicate headers are rejected", func(c *AmneziaConfig) { c.H2 = c.H1 }, "must differ"},
		{"partial headers are rejected", func(c *AmneziaConfig) { c.H4 = 0 }, "must all be set together"},
		{"colliding packet sizes are rejected", func(c *AmneziaConfig) { c.S1, c.S2 = 30, 86 }, "must not equal s2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mutate(&cfg)
			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestAmneziaValidateSkipsPlainWireGuard(t *testing.T) {
	// A disabled block must never block an ordinary core from starting.
	if err := (&AmneziaConfig{Jmin: 999, Jmax: 1}).Validate(); err != nil {
		t.Fatalf("a disabled config must validate, got %v", err)
	}
	var nilCfg *AmneziaConfig
	if err := nilCfg.Validate(); err != nil {
		t.Fatalf("nil config must validate, got %v", err)
	}
}

func TestAmneziaUAPI(t *testing.T) {
	cfg := &AmneziaConfig{Jc: 4, Jmin: 40, Jmax: 70, S1: 30, S2: 40, H1: 10, H2: 11, H3: 12, H4: 13}
	got := cfg.UAPI()
	for _, want := range []string{"jc=4", "jmin=40", "jmax=70", "s1=30", "s2=40", "h1=10", "h2=11", "h3=12", "h4=13"} {
		if !strings.Contains(got, want+"\n") {
			t.Fatalf("UAPI() missing %q, got:\n%s", want, got)
		}
	}
	if (&AmneziaConfig{}).UAPI() != "" {
		t.Fatal("a disabled config must render no UAPI lines")
	}
}

// The obfuscation block is optional: an existing core config with no "amnezia"
// key must keep parsing and stay plain WireGuard.
func TestConfigParsesWithoutAmnezia(t *testing.T) {
	cfg, err := NewConfig(`{"interface_name":"wg0","private_key":"","listen_port":51820,"address":["10.0.0.1/24"]}`)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if cfg.Amnezia.Enabled() {
		t.Fatal("a config without an amnezia block must not enable obfuscation")
	}
}

func TestConfigParsesAmneziaBlock(t *testing.T) {
	raw := `{"interface_name":"wg0","private_key":"","listen_port":51820,"address":["10.0.0.1/24"],
	         "amnezia":{"jc":4,"jmin":40,"jmax":70,"s1":30,"s2":40,"h1":10,"h2":11,"h3":12,"h4":13}}`
	var probe struct {
		Amnezia *AmneziaConfig `json:"amnezia"`
	}
	if err := json.Unmarshal([]byte(raw), &probe); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !probe.Amnezia.Enabled() {
		t.Fatal("amnezia block should enable obfuscation")
	}
	if err := probe.Amnezia.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}
