package singbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Config is the sing-box config the panel sent, plus the few things this
// backend needs to pull out of it to drive the process.
//
// The config itself is kept verbatim and written to disk unchanged. sing-box
// owns its own schema; re-serialising it from parsed structs would silently
// drop any field this node does not know about.
type Config struct {
	raw string

	// Where users are pushed. sing-box takes them over HTTP on clash_api, not
	// over the stats gRPC.
	clashAPIAddress string
	clashAPISecret  string

	// Where usage is read. A separate endpoint, and a separate protocol.
	statsAddress string

	// Inbounds whose users this backend owns. Users are replaced per inbound,
	// so the tags have to be known up front — and so does each one's protocol,
	// because they do not all authenticate with the same kind of secret.
	inbounds []managedInbound
}

// managedInbound is one inbound this backend pushes users to.
type managedInbound struct {
	tag  string
	kind credentialKind
}

// credentialKind is which of a user's secrets an inbound authenticates with.
type credentialKind int

const (
	credHysteria2 credentialKind = iota
	credVLESS
	credVMess
	credTrojan
	credShadowsocks
)

// Inbound types this backend can hand users to, and the secret each expects.
//
// The protocol matters, not just the tag. A vless inbound authenticates a uuid
// and a hysteria2 inbound a password, and they are different values on the same
// user — so pushing one user list to every inbound only works if each inbound
// is sent the field its own protocol reads.
//
// Getting this wrong is silent. The core accepts a vless user whose uuid is
// missing and stores the zero uuid; nothing is logged, the push returns 200,
// and the inbound simply never authenticates anyone. That is exactly what this
// backend did while it knew only hysteria2: every other inbound was left out of
// the tag list entirely and never received a user at all.
var supportedInbounds = map[string]credentialKind{
	"hysteria2":   credHysteria2,
	"vless":       credVLESS,
	"vmess":       credVMess,
	"trojan":      credTrojan,
	"shadowsocks": credShadowsocks,
}

func NewConfig(configStr string) (*Config, error) {
	if strings.TrimSpace(configStr) == "" {
		return nil, errors.New("singbox: empty config")
	}

	var parsed struct {
		Experimental struct {
			ClashAPI struct {
				ExternalController string `json:"external_controller"`
				Secret             string `json:"secret"`
			} `json:"clash_api"`
			V2RayAPI struct {
				Listen string `json:"listen"`
				Stats  struct {
					Enabled bool     `json:"enabled"`
					Users   []string `json:"users"`
				} `json:"stats"`
			} `json:"v2ray_api"`
		} `json:"experimental"`
		Inbounds []struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(configStr), &parsed); err != nil {
		return nil, fmt.Errorf("singbox: config is not valid json: %w", err)
	}

	cfg := &Config{
		raw:             configStr,
		clashAPIAddress: strings.TrimSpace(parsed.Experimental.ClashAPI.ExternalController),
		clashAPISecret:  parsed.Experimental.ClashAPI.Secret,
		statsAddress:    strings.TrimSpace(parsed.Experimental.V2RayAPI.Listen),
	}

	// The panel validates these too, but a config can also arrive from a
	// worker rebuilding state, and a core that starts without them looks
	// healthy while doing nothing: no users ever arrive, or their traffic is
	// counted against nobody.
	if cfg.clashAPIAddress == "" {
		return nil, errors.New(
			"singbox: experimental.clash_api.external_controller is required; " +
				"without it this backend cannot push users",
		)
	}
	if cfg.statsAddress == "" {
		return nil, errors.New(
			"singbox: experimental.v2ray_api.listen is required; " +
				"without it there is no per-user usage to report",
		)
	}
	if !parsed.Experimental.V2RayAPI.Stats.Enabled {
		return nil, errors.New("singbox: experimental.v2ray_api.stats.enabled must be true")
	}
	if !containsWildcard(parsed.Experimental.V2RayAPI.Stats.Users) {
		return nil, errors.New(
			`singbox: experimental.v2ray_api.stats.users must contain "*"; ` +
				"that list is read once at startup, so users added later would pass traffic counted against nobody",
		)
	}

	for _, inbound := range parsed.Inbounds {
		tag := strings.TrimSpace(inbound.Tag)
		kind, supported := supportedInbounds[inbound.Type]
		if tag == "" || !supported {
			continue
		}
		cfg.inbounds = append(cfg.inbounds, managedInbound{tag: tag, kind: kind})
	}
	if len(cfg.inbounds) == 0 {
		return nil, errors.New("singbox: config has no inbound this backend can manage users for")
	}

	return cfg, nil
}

func containsWildcard(users []string) bool {
	for _, u := range users {
		if strings.TrimSpace(u) == "*" {
			return true
		}
	}
	return false
}

// InstanceID distinguishes two sing-box cores on one node. The first managed
// inbound tag is used for the same reason OpenVPN uses its inbound_tag: it is
// what the panel names the core's inbound by, so two cores never collide.
func (c *Config) InstanceID() string {
	if len(c.inbounds) == 0 {
		return ""
	}
	return c.inbounds[0].tag
}

func (c *Config) String() string { return c.raw }
