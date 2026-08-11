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
	// so the tags have to be known up front.
	inboundTags []string
}

// Inbound types this backend can hand users to. The generic
// PUT /inbounds/{tag}/users endpoint dispatches per protocol, and only
// hysteria2 has the exported UpdateUsers it needs so far.
var supportedInbounds = map[string]bool{"hysteria2": true}

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
		if tag == "" || !supportedInbounds[inbound.Type] {
			continue
		}
		cfg.inboundTags = append(cfg.inboundTags, tag)
	}
	if len(cfg.inboundTags) == 0 {
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
	if len(c.inboundTags) == 0 {
		return ""
	}
	return c.inboundTags[0]
}

func (c *Config) String() string { return c.raw }
