package wireguard

// AmneziaWG support.
//
// Plain WireGuard is trivially fingerprintable: its handshake packets have a
// fixed size and fixed header bytes, so a DPI box can block it with one rule.
// AmneziaWG keeps the cryptography identical but pads the handshake, prepends
// junk packets and randomises the message-type headers, which removes that
// signature.
//
// The node runs it through amneziawg-go, a userspace implementation that speaks
// the same UAPI protocol as the kernel module. Only the obfuscation knobs are
// extra, so once the control socket is in place every existing code path — peer
// sync, stats, device limits — keeps working unchanged.
//
// Every value here has to match on both ends of the tunnel; a client with
// different numbers simply never completes a handshake.

import (
	"fmt"
	"sort"
	"strings"
)

// AmneziaConfig holds the obfuscation parameters. All fields are optional in
// the JSON so an ordinary WireGuard core stays exactly that; the presence of
// this block is what switches the interface to AmneziaWG.
type AmneziaConfig struct {
	// Junk packets sent before the real handshake: how many, and the byte
	// range of each.
	Jc   int `json:"jc,omitempty"`
	Jmin int `json:"jmin,omitempty"`
	Jmax int `json:"jmax,omitempty"`

	// Padding added to each message type, which is what breaks the
	// fixed-size fingerprint.
	S1 int `json:"s1,omitempty"`
	S2 int `json:"s2,omitempty"`

	// Replacement values for the four message-type headers, which is what
	// breaks the fixed-header fingerprint. They must be distinct.
	H1 int64 `json:"h1,omitempty"`
	H2 int64 `json:"h2,omitempty"`
	H3 int64 `json:"h3,omitempty"`
	H4 int64 `json:"h4,omitempty"`
}

// Enabled reports whether this core should run as AmneziaWG.
func (a *AmneziaConfig) Enabled() bool {
	if a == nil {
		return false
	}
	return a.Jc > 0 || a.S1 > 0 || a.S2 > 0 || a.H1 != 0 || a.H2 != 0 || a.H3 != 0 || a.H4 != 0
}

// Validate rejects settings that would produce an interface no client can talk
// to. amneziawg-go itself accepts some of these and then silently fails to
// handshake, which is a miserable thing to debug from the panel.
func (a *AmneziaConfig) Validate() error {
	if !a.Enabled() {
		return nil
	}
	if a.Jc < 0 || a.Jc > 128 {
		return fmt.Errorf("amnezia: jc must be between 0 and 128, got %d", a.Jc)
	}
	if a.Jmin < 0 || a.Jmax < 0 {
		return fmt.Errorf("amnezia: jmin/jmax must not be negative")
	}
	if a.Jc > 0 {
		if a.Jmax == 0 {
			return fmt.Errorf("amnezia: jmax is required when jc > 0")
		}
		if a.Jmin > a.Jmax {
			return fmt.Errorf("amnezia: jmin (%d) must not exceed jmax (%d)", a.Jmin, a.Jmax)
		}
		if a.Jmax > 1280 {
			return fmt.Errorf("amnezia: jmax must not exceed 1280, got %d", a.Jmax)
		}
	}
	if a.S1 < 0 || a.S2 < 0 {
		return fmt.Errorf("amnezia: s1/s2 must not be negative")
	}
	if a.S1 > 1132 || a.S2 > 1188 {
		return fmt.Errorf("amnezia: s1/s2 are too large (max 1132/1188)")
	}
	// A handshake-initiation packet padded by S1 must not collide with the
	// response packet size, or the peers cannot tell the two apart.
	if a.S1+56 == a.S2 {
		return fmt.Errorf("amnezia: s1+56 must not equal s2 (both would produce the same packet size)")
	}

	headers := map[string]int64{"h1": a.H1, "h2": a.H2, "h3": a.H3, "h4": a.H4}
	seen := make(map[int64]string, 4)
	for _, name := range sortedKeys(headers) {
		v := headers[name]
		if v == 0 {
			continue
		}
		if v < 5 {
			return fmt.Errorf("amnezia: %s must be 5 or greater (1-4 are the real WireGuard message types)", name)
		}
		if other, dup := seen[v]; dup {
			return fmt.Errorf("amnezia: %s and %s must differ (both are %d)", other, name, v)
		}
		seen[v] = name
	}
	if len(seen) != 0 && len(seen) != 4 {
		return fmt.Errorf("amnezia: h1-h4 must all be set together, got %d of 4", len(seen))
	}
	return nil
}

// UAPI renders the device-level lines amneziawg-go expects. Peers are left to
// the normal wgctrl path.
func (a *AmneziaConfig) UAPI() string {
	if !a.Enabled() {
		return ""
	}
	var b strings.Builder
	write := func(key string, value int64) {
		if value != 0 {
			fmt.Fprintf(&b, "%s=%d\n", key, value)
		}
	}
	write("jc", int64(a.Jc))
	write("jmin", int64(a.Jmin))
	write("jmax", int64(a.Jmax))
	write("s1", int64(a.S1))
	write("s2", int64(a.S2))
	write("h1", a.H1)
	write("h2", a.H2)
	write("h3", a.H3)
	write("h4", a.H4)
	return b.String()
}

func sortedKeys(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
