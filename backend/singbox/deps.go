package singbox

import "github.com/sagernet/sing-box/constant"

// DetectVersion reports the sing-box version this node was built against.
//
// Unlike xray and openvpn there is no external binary to probe: sing-box is
// linked into the node, so its version is fixed at build time.
func DetectVersion() string {
	return constant.Version
}

// CheckDeps exists for symmetry with the other backends. sing-box needs nothing
// installed on the host, so it is always available — but the QUIC-based
// protocols (hysteria2, tuic) only work if the binary was built with the
// `with_quic` tag, which the Dockerfile sets.
func CheckDeps() error { return nil }
