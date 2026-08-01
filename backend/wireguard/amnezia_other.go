//go:build !linux

package wireguard

import "errors"

// AmneziaWG needs a TUN device and a unix control socket, so it only exists on
// Linux; the stubs keep the rest of the package building elsewhere.

func AmneziaAvailable() bool { return false }

func startAmnezia(ifaceName string, cfg *AmneziaConfig) (func(), error) {
	return nil, errors.New("amneziawg is only supported on linux")
}
