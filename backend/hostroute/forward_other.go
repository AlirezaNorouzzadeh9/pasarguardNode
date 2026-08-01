//go:build !linux

package hostroute

// The host firewall rules only exist on Linux; everywhere else these are no-ops
// so the backends can call them unconditionally.

func EnsureForwardAcceptForSubnet(subnet, ownerID string) ([]string, error) { return nil, nil }

func RemoveForwardRules(ownerID string) error { return nil }

func EnsureMSSClampForSubnet(subnet, ownerID string) (int, error) { return 0, nil }

func RemoveMSSClamp(ownerID string) error { return nil }

func PathMSS() (int, error) { return 0, nil }

func StartMSSRefresher(subnet, ownerID string, logf func(format string, args ...any)) func() {
	return func() {}
}
