//go:build linux

package openvpn

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

const (
	envOpenVPNHostRouting  = "PG_NODE_OPENVPN_HOST_ROUTING"
	envOpenVPNNATInterface = "PG_NODE_OPENVPN_NAT_OUTPUT_INTERFACE"
	ipv4ForwardPath        = "/proc/sys/net/ipv4/ip_forward"
)

// applyHostRouting enables IPv4 forwarding and installs an iptables MASQUERADE
// rule for the OpenVPN server subnet, returning a cleanup closure.
//
// Disable with PG_NODE_OPENVPN_HOST_ROUTING=0.
func applyHostRouting(serverSubnet string) func() {
	if v := strings.TrimSpace(os.Getenv(envOpenVPNHostRouting)); v == "0" || strings.EqualFold(v, "false") {
		return nil
	}
	if strings.TrimSpace(serverSubnet) == "" {
		return nil
	}

	if err := ensureIPv4Forwarding(); err != nil {
		log.Printf("openvpn host routing: enabling IPv4 forwarding failed: %v", err)
	}

	outIf := strings.TrimSpace(os.Getenv(envOpenVPNNATInterface))

	masq := func(action string) error {
		args := []string{"-t", "nat", action, "POSTROUTING", "-s", serverSubnet}
		if outIf != "" {
			args = append(args, "-o", outIf)
		}
		args = append(args, "-j", "MASQUERADE")
		return runIptables(args...)
	}

	// -C checks existence; add only if missing.
	if err := masq("-C"); err != nil {
		if err := masq("-A"); err != nil {
			log.Printf("openvpn host routing: iptables masquerade failed: %v", err)
		}
	}

	return func() {
		if err := masq("-D"); err != nil {
			log.Printf("openvpn host routing: iptables cleanup failed: %v", err)
		}
	}
}

func ensureIPv4Forwarding() error {
	out, err := os.ReadFile(ipv4ForwardPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", ipv4ForwardPath, err)
	}
	if strings.TrimSpace(string(out)) == "1" {
		return nil
	}
	if err := os.WriteFile(ipv4ForwardPath, []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", ipv4ForwardPath, err)
	}
	return nil
}

func runIptables(args ...string) error {
	cmd := exec.Command("iptables", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
