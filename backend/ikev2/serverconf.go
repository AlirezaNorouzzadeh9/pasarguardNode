package ikev2

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (o *IKEv2) swanctlDir() string { return filepath.Join(o.config.workDir, "swanctl") }

// writeConfig lays out the swanctl directory and certificate material.
func (o *IKEv2) writeConfig() error {
	dir := o.swanctlDir()
	for _, sub := range []string{"conf.d", "x509", "x509ca", "private"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return err
		}
	}
	files := map[string]string{
		filepath.Join(dir, "x509", "server.pem"):   o.config.ServerCert,
		filepath.Join(dir, "x509ca", "ca.pem"):     o.config.CACert,
		filepath.Join(dir, "private", "server.key"): o.config.ServerKey,
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return err
		}
	}
	return o.writeSwanctl()
}

// writeSwanctl (re)writes the connection/pool/secrets config from current users.
func (o *IKEv2) writeSwanctl() error {
	tag := o.config.InboundTag
	ike := strings.Join(o.config.IKEProposals, ",")
	esp := strings.Join(o.config.ESPProposals, ",")
	dns := strings.Join(o.config.DNS, ",")

	var b strings.Builder
	fmt.Fprintf(&b, "connections {\n")
	fmt.Fprintf(&b, "    %s {\n", tag)
	fmt.Fprintf(&b, "        version = 2\n")
	fmt.Fprintf(&b, "        proposals = %s\n", ike)
	fmt.Fprintf(&b, "        rekey_time = 4h\n")
	fmt.Fprintf(&b, "        encap = yes\n")
	fmt.Fprintf(&b, "        dpd_delay = 30s\n")
	fmt.Fprintf(&b, "        fragmentation = yes\n")
	fmt.Fprintf(&b, "        pools = %s-pool\n", tag)
	fmt.Fprintf(&b, "        send_cert = always\n")
	fmt.Fprintf(&b, "        local {\n")
	fmt.Fprintf(&b, "            auth = pubkey\n")
	fmt.Fprintf(&b, "            certs = server.pem\n")
	fmt.Fprintf(&b, "            id = %s\n", o.config.Identity)
	fmt.Fprintf(&b, "        }\n")
	fmt.Fprintf(&b, "        remote {\n")
	fmt.Fprintf(&b, "            auth = eap-mschapv2\n")
	fmt.Fprintf(&b, "            eap_id = %%any\n")
	fmt.Fprintf(&b, "        }\n")
	fmt.Fprintf(&b, "        children {\n")
	fmt.Fprintf(&b, "            %s {\n", tag)
	fmt.Fprintf(&b, "                esp_proposals = %s\n", esp)
	fmt.Fprintf(&b, "                local_ts = 0.0.0.0/0,::/0\n")
	fmt.Fprintf(&b, "                rekey_time = 1h\n")
	fmt.Fprintf(&b, "                dpd_action = clear\n")
	fmt.Fprintf(&b, "            }\n")
	fmt.Fprintf(&b, "        }\n")
	fmt.Fprintf(&b, "    }\n")
	fmt.Fprintf(&b, "}\n\n")

	fmt.Fprintf(&b, "pools {\n")
	fmt.Fprintf(&b, "    %s-pool {\n", tag)
	fmt.Fprintf(&b, "        addrs = %s\n", o.config.Pool)
	if dns != "" {
		fmt.Fprintf(&b, "        dns = %s\n", dns)
	}
	fmt.Fprintf(&b, "    }\n")
	fmt.Fprintf(&b, "}\n\n")

	fmt.Fprintf(&b, "secrets {\n")
	for username, entry := range o.users.snapshot() {
		fmt.Fprintf(&b, "    eap-%s {\n", username)
		fmt.Fprintf(&b, "        id = %s\n", username)
		fmt.Fprintf(&b, "        secret = %q\n", entry.password)
		fmt.Fprintf(&b, "    }\n")
	}
	fmt.Fprintf(&b, "}\n")

	return os.WriteFile(filepath.Join(o.swanctlDir(), "conf.d", "ikev2.conf"), []byte(b.String()), 0o600)
}
