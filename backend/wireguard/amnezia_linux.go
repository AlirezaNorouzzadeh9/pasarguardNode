//go:build linux

package wireguard

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	amneziaBinary = "amneziawg-go"

	// amneziawg-go puts its control socket here; wgctrl only looks in
	// wgctrlSocketDir, so the two are bridged with a symlink and every
	// existing peer/stats code path keeps working untouched.
	amneziaSocketDir = "/var/run/amneziawg"
	wgctrlSocketDir  = "/var/run/wireguard"

	amneziaStartTimeout = 15 * time.Second
)

// AmneziaAvailable reports whether the userspace implementation is installed.
func AmneziaAvailable() bool {
	_, err := exec.LookPath(amneziaBinary)
	return err == nil
}

// startAmnezia brings up an AmneziaWG interface: it launches amneziawg-go,
// waits for the control socket, exposes that socket where wgctrl expects it and
// applies the obfuscation parameters. The returned func tears it all down.
func startAmnezia(ifaceName string, cfg *AmneziaConfig) (func(), error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !AmneziaAvailable() {
		return nil, fmt.Errorf("amneziawg is not installed on this node (missing %s in PATH)", amneziaBinary)
	}

	// A leftover socket from a previous run makes amneziawg-go refuse to start.
	sock := filepath.Join(amneziaSocketDir, ifaceName+".sock")
	link := filepath.Join(wgctrlSocketDir, ifaceName+".sock")
	_ = os.Remove(link)

	for _, dir := range []string{amneziaSocketDir, wgctrlSocketDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
	}

	cmd := exec.Command(amneziaBinary, "-f", ifaceName)
	cmd.Env = append(os.Environ(), "WG_PROCESS_FOREGROUND=1")
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", amneziaBinary, err)
	}

	stop := func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		_ = os.Remove(link)
		_ = os.Remove(sock)
	}

	if err := waitForSocket(sock, amneziaStartTimeout); err != nil {
		stop()
		return nil, err
	}
	if err := os.Symlink(sock, link); err != nil && !os.IsExist(err) {
		stop()
		return nil, fmt.Errorf("expose amneziawg socket to wgctrl: %w", err)
	}
	if err := applyAmneziaParams(sock, cfg); err != nil {
		stop()
		return nil, err
	}
	return stop, nil
}

func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for the amneziawg control socket at %s", path)
}

// applyAmneziaParams writes the obfuscation settings over UAPI. They are sent
// on their own rather than folded into the wgctrl call because wgctrl has no
// representation for them.
func applyAmneziaParams(sock string, cfg *AmneziaConfig) error {
	params := cfg.UAPI()
	if params == "" {
		return nil
	}
	conn, err := net.DialTimeout("unix", sock, 3*time.Second)
	if err != nil {
		return fmt.Errorf("connect to amneziawg socket: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("set=1\n" + params + "\n")); err != nil {
		return fmt.Errorf("write amneziawg parameters: %w", err)
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read amneziawg response: %w", err)
	}
	// The reply is "errno=0" on success.
	resp := strings.TrimSpace(string(buf[:n]))
	for _, line := range strings.Split(resp, "\n") {
		if strings.HasPrefix(line, "errno=") && strings.TrimSpace(line) != "errno=0" {
			return fmt.Errorf("amneziawg rejected the parameters: %s", line)
		}
	}
	return nil
}
