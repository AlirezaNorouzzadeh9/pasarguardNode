package l2tp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The session hooks used to be written to /etc/ppp/ip-up.d/, which only runs on
// distributions whose /etc/ppp/ip-up iterates that directory. This image is
// Alpine, which does not, so the hook never fired: no session file, no
// interface-to-user mapping, and a tunnel that carried traffic while the panel
// reported the user offline with zero usage.
//
// pppd is told the paths directly now, so the test asserts the two halves that
// have to agree: the scripts exist where the options file says they are.
func TestPPPOptionsNamesTheSessionHooks(t *testing.T) {
	dir := t.TempDir()
	o := &L2TP{config: &Config{
		InboundTag: "l2tp-test",
		DNS:        []string{"1.1.1.1"},
		workDir:    dir,
	}}

	if err := o.writeIPScripts(); err != nil {
		t.Fatalf("writeIPScripts: %v", err)
	}
	if err := o.writePPPOptions(); err != nil {
		t.Fatalf("writePPPOptions: %v", err)
	}

	opts, err := os.ReadFile(filepath.Join(dir, "ppp-options"))
	if err != nil {
		t.Fatalf("read ppp-options: %v", err)
	}
	text := string(opts)

	for _, directive := range []string{"ip-up-script", "ip-down-script"} {
		if !strings.Contains(text, directive) {
			t.Errorf("ppp-options does not name %s; pppd will never record a session", directive)
		}
	}

	for _, want := range []string{o.ipUpScriptPath(), o.ipDownScriptPath()} {
		if !strings.Contains(text, want) {
			t.Errorf("ppp-options does not point at %s", want)
			continue
		}
		info, err := os.Stat(want)
		if err != nil {
			t.Errorf("hook named in ppp-options is missing on disk: %v", err)
			continue
		}
		// Windows has no execute bit, and this only ever runs on Linux, so the
		// check is worth making exactly where it is meaningful.
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o100 == 0 {
			t.Errorf("%s is not executable (%v); pppd will skip it", want, info.Mode().Perm())
		}
	}
}

// A hook that writes nothing useful is as bad as no hook, so the up script has
// to record the username the poll loop attributes traffic to.
func TestIPUpHookRecordsTheUser(t *testing.T) {
	dir := t.TempDir()
	o := &L2TP{config: &Config{InboundTag: "l2tp-test", workDir: dir}}
	if err := o.writeIPScripts(); err != nil {
		t.Fatalf("writeIPScripts: %v", err)
	}
	body, err := os.ReadFile(o.ipUpScriptPath())
	if err != nil {
		t.Fatalf("read ip-up: %v", err)
	}
	for _, want := range []string{"PEERNAME", "user=", sessionStateDir} {
		if !strings.Contains(string(body), want) {
			t.Errorf("ip-up hook does not mention %q", want)
		}
	}
}
