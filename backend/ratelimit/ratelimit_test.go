package ratelimit

import (
	"strings"
	"testing"
)

// fakeRunner records commands instead of touching the kernel.
type fakeRunner struct {
	cmds []string
	// failFor makes any command containing this substring fail.
	failFor string
}

func (f *fakeRunner) run(name string, args ...string) error {
	line := name + " " + strings.Join(args, " ")
	f.cmds = append(f.cmds, line)
	if f.failFor != "" && strings.Contains(line, f.failFor) {
		return errFake
	}
	// `iptables -C` must report "absent" so the add path is exercised.
	if strings.Contains(line, "iptables") && strings.Contains(line, " -C ") {
		return errFake
	}
	return nil
}

func (f *fakeRunner) output(string, ...string) (string, error) { return "", nil }

func (f *fakeRunner) contains(substr string) bool {
	for _, c := range f.cmds {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func (f *fakeRunner) count(substr string) int {
	n := 0
	for _, c := range f.cmds {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

type fakeErr struct{}

func (fakeErr) Error() string { return "fake failure" }

var errFake = fakeErr{}

func newTestManager() (*Manager, *fakeRunner) {
	r := &fakeRunner{}
	m := New("eth0")
	m.runner = r
	return m, r
}

func TestApplyShapesEachDirection(t *testing.T) {
	m, r := newTestManager()

	if err := m.Apply([]Client{{User: "alice", Address: "10.29.0.5", LimitKbps: 8000}}); err != nil {
		t.Fatal(err)
	}

	if !r.contains("tc qdisc add dev eth0 root handle 1: htb") {
		t.Fatal("expected the HTB root to be installed on first use")
	}
	// One class and one mark rule per direction.
	if got := r.count("tc class add dev eth0"); got < 3 {
		t.Fatalf("expected a default class plus one per direction, got %d class adds", got)
	}
	if !r.contains("-d 10.29.0.5") {
		t.Fatal("download traffic must be matched on the destination address")
	}
	if !r.contains("-s 10.29.0.5") {
		t.Fatal("upload traffic must be matched on the source address")
	}
	if !r.contains("rate 8000kbit") {
		t.Fatal("the class rate must be the user's ceiling")
	}
	// Marking has to happen in mangle FORWARD: that is the only place an IPsec
	// client's tunnel address is still readable.
	if !r.contains("-t mangle -A FORWARD") {
		t.Fatal("marks must be set in mangle FORWARD")
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	m, r := newTestManager()
	client := []Client{{User: "alice", Address: "10.29.0.5", LimitKbps: 8000}}

	if err := m.Apply(client); err != nil {
		t.Fatal(err)
	}
	before := len(r.cmds)
	if err := m.Apply(client); err != nil {
		t.Fatal(err)
	}
	if len(r.cmds) != before {
		t.Fatalf("re-applying an unchanged set must not touch anything, got %d extra commands", len(r.cmds)-before)
	}
}

func TestApplyUpdatesChangedCeiling(t *testing.T) {
	m, r := newTestManager()
	if err := m.Apply([]Client{{User: "alice", Address: "10.29.0.5", LimitKbps: 8000}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply([]Client{{User: "alice", Address: "10.29.0.5", LimitKbps: 2000}}); err != nil {
		t.Fatal(err)
	}
	if !r.contains("tc class change") || !r.contains("rate 2000kbit") {
		t.Fatal("a changed ceiling should be applied with a class change")
	}
	if r.contains("tc class del") {
		t.Fatal("changing a ceiling must not tear the client's classes down")
	}
}

func TestApplyRemovesDepartedClients(t *testing.T) {
	m, r := newTestManager()
	if err := m.Apply([]Client{
		{User: "alice", Address: "10.29.0.5", LimitKbps: 8000},
		{User: "bob", Address: "10.29.0.6", LimitKbps: 4000},
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply([]Client{{User: "alice", Address: "10.29.0.5", LimitKbps: 8000}}); err != nil {
		t.Fatal(err)
	}

	if !r.contains("-t mangle -D FORWARD -d 10.29.0.6") {
		t.Fatal("the departed client's mark rules must be removed")
	}
	if r.contains("-t mangle -D FORWARD -d 10.29.0.5") {
		t.Fatal("the remaining client must be left alone")
	}
	if _, still := m.applied["10.29.0.6"]; still {
		t.Fatal("the departed client must be dropped from the applied set")
	}
}

func TestZeroLimitIsNotShaped(t *testing.T) {
	m, r := newTestManager()
	if err := m.Apply([]Client{{User: "alice", Address: "10.29.0.5", LimitKbps: 0}}); err != nil {
		t.Fatal(err)
	}
	if len(r.cmds) != 0 {
		t.Fatalf("an unlimited user must install nothing, got: %v", r.cmds)
	}
}

func TestCloseRemovesEverything(t *testing.T) {
	m, r := newTestManager()
	if err := m.Apply([]Client{{User: "alice", Address: "10.29.0.5", LimitKbps: 8000}}); err != nil {
		t.Fatal(err)
	}
	m.Close()

	if !r.contains("tc qdisc del dev eth0 root") {
		t.Fatal("Close must remove the qdisc so no shaping is left behind")
	}
	if !r.contains("-t mangle -D FORWARD") {
		t.Fatal("Close must remove the mark rules")
	}
	if len(m.applied) != 0 {
		t.Fatal("Close must clear the applied set")
	}
}

func TestMarksAreReusedAfterRemoval(t *testing.T) {
	m, _ := newTestManager()
	if err := m.Apply([]Client{{User: "alice", Address: "10.29.0.5", LimitKbps: 8000}}); err != nil {
		t.Fatal(err)
	}
	first := m.marks["10.29.0.5"]

	if err := m.Apply(nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply([]Client{{User: "bob", Address: "10.29.0.9", LimitKbps: 1000}}); err != nil {
		t.Fatal(err)
	}
	if got := m.marks["10.29.0.9"]; got != first {
		t.Fatalf("a freed mark should be handed to the next client: got %#x, want %#x", got, first)
	}
}

func TestDownloadAndUploadGetDistinctClasses(t *testing.T) {
	down := classID(firstMark, Download)
	up := classID(firstMark, Upload)
	if down == up {
		t.Fatal("the two directions must not share a class, or the cap would be halved")
	}
	if markValue(firstMark, Download) == markValue(firstMark, Upload) {
		t.Fatal("the two directions must not share a mark, or one filter would catch both")
	}
}
