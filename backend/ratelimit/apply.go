package ratelimit

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// execRunner is the real implementation; tests swap in their own.
type execRunner struct{}

func (execRunner) run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (execRunner) output(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// classID is the tc handle for one (client, direction) pair, derived from the
// mark so a class is always recoverable from it. The low bits of the mark start
// at 0, but minor 0 is the root handle (1:0 == 1:), so shift by one: the first
// client's download class is 1:2, its upload 1:3, and so on.
func classID(mark uint32, dir Direction) string {
	minor := ((mark & 0xffff) + 1) * 2
	if dir == Upload {
		minor++
	}
	return fmt.Sprintf("1:%x", minor)
}

// setupRoot installs the HTB root and the one filter that maps marks to classes.
func (m *Manager) setupRoot() error {
	// A fresh start: drop anything we (or a previous crash) left behind.
	m.teardownRoot()

	if err := m.runner.run("tc", "qdisc", "add", "dev", m.iface, "root", "handle", "1:", "htb", "default", "1"); err != nil {
		return fmt.Errorf("install shaping root on %s: %w", m.iface, err)
	}
	// Class 1:1 is the default and is left unlimited, so unshaped users and the
	// node's own traffic are untouched.
	if err := m.runner.run("tc", "class", "add", "dev", m.iface, "parent", "1:", "classid", "1:1",
		"htb", "rate", "1000000mbit"); err != nil {
		return fmt.Errorf("install default class on %s: %w", m.iface, err)
	}
	// One filter for everyone: the class is taken straight from the mark.
	if err := m.runner.run("tc", "filter", "add", "dev", m.iface, "parent", "1:", "protocol", "all",
		"prio", "1", "handle", fmt.Sprintf("%d", markMask), "fw"); err != nil {
		// Not fatal on its own; per-client filters below still classify.
		log.Printf("ratelimit: mark filter on %s not installed: %v", m.iface, err)
	}
	return nil
}

func (m *Manager) teardownRoot() {
	// Ignore errors: there is usually nothing to delete.
	_ = m.runner.run("tc", "qdisc", "del", "dev", m.iface, "root")
}

// allocMark hands out a mark, reusing one from a departed client when possible.
func (m *Manager) allocMark(addr string) (uint32, error) {
	if mark, ok := m.marks[addr]; ok {
		return mark, nil
	}
	if n := len(m.freed); n > 0 {
		mark := m.freed[n-1]
		m.freed = m.freed[:n-1]
		m.marks[addr] = mark
		return mark, nil
	}
	if m.nextMark-firstMark >= maxClients {
		return 0, fmt.Errorf("too many shaped clients (max %d)", maxClients)
	}
	mark := m.nextMark
	m.nextMark++
	m.marks[addr] = mark
	return mark, nil
}

func (m *Manager) addLocked(c Client) error {
	mark, err := m.allocMark(c.Address)
	if err != nil {
		return err
	}

	for _, dir := range []Direction{Download, Upload} {
		if err := m.addClass(mark, dir, c.LimitKbps); err != nil {
			return err
		}
		if err := m.addMarkRule(c.Address, mark, dir); err != nil {
			return err
		}
	}

	m.applied[c.Address] = c
	log.Printf("ratelimit: %s (%s) capped at %d kbit/s per direction", c.User, c.Address, c.LimitKbps)
	return nil
}

func (m *Manager) updateLocked(c Client) error {
	mark, ok := m.marks[c.Address]
	if !ok {
		return m.addLocked(c)
	}
	for _, dir := range []Direction{Download, Upload} {
		if err := m.changeClass(mark, dir, c.LimitKbps); err != nil {
			return err
		}
	}
	m.applied[c.Address] = c
	log.Printf("ratelimit: %s (%s) cap changed to %d kbit/s per direction", c.User, c.Address, c.LimitKbps)
	return nil
}

func (m *Manager) removeLocked(addr string) {
	mark, ok := m.marks[addr]
	if ok {
		for _, dir := range []Direction{Download, Upload} {
			m.delMarkRule(addr, mark, dir)
			m.delClass(mark, dir)
		}
		delete(m.marks, addr)
		m.freed = append(m.freed, mark)
	}
	delete(m.applied, addr)
}

func (m *Manager) addClass(mark uint32, dir Direction, kbps uint32) error {
	rate := fmt.Sprintf("%dkbit", kbps)
	return m.runner.run("tc", "class", "add", "dev", m.iface, "parent", "1:", "classid", classID(mark, dir),
		"htb", "rate", rate, "ceil", rate)
}

func (m *Manager) changeClass(mark uint32, dir Direction, kbps uint32) error {
	rate := fmt.Sprintf("%dkbit", kbps)
	return m.runner.run("tc", "class", "change", "dev", m.iface, "parent", "1:", "classid", classID(mark, dir),
		"htb", "rate", rate, "ceil", rate)
}

func (m *Manager) delClass(mark uint32, dir Direction) {
	_ = m.runner.run("tc", "class", "del", "dev", m.iface, "classid", classID(mark, dir))
}

// markArgs builds the mangle rule that tags this client's packets. Marking
// happens in FORWARD, where the tunnel address is still readable even for
// IPsec, whose packets are encrypted before they reach the egress qdisc.
func (m *Manager) markArgs(addr string, mark uint32, dir Direction, action string) []string {
	match := "-d"
	if dir == Upload {
		match = "-s"
	}
	return []string{
		"-t", "mangle", action, "FORWARD", match, addr,
		"-j", "MARK", "--set-xmark", fmt.Sprintf("0x%x/0x%x", markValue(mark, dir), markMask),
		"-m", "comment", "--comment", commentFor(addr, dir),
	}
}

// markValue folds the direction into the mark so one fw filter can separate the
// two classes.
func markValue(mark uint32, dir Direction) uint32 {
	v := mark
	if dir == Upload {
		v |= 0x8000
	}
	return v
}

func commentFor(addr string, dir Direction) string {
	return fmt.Sprintf("pg_node_rl %s %s", addr, dir)
}

func (m *Manager) addMarkRule(addr string, mark uint32, dir Direction) error {
	// -C first: re-applying the same state should not stack duplicate rules.
	if err := m.runner.run("iptables", m.markArgs(addr, mark, dir, "-C")...); err == nil {
		return nil
	}
	if err := m.runner.run("iptables", m.markArgs(addr, mark, dir, "-A")...); err != nil {
		return fmt.Errorf("mark %s traffic for %s: %w", dir, addr, err)
	}
	// The mark alone does not pick a class; this filter does.
	return m.runner.run("tc", "filter", "add", "dev", m.iface, "parent", "1:", "protocol", "all",
		"prio", "1", "handle", fmt.Sprintf("%d", markValue(mark, dir)), "fw", "flowid", classID(mark, dir))
}

func (m *Manager) delMarkRule(addr string, mark uint32, dir Direction) {
	_ = m.runner.run("iptables", m.markArgs(addr, mark, dir, "-D")...)
	_ = m.runner.run("tc", "filter", "del", "dev", m.iface, "parent", "1:", "protocol", "all",
		"prio", "1", "handle", fmt.Sprintf("%d", markValue(mark, dir)), "fw")
}
