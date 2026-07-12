package openvpn

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// clientStatus is a parsed CLIENT_LIST row from `status 3` output.
type clientStatus struct {
	CommonName    string
	RealAddress   string
	BytesReceived int64 // from client (client uplink)
	BytesSent     int64 // to client (client downlink)
	ClientID      string
}

// authDecider decides whether a connecting common name/serial is authorized.
type authDecider interface {
	authorize(commonName, serial string) bool
}

// mgmtClient talks to the OpenVPN management interface over a unix socket.
// A single reader goroutine handles both the async management-client-auth
// CONNECT events and the synchronous `status 3` output.
type mgmtClient struct {
	socketPath string
	decider    authDecider
	logf       func(format string, args ...any)

	writeMu sync.Mutex
	conn    net.Conn
	rw      *bufio.ReadWriter

	// in-flight CONNECT/REAUTH accumulation
	pendingCID string
	pendingKID string
	pendingEnv map[string]string

	// status snapshot
	statusMu    sync.Mutex
	statusBuf   []clientStatus
	lastStatus  []clientStatus
	statusReady chan struct{}
}

func newMgmtClient(socketPath string, decider authDecider, logf func(string, ...any)) *mgmtClient {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &mgmtClient{
		socketPath:  socketPath,
		decider:     decider,
		logf:        logf,
		statusReady: make(chan struct{}, 1),
	}
}

// connect dials the management socket, retrying briefly while openvpn boots.
func (m *mgmtClient) connect() error {
	var lastErr error
	for i := 0; i < 50; i++ {
		conn, err := net.Dial("unix", m.socketPath)
		if err == nil {
			m.writeMu.Lock()
			m.conn = conn
			m.rw = bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
			m.writeMu.Unlock()
			return nil
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("connect management socket %s: %w", m.socketPath, lastErr)
}

func (m *mgmtClient) close() {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	if m.conn != nil {
		_ = m.conn.Close()
		m.conn = nil
	}
}

// run reads the management event stream until the connection closes.
func (m *mgmtClient) run() {
	m.writeMu.Lock()
	rw := m.rw
	m.writeMu.Unlock()
	if rw == nil {
		return
	}
	for {
		line, err := rw.Reader.ReadString('\n')
		if err != nil {
			return
		}
		m.handleLine(strings.TrimRight(line, "\r\n"))
	}
}

func (m *mgmtClient) handleLine(line string) {
	switch {
	case strings.HasPrefix(line, ">CLIENT:CONNECT,"), strings.HasPrefix(line, ">CLIENT:REAUTH,"):
		rest := line[strings.IndexByte(line, ',')+1:]
		parts := strings.SplitN(rest, ",", 2)
		m.pendingCID = parts[0]
		m.pendingKID = ""
		if len(parts) > 1 {
			m.pendingKID = parts[1]
		}
		m.pendingEnv = make(map[string]string)
	case strings.HasPrefix(line, ">CLIENT:ENV,"):
		env := strings.TrimPrefix(line, ">CLIENT:ENV,")
		if env == "END" {
			m.finishConnect()
			return
		}
		if k, v, ok := strings.Cut(env, "="); ok && m.pendingEnv != nil {
			m.pendingEnv[k] = v
		}
	case strings.HasPrefix(line, "CLIENT_LIST\t"):
		if cs, ok := parseStatusLine(line); ok {
			m.statusBuf = append(m.statusBuf, cs)
		}
	case line == "END":
		// Terminates a `status 3` block (>CLIENT:ENV,END has its own prefix).
		m.publishStatus()
	}
}

func (m *mgmtClient) publishStatus() {
	m.statusMu.Lock()
	m.lastStatus = m.statusBuf
	m.statusBuf = nil
	m.statusMu.Unlock()

	select {
	case m.statusReady <- struct{}{}:
	default:
	}
}

func (m *mgmtClient) finishConnect() {
	cid := m.pendingCID
	kid := m.pendingKID
	env := m.pendingEnv
	m.pendingCID, m.pendingKID, m.pendingEnv = "", "", nil
	if cid == "" || env == nil {
		return
	}

	cn := env["common_name"]
	serial := env["tls_serial_0"]
	if m.decider != nil && m.decider.authorize(cn, serial) {
		m.send(fmt.Sprintf("client-auth-nt %s %s", cid, kid))
		m.logf("openvpn: authorized cn=%s", cn)
	} else {
		m.send(fmt.Sprintf("client-deny %s %s \"unauthorized\"", cid, kid))
		m.logf("openvpn: denied cn=%s serial=%s", cn, serial)
	}
}

func (m *mgmtClient) send(cmd string) {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	if m.rw == nil {
		return
	}
	_, _ = m.rw.Writer.WriteString(cmd + "\n")
	_ = m.rw.Writer.Flush()
}

// kill terminates all sessions for a common name.
func (m *mgmtClient) kill(commonName string) {
	if commonName == "" {
		return
	}
	m.send("kill " + commonName)
}

// requestStatus issues `status 3` and waits for the parsed snapshot.
func (m *mgmtClient) requestStatus(timeout time.Duration) []clientStatus {
	// Drain any stale ready signal.
	select {
	case <-m.statusReady:
	default:
	}
	m.send("status 3")

	select {
	case <-m.statusReady:
	case <-time.After(timeout):
	}

	m.statusMu.Lock()
	defer m.statusMu.Unlock()
	out := make([]clientStatus, len(m.lastStatus))
	copy(out, m.lastStatus)
	return out
}

// parseStatusLine parses a single tab-separated CLIENT_LIST row from status v3.
// Format: CLIENT_LIST\tCommonName\tRealAddress\tVirtualAddress\tVirtualIPv6\t
//
//	BytesReceived\tBytesSent\tConnectedSince\tConnectedSince(time_t)\t
//	Username\tClientID\tPeerID\tDataChannelCipher
func parseStatusLine(line string) (clientStatus, bool) {
	if !strings.HasPrefix(line, "CLIENT_LIST\t") {
		return clientStatus{}, false
	}
	fields := strings.Split(line, "\t")
	if len(fields) < 11 {
		return clientStatus{}, false
	}
	cs := clientStatus{
		CommonName:  fields[1],
		RealAddress: fields[2],
		ClientID:    fields[10],
	}
	cs.BytesReceived, _ = strconv.ParseInt(fields[5], 10, 64)
	cs.BytesSent, _ = strconv.ParseInt(fields[6], 10, 64)
	return cs, true
}
