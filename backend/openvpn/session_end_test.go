package openvpn

import "testing"

// A disconnected client is gone from `status 3` before the next poll runs, so
// everything it moved since the previous tick used to be dropped on the floor —
// and a session that fitted between two ticks was never counted at all. Cycling
// connect/transfer/disconnect faster than the poll interval therefore cost the
// user nothing, which is a data limit that can be walked around.
//
// openvpn reports the totals in the disconnect event; these pin that they are
// billed exactly once.

func newOV(seen map[string]clientStatus, ended []endedSession) *OpenVPN {
	if seen == nil {
		seen = map[string]clientStatus{}
	}
	return &OpenVPN{sessionSeen: seen, endedSessions: ended}
}

func TestEndedSessionTailIsBilled(t *testing.T) {
	// Last poll saw 90MB/900MB; the client then moved more and left at 100/1000.
	o := newOV(
		map[string]clientStatus{"7": {CommonName: "101", BytesReceived: 90, BytesSent: 900}},
		[]endedSession{{clientID: "7", commonName: "101", rx: 100, tx: 1000}},
	)

	perCN := map[string]*clientStatus{}
	o.foldEndedSessionsLocked(perCN)

	got := perCN["101"]
	if got == nil {
		t.Fatal("ended session was not billed at all")
	}
	if got.BytesReceived != 10 || got.BytesSent != 100 {
		t.Fatalf("tail billed as rx=%d tx=%d, want rx=10 tx=100", got.BytesReceived, got.BytesSent)
	}
	if _, still := o.sessionSeen["7"]; still {
		t.Error("settled session left its baseline behind")
	}
}

func TestSessionShorterThanOnePollIsBilledInFull(t *testing.T) {
	// Connected and gone between two ticks: never polled, so no baseline.
	o := newOV(nil, []endedSession{{clientID: "9", commonName: "202", rx: 500, tx: 5000}})

	perCN := map[string]*clientStatus{}
	o.foldEndedSessionsLocked(perCN)

	got := perCN["202"]
	if got == nil {
		t.Fatal("a session that fitted between two polls was billed nothing — the data limit is evadable by reconnecting")
	}
	if got.BytesReceived != 500 || got.BytesSent != 5000 {
		t.Fatalf("billed rx=%d tx=%d, want the whole session rx=500 tx=5000", got.BytesReceived, got.BytesSent)
	}
}

func TestInFlightStatusRowIsNotBilledTwice(t *testing.T) {
	// The `status 3` reply was already in flight when the client left, so this
	// poll folded a row for it first (baseline now 100/1000) and only the
	// remainder up to the disconnect totals is still owed.
	o := newOV(
		map[string]clientStatus{"7": {CommonName: "101", BytesReceived: 100, BytesSent: 1000}},
		[]endedSession{{clientID: "7", commonName: "101", rx: 100, tx: 1000}},
	)

	perCN := map[string]*clientStatus{"101": {CommonName: "101", BytesReceived: 10, BytesSent: 100}}
	o.foldEndedSessionsLocked(perCN)

	if got := perCN["101"]; got.BytesReceived != 10 || got.BytesSent != 100 {
		t.Fatalf("row already counted was billed again: rx=%d tx=%d, want rx=10 tx=100", got.BytesReceived, got.BytesSent)
	}
}

func TestDisconnectTotalsBelowTheBaselineBillNothing(t *testing.T) {
	// Not expected from openvpn, but a smaller total must never be read as a
	// brand-new session and billed from zero.
	o := newOV(
		map[string]clientStatus{"7": {CommonName: "101", BytesReceived: 100, BytesSent: 1000}},
		[]endedSession{{clientID: "7", commonName: "101", rx: 40, tx: 400}},
	)

	perCN := map[string]*clientStatus{}
	o.foldEndedSessionsLocked(perCN)

	if got, ok := perCN["101"]; ok {
		t.Fatalf("billed rx=%d tx=%d for a session that appears to have gone backwards", got.BytesReceived, got.BytesSent)
	}
}

func TestQueueIsDrainedOnce(t *testing.T) {
	o := newOV(nil, []endedSession{{clientID: "9", commonName: "202", rx: 500, tx: 5000}})

	o.foldEndedSessionsLocked(map[string]*clientStatus{})
	second := map[string]*clientStatus{}
	o.foldEndedSessionsLocked(second)

	if len(second) != 0 {
		t.Fatalf("the same ended session was billed on a later poll too: %+v", second)
	}
}
