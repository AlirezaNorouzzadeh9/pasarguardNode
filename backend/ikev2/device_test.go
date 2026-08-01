package ikev2

import "testing"

// Behind a relay every client arrives from the relay's address, so counting
// bare IPs would collapse all of a user's devices into one and the device limit
// would never fire. Each device keeps its own NAT source port.
func TestSAInfoDevice(t *testing.T) {
	cases := []struct {
		name string
		sa   saInfo
		want string
	}{
		{
			"direct client",
			saInfo{Remote: "5.209.100.126", RemotePort: "41234"},
			"5.209.100.126:41234",
		},
		{
			"a port is what separates two devices behind one relay address",
			saInfo{Remote: "20.20.20.1", RemotePort: "23291"},
			"20.20.20.1:23291",
		},
		{
			"falls back to the address when no port was reported",
			saInfo{Remote: "20.20.20.1"},
			"20.20.20.1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.sa.Device(); got != tc.want {
				t.Fatalf("Device() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTwoDevicesBehindOneRelayAddressAreDistinct(t *testing.T) {
	a := saInfo{Remote: "20.20.20.1", RemotePort: "23291"}
	b := saInfo{Remote: "20.20.20.1", RemotePort: "40112"}
	if a.Device() == b.Device() {
		t.Fatal("two devices sharing a relay address must not collapse into one")
	}
}

// A rekey keeps the same UDP tuple, so the same device must not be counted
// twice while both the old and new SA are briefly present.
func TestRekeyedSAIsTheSameDevice(t *testing.T) {
	old := saInfo{IKEID: 7, Remote: "20.20.20.1", RemotePort: "23291"}
	rekeyed := saInfo{IKEID: 9, Remote: "20.20.20.1", RemotePort: "23291"}
	if old.Device() != rekeyed.Device() {
		t.Fatal("a rekeyed SA from the same endpoint must count as one device")
	}
}
