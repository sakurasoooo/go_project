package ipgen

import (
	"net/netip"
	"testing"
)

func TestExpandCIDRSkipsNetworkAndBroadcast(t *testing.T) {
	got, err := ExpandCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatalf("ExpandCIDR: %v", err)
	}
	want := []netip.Addr{
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("192.168.1.2"),
	}
	if len(got) != len(want) {
		t.Fatalf("len got=%d want=%d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d got=%s want=%s", i, got[i], want[i])
		}
	}
}

func TestExpandCIDRSlash32(t *testing.T) {
	got, err := ExpandCIDR("10.0.0.5/32")
	if err != nil {
		t.Fatalf("ExpandCIDR: %v", err)
	}
	if len(got) != 1 || got[0] != netip.MustParseAddr("10.0.0.5") {
		t.Fatalf("unexpected: %v", got)
	}
}

func TestExpandRangeFullForm(t *testing.T) {
	got, err := ExpandRange("192.168.1.10-192.168.1.12")
	if err != nil {
		t.Fatalf("ExpandRange: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 got %d", len(got))
	}
	if got[0].String() != "192.168.1.10" || got[2].String() != "192.168.1.12" {
		t.Fatalf("unexpected: %v", got)
	}
}

func TestExpandRangeShorthand(t *testing.T) {
	got, err := ExpandRange("192.168.1.5-7")
	if err != nil {
		t.Fatalf("ExpandRange: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 got %d", len(got))
	}
	if got[2].String() != "192.168.1.7" {
		t.Fatalf("unexpected: %v", got)
	}
}

func TestParsePortsListAndRange(t *testing.T) {
	got, err := ParsePorts("5353,53,5000-5001")
	if err != nil {
		t.Fatalf("ParsePorts: %v", err)
	}
	want := []uint16{5353, 53, 5000, 5001}
	if len(got) != len(want) {
		t.Fatalf("len got=%d want=%d (%v)", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("index %d got=%d want=%d", i, got[i], w)
		}
	}
}

func TestParsePortsRejectsBadInput(t *testing.T) {
	for _, in := range []string{"", "0", "70000", "5-3", "abc"} {
		if _, err := ParsePorts(in); err == nil {
			t.Fatalf("expected error for %q", in)
		}
	}
}

func TestCIDRTooLarge(t *testing.T) {
	if _, err := ExpandCIDR("10.0.0.0/8"); err == nil {
		t.Fatalf("expected error for /8")
	}
}
