// Package ipgen expands user input ("CIDR", "a-b range", "single IP") into a
// concrete slice of netip.Addr. It is deliberately conservative: it caps the
// number of addresses it returns so a typo like "10.0.0.0/8" does not silently
// queue 16M probes.
package ipgen

import (
	"fmt"
	"net/netip"
	"strings"
)

// MaxHosts is the largest CIDR/range Expand will return. Larger inputs are
// rejected; the operator must split them explicitly. 1<<20 ≈ 1M hosts covers
// every plausible enterprise LAN sweep while still bounding RAM and goroutine
// pressure.
const MaxHosts = 1 << 20

// ExpandCIDR returns every host inside a CIDR. For IPv4 it skips the network
// and broadcast addresses when the prefix is shorter than /31, matching the
// usual "scannable hosts" semantics. For IPv6 every address is returned.
func ExpandCIDR(s string) ([]netip.Addr, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("parse cidr %q: %w", s, err)
	}
	p = p.Masked()
	addr := p.Addr()
	bits := addr.BitLen() - p.Bits()
	if bits > 30 { // safety net before exponentiation
		return nil, fmt.Errorf("cidr %s too large", s)
	}
	count := uint64(1) << uint(bits)
	if count > MaxHosts {
		return nil, fmt.Errorf("cidr %s expands to %d hosts (max %d)", s, count, MaxHosts)
	}
	out := make([]netip.Addr, 0, count)
	cur := addr
	skipNet := addr.Is4() && p.Bits() <= 30
	for i := uint64(0); i < count; i++ {
		if !(skipNet && (i == 0 || i == count-1)) {
			out = append(out, cur)
		}
		cur = cur.Next()
		if !cur.IsValid() {
			break
		}
	}
	return out, nil
}

// ExpandRange parses "a.b.c.d-e.f.g.h" or "a.b.c.d-h" (last-octet shorthand)
// and returns the inclusive list of IPv4 addresses between them.
func ExpandRange(s string) ([]netip.Addr, error) {
	s = strings.TrimSpace(s)
	dash := strings.Index(s, "-")
	if dash < 0 {
		one, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("parse ip %q: %w", s, err)
		}
		return []netip.Addr{one}, nil
	}
	leftStr := strings.TrimSpace(s[:dash])
	rightStr := strings.TrimSpace(s[dash+1:])
	left, err := netip.ParseAddr(leftStr)
	if err != nil {
		return nil, fmt.Errorf("parse range start %q: %w", leftStr, err)
	}
	var right netip.Addr
	if strings.Contains(rightStr, ".") || strings.Contains(rightStr, ":") {
		right, err = netip.ParseAddr(rightStr)
		if err != nil {
			return nil, fmt.Errorf("parse range end %q: %w", rightStr, err)
		}
	} else {
		// last-octet shorthand: only valid for IPv4
		if !left.Is4() {
			return nil, fmt.Errorf("last-octet shorthand only valid for IPv4")
		}
		b := left.As4()
		var lastOctet int
		if _, err := fmt.Sscanf(rightStr, "%d", &lastOctet); err != nil {
			return nil, fmt.Errorf("parse range end %q: %w", rightStr, err)
		}
		if lastOctet < 0 || lastOctet > 255 {
			return nil, fmt.Errorf("range end octet out of bounds: %d", lastOctet)
		}
		b[3] = byte(lastOctet)
		right = netip.AddrFrom4(b)
	}
	if left.Is4() != right.Is4() {
		return nil, fmt.Errorf("range endpoints mix IPv4 and IPv6")
	}
	if right.Less(left) {
		return nil, fmt.Errorf("range end %s precedes start %s", right, left)
	}
	out := make([]netip.Addr, 0)
	cur := left
	for {
		out = append(out, cur)
		if cur == right {
			break
		}
		if len(out) > MaxHosts {
			return nil, fmt.Errorf("range %s expands beyond MaxHosts (%d)", s, MaxHosts)
		}
		cur = cur.Next()
		if !cur.IsValid() {
			break
		}
	}
	return out, nil
}

// Expand accepts either a CIDR or a range and dispatches accordingly. It is
// the convenience entrypoint used by the CLI; library callers that already
// know which form they have should call ExpandCIDR/ExpandRange directly.
func Expand(s string) ([]netip.Addr, error) {
	if strings.Contains(s, "/") {
		return ExpandCIDR(s)
	}
	return ExpandRange(s)
}

// ParsePorts accepts a comma-separated list where each element is either
// "n" or "n-m" (inclusive). Empty input is rejected so the caller is forced
// to make port selection explicit.
func ParsePorts(s string) ([]uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty port list")
	}
	seen := make(map[uint16]struct{})
	out := make([]uint16, 0, 4)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if dash := strings.Index(part, "-"); dash >= 0 {
			var lo, hi int
			if _, err := fmt.Sscanf(part, "%d-%d", &lo, &hi); err != nil {
				return nil, fmt.Errorf("parse port range %q: %w", part, err)
			}
			if lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("port range %q out of bounds", part)
			}
			for p := lo; p <= hi; p++ {
				addPort(out[:0:0], seen, uint16(p), &out)
			}
			continue
		}
		var p int
		if _, err := fmt.Sscanf(part, "%d", &p); err != nil {
			return nil, fmt.Errorf("parse port %q: %w", part, err)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port %d out of bounds", p)
		}
		addPort(out[:0:0], seen, uint16(p), &out)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid ports parsed from %q", s)
	}
	return out, nil
}

func addPort(_ []uint16, seen map[uint16]struct{}, p uint16, out *[]uint16) {
	if _, ok := seen[p]; ok {
		return
	}
	seen[p] = struct{}{}
	*out = append(*out, p)
}
