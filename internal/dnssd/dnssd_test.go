package dnssd

import (
	"net"
	"sort"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// buildExampleResponse fabricates a single dns.Msg whose Answer + Extra
// sections reproduce the chain seen in 题目.md so we can assert the parser
// recovers ports, hostnames and TXT banners without touching the network.
func buildExampleResponse(t *testing.T) *dns.Msg {
	t.Helper()
	msg := new(dns.Msg)
	msg.Response = true

	add := func(rr dns.RR) { msg.Answer = append(msg.Answer, rr) }
	extra := func(rr dns.RR) { msg.Extra = append(msg.Extra, rr) }

	hdr := func(name string, typ uint16) dns.RR_Header {
		return dns.RR_Header{Name: dns.Fqdn(name), Rrtype: typ, Class: dns.ClassINET, Ttl: 10}
	}

	add(&dns.PTR{Hdr: hdr("_workstation._tcp.local.", dns.TypePTR), Ptr: "slw-nas [24:5e:be:69:a3:13]._workstation._tcp.local."})
	add(&dns.PTR{Hdr: hdr("_http._tcp.local.", dns.TypePTR), Ptr: "slw-nas._http._tcp.local."})
	add(&dns.PTR{Hdr: hdr("_smb._tcp.local.", dns.TypePTR), Ptr: "slw-nas._smb._tcp.local."})
	add(&dns.PTR{Hdr: hdr("_qdiscover._tcp.local.", dns.TypePTR), Ptr: "slw-nas._qdiscover._tcp.local."})
	add(&dns.PTR{Hdr: hdr("_device-info._tcp.local.", dns.TypePTR), Ptr: "slw-nas(AFP)._device-info._tcp.local."})
	add(&dns.PTR{Hdr: hdr("_afpovertcp._tcp.local.", dns.TypePTR), Ptr: "slw-nas(AFP)._afpovertcp._tcp.local."})

	extra(&dns.SRV{Hdr: hdr("slw-nas [24:5e:be:69:a3:13]._workstation._tcp.local.", dns.TypeSRV), Port: 9, Target: "slw-nas.local."})
	extra(&dns.SRV{Hdr: hdr("slw-nas._http._tcp.local.", dns.TypeSRV), Port: 5000, Target: "slw-nas.local."})
	extra(&dns.SRV{Hdr: hdr("slw-nas._smb._tcp.local.", dns.TypeSRV), Port: 445, Target: "slw-nas.local."})
	extra(&dns.SRV{Hdr: hdr("slw-nas._qdiscover._tcp.local.", dns.TypeSRV), Port: 5000, Target: "slw-nas.local."})
	extra(&dns.SRV{Hdr: hdr("slw-nas(AFP)._afpovertcp._tcp.local.", dns.TypeSRV), Port: 548, Target: "slw-nas.local."})

	extra(&dns.TXT{Hdr: hdr("slw-nas._http._tcp.local.", dns.TypeTXT), Txt: []string{"path=/"}})
	extra(&dns.TXT{Hdr: hdr("slw-nas._qdiscover._tcp.local.", dns.TypeTXT),
		Txt: []string{"accessType=https", "accessPort=86", "model=TS-X64", "displayModel=TS-464C", "fwVer=5.2.9", "fwBuildNum=20260214"}})
	extra(&dns.TXT{Hdr: hdr("slw-nas(AFP)._device-info._tcp.local.", dns.TypeTXT), Txt: []string{"model=Xserve"}})

	extra(&dns.A{Hdr: hdr("slw-nas.local.", dns.TypeA), A: net.IPv4(192, 168, 1, 50)})
	extra(&dns.AAAA{Hdr: hdr("slw-nas.local.", dns.TypeAAAA), AAAA: net.ParseIP("fe80::265e:beff:fe69:a313")})

	return msg
}

func TestServicesFromMsgRecoversAllServices(t *testing.T) {
	msg := buildExampleResponse(t)
	services := ServicesFromMsg(msg)

	want := map[string]struct {
		port     uint16
		hostname string
		ipv4     string
		ipv6     string
		hasTXT   []string
	}{
		"workstation":  {port: 9, hostname: "slw-nas.local", ipv4: "192.168.1.50", ipv6: "fe80::265e:beff:fe69:a313"},
		"http":         {port: 5000, hostname: "slw-nas.local", ipv4: "192.168.1.50", hasTXT: []string{"path=/"}},
		"smb":          {port: 445, hostname: "slw-nas.local"},
		"qdiscover":    {port: 5000, hostname: "slw-nas.local", hasTXT: []string{"accessType=https", "model=TS-X64", "fwVer=5.2.9"}},
		"device-info":  {port: 0, hasTXT: []string{"model=Xserve"}},
		"afpovertcp":   {port: 548, hostname: "slw-nas.local"},
	}

	got := make(map[string]*svcView)
	for _, s := range services {
		got[s.ShortName] = &svcView{
			port: s.Port, hostname: s.Hostname, ipv4: s.IPv4, ipv6: s.IPv6, txt: s.TXT,
		}
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Fatalf("missing service %q", name)
		}
		if g.port != w.port {
			t.Fatalf("%s: port got=%d want=%d", name, g.port, w.port)
		}
		if w.hostname != "" && g.hostname != w.hostname {
			t.Fatalf("%s: hostname got=%q want=%q", name, g.hostname, w.hostname)
		}
		if w.ipv4 != "" && g.ipv4 != w.ipv4 {
			t.Fatalf("%s: ipv4 got=%q want=%q", name, g.ipv4, w.ipv4)
		}
		if w.ipv6 != "" && g.ipv6 != w.ipv6 {
			t.Fatalf("%s: ipv6 got=%q want=%q", name, g.ipv6, w.ipv6)
		}
		for _, kv := range w.hasTXT {
			if !containsSubstring(g.txt, kv) {
				t.Fatalf("%s: TXT missing %q, got %v", name, kv, g.txt)
			}
		}
	}
}

func TestMetaTargetsExtractsServiceList(t *testing.T) {
	msg := new(dns.Msg)
	hdr := func(name string) dns.RR_Header {
		return dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 30}
	}
	msg.Answer = []dns.RR{
		&dns.PTR{Hdr: hdr("_services._dns-sd._udp.local."), Ptr: "_http._tcp.local."},
		&dns.PTR{Hdr: hdr("_services._dns-sd._udp.local."), Ptr: "_workstation._tcp.local."},
		&dns.PTR{Hdr: hdr("_services._dns-sd._udp.local."), Ptr: "_http._tcp.local."}, // duplicate, should dedupe
	}
	out := MetaTargets(Parse(msg))
	sort.Strings(out)
	want := []string{"_http._tcp.local.", "_workstation._tcp.local."}
	if strings.Join(out, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", out, want)
	}
}

type svcView struct {
	port             uint16
	hostname         string
	ipv4, ipv6       string
	txt              []string
}

func containsSubstring(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
