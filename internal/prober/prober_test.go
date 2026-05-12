package prober

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/zjw-swun/mdns-survey/internal/config"
)

// fakeQuerier responds with canned messages keyed by the PTR question name.
// This lets us exercise the probe loop end-to-end without opening a socket.
type fakeQuerier struct {
	answers map[string]*dns.Msg
	calls   int
}

func (f *fakeQuerier) Exchange(_ context.Context, _ string, q *dns.Msg) (*dns.Msg, error) {
	f.calls++
	if len(q.Question) == 0 {
		return nil, nil
	}
	return f.answers[q.Question[0].Name], nil
}

func hdr(name string, typ uint16) dns.RR_Header {
	return dns.RR_Header{Name: dns.Fqdn(name), Rrtype: typ, Class: dns.ClassINET, Ttl: 10}
}

func TestProberMergesServicesPerSource(t *testing.T) {
	cfg := &config.Config{
		Ports:   []uint16{5353},
		Timeout: 100 * time.Millisecond,
		Workers: 2,
		PTRList: []string{"_http._tcp.local.", "_smb._tcp.local."},
	}

	httpResp := &dns.Msg{}
	httpResp.Answer = []dns.RR{
		&dns.PTR{Hdr: hdr("_http._tcp.local.", dns.TypePTR), Ptr: "slw-nas._http._tcp.local."},
	}
	httpResp.Extra = []dns.RR{
		&dns.SRV{Hdr: hdr("slw-nas._http._tcp.local.", dns.TypeSRV), Port: 5000, Target: "slw-nas.local."},
		&dns.TXT{Hdr: hdr("slw-nas._http._tcp.local.", dns.TypeTXT), Txt: []string{"path=/"}},
		&dns.A{Hdr: hdr("slw-nas.local.", dns.TypeA), A: net.IPv4(192, 168, 1, 50)},
	}
	smbResp := &dns.Msg{}
	smbResp.Answer = []dns.RR{
		&dns.PTR{Hdr: hdr("_smb._tcp.local.", dns.TypePTR), Ptr: "slw-nas._smb._tcp.local."},
	}
	smbResp.Extra = []dns.RR{
		&dns.SRV{Hdr: hdr("slw-nas._smb._tcp.local.", dns.TypeSRV), Port: 445, Target: "slw-nas.local."},
		&dns.A{Hdr: hdr("slw-nas.local.", dns.TypeA), A: net.IPv4(192, 168, 1, 50)},
	}

	fq := &fakeQuerier{answers: map[string]*dns.Msg{
		"_http._tcp.local.": httpResp,
		"_smb._tcp.local.":  smbResp,
	}}
	p := NewWithQueriers(cfg, fq, nil)
	res := p.Run(context.Background(), []Target{
		{IP: netip.MustParseAddr("192.168.1.50"), Port: 5353, Transport: "udp"},
	}, nil, nil)

	hosts := res.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts len got=%d want=1", len(hosts))
	}
	host := hosts[0]
	if len(host.Services) != 2 {
		t.Fatalf("services len got=%d want=2", len(host.Services))
	}
	// services are sorted by port ascending: smb (445), http (5000)
	if host.Services[0].ShortName != "smb" || host.Services[0].Port != 445 {
		t.Fatalf("svc[0] got %+v", host.Services[0])
	}
	if host.Services[1].ShortName != "http" || host.Services[1].Port != 5000 {
		t.Fatalf("svc[1] got %+v", host.Services[1])
	}
	if host.Services[1].TXT[0] != "path=/" {
		t.Fatalf("missing TXT: %v", host.Services[1].TXT)
	}
	if len(host.PTRs) != 2 {
		t.Fatalf("PTRs len got=%d want=2", len(host.PTRs))
	}
}

func TestProberStopsOnCanceledContext(t *testing.T) {
	cfg := &config.Config{
		Ports:   []uint16{5353},
		Timeout: 100 * time.Millisecond,
		Workers: 1,
		PTRList: []string{"_a._tcp.local.", "_b._tcp.local."},
	}
	fq := &fakeQuerier{answers: map[string]*dns.Msg{}}
	p := NewWithQueriers(cfg, fq, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := p.Run(ctx, []Target{
		{IP: netip.MustParseAddr("10.0.0.1"), Port: 5353, Transport: "udp"},
	}, nil, nil)
	if len(res.Hosts()) > 1 {
		t.Fatalf("unexpected results when canceled")
	}
}
