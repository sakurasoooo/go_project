//go:build integration

package main

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// .../cmd/survey/integration_stub_test.go -> repo root
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func stubDNSHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	if len(r.Question) != 1 {
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	if q.Qtype != dns.TypePTR {
		_ = w.WriteMsg(m)
		return
	}
	if !strings.EqualFold(q.Name, "_http._tcp.local.") {
		// Immediate empty NOERROR so the CLI does not wait per-query UDP timeouts
		// for the long default PTR plan.
		_ = w.WriteMsg(m)
		return
	}
	inst := "smokebox._http._tcp.local."
	ptr := &dns.PTR{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120},
		Ptr: inst,
	}
	m.Answer = append(m.Answer, ptr)
	m.Extra = append(m.Extra,
		&dns.SRV{
			Hdr:    dns.RR_Header{Name: inst, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120},
			Port:   5000,
			Target: "stub.local.",
		},
		&dns.TXT{
			Hdr: dns.RR_Header{Name: inst, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120},
			Txt: []string{"path=/", "accessType=https", "model=TS-X64"},
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "stub.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
			A:   net.IPv4(127, 0, 0, 1),
		},
	)
	_ = w.WriteMsg(m)
}

// TestIntegrationSurveyAgainstUDPStub covers SMK-10 / SMK-11: built CLI talks to a
// minimal DNS-SD responder and recovers SRV/TXT/A plus PTR answers.
func TestIntegrationSurveyAgainstUDPStub(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()

	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(stubDNSHandler)}
	go func() {
		_ = srv.ActivateAndServe()
	}()
	defer func() {
		_ = srv.Shutdown()
	}()

	udpAddr := pc.LocalAddr().(*net.UDPAddr)
	port := udpAddr.Port

	root := moduleRoot(t)
	bin := filepath.Join(t.TempDir(), "survey")
	build := exec.Command("go", "build", "-o", bin, "./cmd/survey")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	run := exec.Command(bin,
		"--cidr", "127.0.0.1/32",
		"--ports", fmt.Sprintf("%d", port),
		"--timeout", "2s",
		"--workers", "8",
		"--enumerate", "false",
	)
	run.Dir = root
	var stdout, stderr bytes.Buffer
	run.Stdout = &stdout
	run.Stderr = &stderr
	if err := run.Run(); err != nil {
		t.Fatalf("survey: %v\nstderr=%s\nstdout=%s", err, stderr.String(), stdout.String())
	}
	out := stdout.String()
	for _, sub := range []string{
		"5000/tcp http:",
		"path=/",
		"accessType=https,model=TS-X64",
		"IPv4=127.0.0.1",
		"answers:",
		"PTR:",
		"_http._tcp.local",
	} {
		if !strings.Contains(out, sub) {
			t.Fatalf("stdout missing %q\n---\n%s", sub, out)
		}
	}
}
