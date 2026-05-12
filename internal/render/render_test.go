package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/zjw-swun/mdns-survey/internal/model"
)

// buildExampleResult assembles the exact host shape used in 题目.md so we can
// diff the renderer's output against the example line-by-line.
func buildExampleResult() *model.Result {
	r := model.NewResult()
	src := "192.168.1.50:5353/udp"
	r.EnsureHost(src, "192.168.1.50", 5353)

	r.MergeService(src, &model.Service{
		Type: "_workstation._tcp.local.", ShortName: "workstation", Transport: "tcp",
		Port: 9, Name: "slw-nas [24:5e:be:69:a3:13]", Hostname: "slw-nas.local",
		IPv4: "x.x.x.x", IPv6: "fe80::265e:beff:fe69:a313", TTL: 10,
	})
	r.MergeService(src, &model.Service{
		Type: "_http._tcp.local.", ShortName: "http", Transport: "tcp",
		Port: 5000, Name: "slw-nas", Hostname: "slw-nas.local",
		IPv4: "x.x.x.x", IPv6: "fe80::265e:beff:fe69:a313", TTL: 10,
		TXT: []string{"path=/"},
	})
	r.MergeService(src, &model.Service{
		Type: "_smb._tcp.local.", ShortName: "smb", Transport: "tcp",
		Port: 445, Name: "slw-nas", Hostname: "slw-nas.local",
		IPv4: "x.x.x.x", IPv6: "fe80::265e:beff:fe69:a313", TTL: 10,
	})
	r.MergeService(src, &model.Service{
		Type: "_qdiscover._tcp.local.", ShortName: "qdiscover", Transport: "tcp",
		Port: 5000, Name: "slw-nas", Hostname: "slw-nas.local",
		IPv4: "x.x.x.x", IPv6: "fe80::265e:beff:fe69:a313", TTL: 10,
		TXT: []string{"accessType=https", "accessPort=86", "model=TS-X64", "displayModel=TS-464C", "fwVer=5.2.9", "fwBuildNum=20260214"},
	})
	r.MergeService(src, &model.Service{
		Type: "_device-info._tcp.local.", ShortName: "device-info", Transport: "",
		Port: 0, Name: "slw-nas(AFP)", Hostname: "slw-nas.local",
		IPv4: "x.x.x.x", IPv6: "fe80::265e:beff:fe69:a313", TTL: 10,
		TXT: []string{"model=Xserve"},
	})
	r.MergeService(src, &model.Service{
		Type: "_afpovertcp._tcp.local.", ShortName: "afpovertcp", Transport: "tcp",
		Port: 548, Name: "slw-nas(AFP)", Hostname: "slw-nas.local",
		IPv4: "x.x.x.x", IPv6: "fe80::265e:beff:fe69:a313", TTL: 10,
	})

	for _, ptr := range []string{
		"_workstation._tcp.local.",
		"_http._tcp.local.",
		"_smb._tcp.local.",
		"_qdiscover._tcp.local.",
		"_device-info._tcp.local.",
		"_afpovertcp._tcp.local.",
	} {
		r.AddPTR(src, ptr)
	}
	return r
}

func TestTextRendererMatchesExampleDepth(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, buildExampleResult()); err != nil {
		t.Fatalf("Text: %v", err)
	}
	got := buf.String()

	// The renderer sorts services by port; "device-info" (port 0) lands first.
	// We assert presence + key shape rather than exact line equality so changes
	// to ordering policy do not silently break this test.
	mustContain := []string{
		"services:",
		"9/tcp workstation:",
		"Name=slw-nas [24:5e:be:69:a3:13]",
		"IPv4=x.x.x.x",
		"IPv6=fe80::265e:beff:fe69:a313",
		"Hostname=slw-nas.local",
		"TTL=10",
		"5000/tcp http:",
		"path=/",
		"445/tcp smb:",
		"5000/tcp qdiscover:",
		"accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214",
		"device-info:",
		"model=Xserve",
		"548/tcp afpovertcp:",
		"answers:",
		"PTR:",
		"_workstation._tcp.local",
		"_http._tcp.local",
		"_smb._tcp.local",
		"_qdiscover._tcp.local",
		"_device-info._tcp.local",
		"_afpovertcp._tcp.local",
	}
	for _, line := range mustContain {
		if !strings.Contains(got, line) {
			t.Fatalf("output missing %q.\n--- output ---\n%s", line, got)
		}
	}
	// Trailing dots on PTR names must be stripped to match the example.
	if strings.Contains(got, "_workstation._tcp.local.\n") {
		t.Fatalf("PTR line should not carry trailing dot")
	}
}

func TestTextRendererEmptyResultEmitsSkeleton(t *testing.T) {
	r := model.NewResult()
	r.EnsureHost("10.0.0.1:5353/udp", "10.0.0.1", 5353)
	var buf bytes.Buffer
	if err := Text(&buf, r); err != nil {
		t.Fatalf("Text: %v", err)
	}
	got := buf.String()
	for _, line := range []string{"services:", "answers:", "PTR:"} {
		if !strings.Contains(got, line) {
			t.Fatalf("expected %q in output, got %q", line, got)
		}
	}
}

func TestYAMLRendererEmptyAndExample(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		r := model.NewResult()
		r.EnsureHost("10.0.0.1:5353/udp", "10.0.0.1", 5353)
		var buf bytes.Buffer
		if err := YAML(&buf, r); err != nil {
			t.Fatalf("YAML: %v", err)
		}
		if !strings.Contains(buf.String(), "hosts: []") {
			t.Fatalf("expected hosts: [], got %q", buf.String())
		}
	})
	t.Run("example", func(t *testing.T) {
		var buf bytes.Buffer
		if err := YAML(&buf, buildExampleResult()); err != nil {
			t.Fatalf("YAML: %v", err)
		}
		got := buf.String()
		for _, sub := range []string{"hosts:", "shortName: http", "path=/", "accessType=https", "_http._tcp.local."} {
			if !strings.Contains(got, sub) {
				t.Fatalf("missing %q in:\n%s", sub, got)
			}
		}
	})
}
