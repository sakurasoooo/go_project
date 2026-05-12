// Package render serialises a model.Result into the text layout shown in
// 题目.md. The renderer is intentionally string-driven (no templates) so the
// output is byte-stable and trivial to compare against a golden file.
package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/zjw-swun/mdns-survey/internal/model"
	"gopkg.in/yaml.v3"
)

// Text writes the human-readable, example-aligned report. When the result
// contains more than one host the renderer prefixes each block with a
// "host:" line so operators can tell which IP/port produced each section.
func Text(w io.Writer, res *model.Result) error {
	hosts := visibleHosts(res)
	if len(hosts) == 0 {
		return writeEmptySkeleton(w)
	}
	for i, host := range hosts {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if len(hosts) > 1 {
			if _, err := fmt.Fprintf(w, "host: %s\n", host.Source); err != nil {
				return err
			}
		}
		if err := writeHost(w, host); err != nil {
			return err
		}
	}
	return nil
}

// writeEmptySkeleton prints the report headings with no rows so smoke tests
// and machine parsers always see a stable top-level shape, even when nothing
// answered on the wire.
func writeEmptySkeleton(w io.Writer) error {
	for _, line := range []string{"services:", "answers:", "PTR:"} {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

// YAML emits a compact machine-readable view of the same logical data as Text.
// It is intended for jq-style tooling and smoke checks; field names are stable.
func YAML(w io.Writer, res *model.Result) error {
	hosts := visibleHosts(res)
	doc := yamlDoc{Hosts: make([]yamlHostDoc, 0, len(hosts))}
	for _, h := range hosts {
		yd := yamlHostDoc{
			Source: h.Source,
			PTRs:   append([]string(nil), h.PTRs...),
		}
		for _, svc := range h.Services {
			yd.Services = append(yd.Services, yamlServiceDoc{
				Type:       svc.Type,
				ShortName:  svc.ShortName,
				Transport:  svc.Transport,
				Port:       svc.Port,
				Name:       svc.Name,
				Hostname:   strings.TrimSuffix(svc.Hostname, "."),
				IPv4:       svc.IPv4,
				IPv6:       svc.IPv6,
				TTL:        svc.TTL,
				TXT:        append([]string(nil), svc.TXT...),
			})
		}
		doc.Hosts = append(doc.Hosts, yd)
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	_, err = w.Write(out)
	return err
}

type yamlDoc struct {
	Hosts []yamlHostDoc `yaml:"hosts"`
}

type yamlHostDoc struct {
	Source   string            `yaml:"source"`
	Services []yamlServiceDoc  `yaml:"services"`
	PTRs     []string          `yaml:"ptrs"`
}

type yamlServiceDoc struct {
	Type       string   `yaml:"type,omitempty"`
	ShortName  string   `yaml:"shortName"`
	Transport  string   `yaml:"transport,omitempty"`
	Port       uint16   `yaml:"port"`
	Name       string   `yaml:"name,omitempty"`
	Hostname   string   `yaml:"hostname,omitempty"`
	IPv4       string   `yaml:"ipv4,omitempty"`
	IPv6       string   `yaml:"ipv6,omitempty"`
	TTL        uint32   `yaml:"ttl,omitempty"`
	TXT        []string `yaml:"txt,omitempty"`
}

// visibleHosts drops hosts that produced no services and no PTR records.
// Empty hosts would otherwise dominate the output of a large CIDR sweep
// where only a handful of devices reply.
func visibleHosts(res *model.Result) []*model.Host {
	all := res.Hosts()
	out := make([]*model.Host, 0, len(all))
	for _, h := range all {
		if len(h.Services) == 0 && len(h.PTRs) == 0 {
			continue
		}
		out = append(out, h)
	}
	return out
}

func writeHost(w io.Writer, host *model.Host) error {
	if _, err := fmt.Fprintln(w, "services:"); err != nil {
		return err
	}
	for _, svc := range host.Services {
		if err := writeService(w, svc); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w, "answers:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "PTR:"); err != nil {
		return err
	}
	for _, ptr := range host.PTRs {
		if _, err := fmt.Fprintln(w, strings.TrimSuffix(ptr, ".")); err != nil {
			return err
		}
	}
	return nil
}

// writeService emits exactly the block shape from 题目.md:
//
//	5000/tcp http:
//	Name=slw-nas
//	IPv4=...
//	IPv6=...
//	Hostname=...
//	TTL=...
//	path=/
//
// Missing fields are skipped so we never print "IPv4=" with an empty value.
func writeService(w io.Writer, svc *model.Service) error {
	var header string
	switch {
	case svc.Port == 0 && svc.Transport == "":
		header = fmt.Sprintf("%s:", svc.ShortName)
	case svc.Port == 0:
		header = fmt.Sprintf("%s:", svc.ShortName)
	default:
		transport := svc.Transport
		if transport == "" {
			transport = "tcp"
		}
		header = fmt.Sprintf("%d/%s %s:", svc.Port, transport, svc.ShortName)
	}
	if _, err := fmt.Fprintln(w, header); err != nil {
		return err
	}
	if svc.Name != "" {
		if _, err := fmt.Fprintf(w, "Name=%s\n", svc.Name); err != nil {
			return err
		}
	}
	if svc.IPv4 != "" {
		if _, err := fmt.Fprintf(w, "IPv4=%s\n", svc.IPv4); err != nil {
			return err
		}
	}
	if svc.IPv6 != "" {
		if _, err := fmt.Fprintf(w, "IPv6=%s\n", svc.IPv6); err != nil {
			return err
		}
	}
	if svc.Hostname != "" {
		if _, err := fmt.Fprintf(w, "Hostname=%s\n", strings.TrimSuffix(svc.Hostname, ".")); err != nil {
			return err
		}
	}
	if svc.TTL != 0 {
		if _, err := fmt.Fprintf(w, "TTL=%d\n", svc.TTL); err != nil {
			return err
		}
	}
	if len(svc.TXT) > 0 {
		// TXT records collapse onto a single comma-separated line because the
		// sample output in 题目.md shows that exact shape for the qdiscover
		// service ("accessType=https,accessPort=86,model=TS-X64,..."). One
		// TXT pair degenerates into a single key=value line, matching
		// "path=/" and "model=Xserve" in the same example.
		joined := strings.Join(svc.TXT, ",")
		if _, err := fmt.Fprintln(w, joined); err != nil {
			return err
		}
	}
	return nil
}
