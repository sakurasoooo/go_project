package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/zjw-swun/mdns-survey/internal/httpsrv"
)

func runServe(args []string, stderr *os.File) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", ":8080", "listen address (e.g. :8080 or 127.0.0.1:8080)")
	var corsOrigins multiFlag
	fs.Var(&corsOrigins, "cors-origin", "extra allowed CORS origin (repeatable), e.g. http://localhost:3000")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: survey serve [--addr :8080] [--cors-origin <url> ...]")
		fs.PrintDefaults()
	}
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fs.Usage()
		return nil
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	srv := httpsrv.New(httpsrv.Options{
		Addr:        *addr,
		CORSOrigins: corsOrigins,
	})
	return srv.ListenAndServe()
}

type multiFlag []string

func (m *multiFlag) String() string { return fmt.Sprint(*m) }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
