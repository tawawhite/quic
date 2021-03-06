package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/goburrow/quic"
	"github.com/goburrow/quic/transport"
)

func clientCommand(args []string) error {
	cmd := flag.NewFlagSet("client", flag.ExitOnError)
	listenAddr := cmd.String("listen", "0.0.0.0:0", "listen on the given IP:port")
	insecure := cmd.Bool("insecure", false, "skip verifying server certificate")
	data := cmd.String("data", "GET /\r\n", "sending data")
	logLevel := cmd.Int("v", 2, "log verbose: 0=off 1=error 2=info 3=debug 4=trace")
	cmd.Parse(args)

	addr := cmd.Arg(0)
	if addr == "" {
		fmt.Fprintln(cmd.Output(), "Usage: quince client [options] <address>")
		cmd.PrintDefaults()
		return nil
	}
	config := newConfig()
	config.TLS.ServerName = serverName(addr)
	config.TLS.InsecureSkipVerify = *insecure
	handler := clientHandler{data: *data}
	client := quic.NewClient(config)
	client.SetHandler(&handler)
	client.SetLogger(*logLevel, os.Stdout)
	if err := client.ListenAndServe(*listenAddr); err != nil {
		return err
	}
	handler.wg.Add(1)
	if err := client.Connect(addr); err != nil {
		return err
	}
	handler.wg.Wait()
	return client.Close()
}

type clientHandler struct {
	wg   sync.WaitGroup
	data string
}

func (s *clientHandler) Serve(c quic.Conn, events []transport.Event) {
	for _, e := range events {
		log.Printf("%s connection event: %v", c.RemoteAddr(), e.Type)
		switch e.Type {
		case quic.EventConnAccept:
			st := c.Stream(4)
			_, _ = st.Write([]byte(s.data))
			_ = st.Close()
		case transport.EventStream:
			st := c.Stream(e.StreamID)
			if st != nil {
				buf := make([]byte, 512)
				n, _ := st.Read(buf)
				log.Printf("stream %d received:\n%s", e.StreamID, buf[:n])
			}
		case quic.EventConnClose:
			s.wg.Done()
		}
	}
}

func serverName(s string) string {
	colon := strings.LastIndex(s, ":")
	if colon > 0 {
		bracket := strings.LastIndex(s, "]")
		if colon > bracket {
			return s[:colon]
		}
	}
	return s
}
