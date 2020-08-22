package main

import (
	"crypto/tls"
	"log"

	"github.com/mberhault/go-sct"
)

func main() {
	host := "www.certificate-transparency.org:443"
	// Known to return SCTs in TLS extensions.
	// host := "ritter.vg:443"

	conn, err := tls.Dial("tcp", host, &tls.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	err = sct.CheckConnectionState(&state)
	if err != nil {
		log.Fatalf("failed SCT check: %v", err)
	}

	log.Printf("OK")
}
