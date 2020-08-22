package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"github.com/mberhault/go-sct"
)

func main() {
	url := "https://www.certificate-transparency.org"
	// Known to return SCTs in TLS extensions.
	// url := "https://ritter.vg"

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				VerifyConnection: func(state tls.ConnectionState) error {
					return sct.CheckConnectionState(&state)
				},
			},
		},
	}

	_, err := client.Get(url)
	if err != nil {
		log.Fatalf("get failed for %s: %v", url, err)
	}

	log.Printf("OK")
}
