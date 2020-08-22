package sct_test

import (
	"net/http"

	"github.com/mberhault/go-sct"
)

func ExampleCheckConnectionState() {
	// Verifying the SCTs after a HTTPS GET request.
	resp, err := http.Get("https://www.certificate-transparency.org")
	if err != nil {
		panic("get failed " + err.Error())
	}

	err = sct.CheckConnectionState(resp.TLS)
	if err != nil {
		panic("SCT check failed " + err.Error())
	}
}
