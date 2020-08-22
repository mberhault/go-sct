# go-sct: Verifying Signed Certificate Timestamps in Go.

[![PkgGoDev](https://pkg.go.dev/badge/github.com/mberhault/go-sct)](https://pkg.go.dev/github.com/mberhault/go-sct)

Verify Signed Certificate Timestamps as defined in [RFC 6962](https://datatracker.ietf.org/doc/rfc6962/).

## Warning:

This is a prototype, no guarantees are provided regarding correctness.

## Use:

Perform Signed Certificate Timestamp verification for TLS connections.

To install:

```
go get github.com/mberhault/go-sct
```

Using it to verify a simple https Get:

```
package main

import (
  "log"
  "net/http"

  "github.com/mberhault/go-sct"
)

func main() {
  resp, err := http.Get("https://www.certificate-transparency.org")
  if err != nil {
    log.Fatalf("get failed for %s: %v", url, err)
  }

  err = sct.CheckConnectionState(resp.TLS)
  if err != nil {
    log.Fatalf("failed SCT check: %v", err)
  }

  log.Printf("OK")
}
```

See the [examples](examples/) directory for various methods of verifying the [tls.ConnectionState](https://golang.org/pkg/crypto/tls/#ConnectionState):

- [`examples/check_get_response`](examples/check_get_response/) to verify a [http.Response](https://golang.org/pkg/net/http/#Response)
- [`examples/dial_tls`](examples/dial_tls/) to verify a [tls.Conn](https://golang.org/pkg/crypto/tls/#Conn)
- [`examples/tls_config_verify`](examples/tls_config_verify/) to use the `VerifyConnection` callback of a [tls.Config](https://golang.org/pkg/crypto/tls/#Config)

## Signed Certificate Timestamp acceptance:

Two types of SCTs (Signed Certificate Timestamps) are examined:

- embedded in a x509 certificate
- included in the TLS handshake as a TLS extension

SCTs are verified using the following:

- extract SCTs from x509 certificate or TLS extension
- lookup corresponding log in the [Chrome CT log list](https://www.certificate-transparency.org/known-logs), specifically `https://www.gstatic.com/ct/log_list/v2/log_list.json`, log must be qualified (qualified, usable, or read-only)
- verify SCT signature using the log's public key
- check the log for inclusion

`sct.CheckConnectionState` returns success when the first valid SCT is encountered, skipping all others.

## Caveats:

There are a few noteworthy caveats:

- **this is a prototype**
- SCTs included in the OCSP response are not examined
- the log list is not refreshed after initialization
- if the issuer certificate is missing, embedded SCTs cannot be verified and will fail
- if the SCT is not included in the tree but its timestamp is before `Maximum Merge Delay`, the check passes
- no configuration is currently possible
- the set of dependencies is massive, pulling a large portion of [certificate-transparency-go](https://github.com/google/certificate-transparency-go) and its dependencies.
- expect severely increase latency, no optimization or caching has been done
