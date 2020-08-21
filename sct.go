package sct

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist2"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
)

var (
	defaultCheckerOnce sync.Once
	DefaultChecker     *Checker
)

type Checker struct {
	ll *loglist2.LogList
}

func GetDefaultChecker() *Checker {
	defaultCheckerOnce.Do(func() {
		DefaultChecker = &Checker{
			ll: newDefaultLogList(),
		}
	})

	return DefaultChecker
}

func CheckSCTs(state *tls.ConnectionState) error {
	return GetDefaultChecker().checkSCTs(state)
}

func (c *Checker) checkSCTs(state *tls.ConnectionState) error {
	if state == nil {
		return errors.New("no TLS connection state")
	}

	log.Printf("Certificates: %d", len(state.PeerCertificates))
	log.Printf("TLS SCTs:     %d", len(state.SignedCertificateTimestamps))

	chain, err := buildCertificateChain(state.PeerCertificates)
	if err != nil {
		return err
	}

	lastError := errors.New("no Signed Certificate Timestamps found")

	// SCTs provided in the TLS handshake.
	if len(state.SignedCertificateTimestamps) > 0 {
		err = c.checkTLSSCTs(state.SignedCertificateTimestamps, chain)
		if err != nil {
			lastError = err
		} else {
			// We found some good SCTs, return early.
			return nil
		}
	}

	return lastError
}

// Check SCTs provided with the TLS handshake. Returns an error if no SCT is valid.
func (c *Checker) checkTLSSCTs(scts [][]byte, chain []*ctx509.Certificate) error {
	merkleLeaf, err := ct.MerkleTreeLeafFromChain(chain, ct.X509LogEntryType, 0)
	if err != nil {
		return err
	}

	for _, sct := range scts {
		x509SCT := &ctx509.SerializedSCT{Val: sct}
		err := c.checkOneSCT(x509SCT, merkleLeaf)
		if err == nil {
			// Valid: return early.
			return nil
		}
	}

	return errors.New("no valid SCT in SSL handshake")
}

func (c *Checker) checkOneSCT(x509SCT *ctx509.SerializedSCT, merkleLeaf *ct.MerkleTreeLeaf) error {
	sct, err := ctx509util.ExtractSCT(x509SCT)
	if err != nil {
		return err
	}

	ctLog := c.ll.FindLogByKeyHash(sct.LogID.KeyID)
	if ctLog == nil {
		return fmt.Errorf("no log found with KeyID %x", sct.LogID)
	}

	logInfo, err := newLogInfoFromLog(ctLog)
	if err != nil {
		return fmt.Errorf("could not create client for log %s", ctLog.Description)
	}

	err = logInfo.VerifySCTSignature(*sct, *merkleLeaf)
	if err != nil {
		return fmt.Errorf("failed to verify signature from log %q: %v", ctLog.Description, err)
	}

	_, err = logInfo.VerifyInclusion(context.Background(), *merkleLeaf, sct.Timestamp)
	if err != nil {
		age := time.Since(ct.TimestampToTime(sct.Timestamp))
		if age >= logInfo.MMD {
			return fmt.Errorf("failed to verify inclusion in log %q", ctLog.Description)
		}

		// TODO(mberhault): option to fail on timestamp too recent.
		return nil
	}

	return nil
}
