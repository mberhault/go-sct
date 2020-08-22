package sct

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist2"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
)

var (
	defaultCheckerOnce sync.Once
	defaultChecker     *checker
)

// checker performs SCT checks.
type checker struct {
	ll *loglist2.LogList
}

// getDefaultChecker returns the default Checker, initializing it if needed.
func getDefaultChecker() *checker {
	defaultCheckerOnce.Do(func() {
		defaultChecker = &checker{
			ll: newDefaultLogList(),
		}
	})

	return defaultChecker
}

// CheckConnectionState examines SCTs (both embedded and in the TLS extension) and returns
// nil if at least one of them is valid.
func CheckConnectionState(state *tls.ConnectionState) error {
	return getDefaultChecker().checkSCTs(state)
}

func (c *checker) checkSCTs(state *tls.ConnectionState) error {
	if state == nil {
		return errors.New("no TLS connection state")
	}

	if len(state.PeerCertificates) == 0 {
		return errors.New("no peer certificates in TLS connection state")
	}

	chain, err := buildCertificateChain(state.PeerCertificates)
	if err != nil {
		return err
	}

	lastError := errors.New("no Signed Certificate Timestamps found")

	// SCTs provided in the TLS handshake.
	if err = c.checkTLSSCTs(state.SignedCertificateTimestamps, chain); err != nil {
		lastError = err
	} else {
		return nil
	}

	// Check SCTs embedded in the leaf certificate.
	if err = c.checkCertSCTs(chain); err != nil {
		lastError = err
	} else {
		return nil
	}

	// TODO(mberhault): check SCTs in OSCP response.
	return lastError
}

// Check SCTs provided with the TLS handshake. Returns an error if no SCT is valid.
func (c *checker) checkTLSSCTs(scts [][]byte, chain []*ctx509.Certificate) error {
	if len(scts) == 0 {
		return errors.New("no SCTs in SSL handshake")
	}

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

// Check SCTs embedded in the leaf certificate. Returns an error if no SCT is valid.
func (c *checker) checkCertSCTs(chain []*ctx509.Certificate) error {
	leaf := chain[0]
	if len(leaf.SCTList.SCTList) == 0 {
		return errors.New("no SCTs in leaf certificate")
	}

	if len(chain) < 2 {
		// TODO(mberhault): optionally fetch issuer from IssuingCertificateURL.
		return errors.New("no issuer certificate in chain")
	}
	issuer := chain[1]

	merkleLeaf, err := ct.MerkleTreeLeafForEmbeddedSCT([]*ctx509.Certificate{leaf, issuer}, 0)
	if err != nil {
		return err
	}

	for _, sct := range leaf.SCTList.SCTList {
		err := c.checkOneSCT(&sct, merkleLeaf)
		if err == nil {
			// Valid: return early.
			return nil
		}
	}

	return errors.New("no valid SCT in SSL handshake")
}

func (c *checker) checkOneSCT(x509SCT *ctx509.SerializedSCT, merkleLeaf *ct.MerkleTreeLeaf) error {
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
		return err
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
