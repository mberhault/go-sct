package sct

import (
	"fmt"
	"log"
	"net/http"
	"time"

	ct "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/ctutil"
	ctjsonclient "github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist2"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
)

const (
	logListURL       = loglist2.LogListURL
	logListSigURL    = loglist2.LogListSignatureURL
	logListPubKeyURL = "https://www.gstatic.com/ct/log_list/v2/log_list_pubkey.pem"
)

var (
	qualifiedLogs = []loglist2.LogStatus{
		loglist2.QualifiedLogStatus,
		loglist2.UsableLogStatus,
		loglist2.ReadOnlyLogStatus,
	}
)

func newDefaultLogList() *loglist2.LogList {
	return newLogListFromSources(logListURL, logListSigURL, logListPubKeyURL)
}

func newLogListFromSources(listURL, listSigURL, listPubKeyURL string) *loglist2.LogList {
	jsonData, err := ctx509util.ReadFileOrURL(listURL, http.DefaultClient)
	if err != nil {
		log.Fatalf("failed to fetch log list %s: %v", listURL, err)
	}

	sigData, err := ctx509util.ReadFileOrURL(listSigURL, http.DefaultClient)
	if err != nil {
		log.Fatalf("failed to fetch log list signature %s: %v", listSigURL, err)
	}

	pemData, err := ctx509util.ReadFileOrURL(listPubKeyURL, http.DefaultClient)
	if err != nil {
		log.Fatalf("failed to fetch log list public key %s: %v", listPubKeyURL, err)
	}

	pubKey, _, _, err := ct.PublicKeyFromPEM(pemData)
	if err != nil {
		log.Fatalf("could not parse log list public key %s: %v", listPubKeyURL, err)
	}

	ll, err := loglist2.NewFromSignedJSON(jsonData, sigData, pubKey)
	if err != nil {
		log.Fatalf("could not verify log list signature: %v", err)
	}

	qualifiedLogs := ll.SelectByStatus(qualifiedLogs)
	return &qualifiedLogs
}

func newLogInfoFromLog(ctLog *loglist2.Log) (*ctutil.LogInfo, error) {
	client, err := ctclient.New(
		ctLog.URL,
		http.DefaultClient,
		ctjsonclient.Options{PublicKeyDER: ctLog.Key, UserAgent: "go-st"},
	)
	if err != nil {
		return nil, fmt.Errorf("could not create client for log %q: %v", ctLog.Description, err)
	}

	logKey, err := ctx509.ParsePKIXPublicKey(ctLog.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key for log %q: %v", ctLog.Description, err)
	}

	verifier, err := ct.NewSignatureVerifier(logKey)
	if err != nil {
		return nil, fmt.Errorf("failed to build verifier for log %q: %v", ctLog.Description, err)
	}

	mmd := time.Duration(ctLog.MMD) * time.Second
	logInfo := &ctutil.LogInfo{
		Description: ctLog.Description,
		Client:      client,
		MMD:         mmd,
		Verifier:    verifier,
		PublicKey:   ctLog.Key,
	}

	return logInfo, nil
}
