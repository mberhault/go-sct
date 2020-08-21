package sct

import (
	"log"
	"net/http"

	ct "github.com/mberhault/certificate-transparency-go"
	"github.com/mberhault/certificate-transparency-go/loglist2"
	"github.com/mberhault/certificate-transparency-go/x509util"
)

const (
	logListURL       = loglist2.LogListURL
	logListSigURL    = loglist2.LogListSignatureURL
	logListPubKeyURL = "https://www.gstatic.com/ct/log_list/v2/log_list_pubkey.pem"
)

func newDefaultLogList() *loglist2.LogList {
	return newLogListFromSources(logListURL, logListSigURL, logListPubKeyURL)
}

func newLogListFromSources(listURL, listSigURL, listPubKeyURL string) *loglist2.LogList {
	jsonData, err := x509util.ReadFileOrURL(listURL, http.DefaultClient)
	if err != nil {
		log.Fatalf("failed to fetch log list %s: %v", listURL, err)
	}

	sigData, err := x509util.ReadFileOrURL(listSigURL, http.DefaultClient)
	if err != nil {
		log.Fatalf("failed to fetch log list signature %s: %v", listSigURL, err)
	}

	pemData, err := x509util.ReadFileOrURL(listPubKeyURL, http.DefaultClient)
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

	return ll
}
