package sct

import "testing"

var (
	testLogListPath       = "testdata/log_list.json"
	testLogListSigPath    = "testdata/log_list.sig"
	testLogListPubKeyPath = "testdata/log_list_pubkey.pem"
)

func TestNewLogListSigned(t *testing.T) {
	ll := newLogListFromSources(testLogListPath, testLogListSigPath, testLogListPubKeyPath)
	if ll == nil {
		t.Fatal("returned log list is nil")
	}
}
