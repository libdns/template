package main

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/libdns/libdns/libdnstest"
	"github.com/libdns/mittwald"
)

// hostRewriter sends every request to another API host, such as a test
// system of mittwald.
type hostRewriter struct {
	to   *url.URL
	next http.RoundTripper
}

func (h hostRewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host, req.Host = h.to.Scheme, h.to.Host, h.to.Host
	return h.next.RoundTrip(req)
}

func TestMittwaldProvider(t *testing.T) {
	token := os.Getenv("MITTWALD_API_TOKEN")
	zone := os.Getenv("MITTWALD_TEST_ZONE")
	if token == "" || zone == "" {
		t.Skip("MITTWALD_API_TOKEN and MITTWALD_TEST_ZONE must be set")
	}
	if !strings.HasSuffix(zone, ".") {
		t.Fatal("MITTWALD_TEST_ZONE needs a trailing dot")
	}
	if u := os.Getenv("MITTWALD_API_URL"); u != "" {
		to, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		orig := http.DefaultTransport
		http.DefaultTransport = hostRewriter{to: to, next: orig}
		t.Cleanup(func() { http.DefaultTransport = orig })
	}

	suite := libdnstest.NewTestSuite(&mittwald.Provider{APIToken: token}, zone)
	suite.SkipRRTypes = map[string]bool{"NS": true, "SVCB": true, "HTTPS": true}
	suite.RunTests(t)
}
