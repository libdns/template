package nameocean

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// TestLive runs against the real API when NAMEOCEAN_API_KEY (dns:read and
// dns:write) and LIBDNS_NAMEOCEAN_TEST_ZONE (a zone on that account, e.g.
// "example.com.") are set. It adds, changes and deletes records under the
// libdns-test name and leaves the zone as it found it.
//
//	NAMEOCEAN_API_KEY=... LIBDNS_NAMEOCEAN_TEST_ZONE=example.com. go test -run TestLive -v
func TestLive(t *testing.T) {
	zone := os.Getenv("LIBDNS_NAMEOCEAN_TEST_ZONE")
	if zone == "" || os.Getenv("NAMEOCEAN_API_KEY") == "" {
		t.Skip("set NAMEOCEAN_API_KEY and LIBDNS_NAMEOCEAN_TEST_ZONE to run against the real API")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p := &Provider{}
	const name = "libdns-test"

	count := func() map[string]int {
		recs, err := p.GetRecords(ctx, zone)
		if err != nil {
			t.Fatal(err)
		}
		n := map[string]int{}
		for _, r := range recs {
			n[r.RR().Name+" "+r.RR().Type]++
		}
		return n
	}
	before := count()
	t.Cleanup(func() {
		_, _ = p.DeleteRecords(context.Background(), zone, []libdns.Record{
			libdns.RR{Name: name}, libdns.RR{Name: "_acme-challenge." + name},
		})
	})

	zones, err := p.ListZones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, z := range zones {
		found = found || z.Name == libdns.AbsoluteName("@", zone)
	}
	if !found {
		t.Fatalf("%s not in ListZones: %v", zone, zones)
	}

	// ACME: two TXT values on one name (apex + wildcard), then remove them
	acme := "_acme-challenge." + name
	added, err := p.AppendRecords(ctx, zone, []libdns.Record{
		libdns.TXT{Name: acme, Text: "libdns-one"},
		libdns.TXT{Name: acme, Text: "libdns-two"},
	})
	if err != nil || len(added) != 2 {
		t.Fatalf("append TXT: %v %#v", err, added)
	}
	if got := count()[acme+" TXT"]; got != 2 {
		t.Fatalf("%d TXT on %s, want 2", got, acme)
	}

	// set an A RRset, change it, then a TTL
	ip1, ip2 := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")
	if _, err := p.SetRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: name, IP: ip1, TTL: time.Hour},
		libdns.Address{Name: name, IP: ip2, TTL: time.Hour},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.SetRecords(ctx, zone, []libdns.Record{libdns.Address{Name: name, IP: ip2, TTL: 5 * time.Minute}}); err != nil {
		t.Fatal(err)
	}
	recs, _ := p.GetRecords(ctx, zone)
	var as []libdns.Address
	for _, r := range recs {
		if a, ok := r.(libdns.Address); ok && a.Name == name {
			as = append(as, a)
		}
	}
	if len(as) != 1 || as[0].IP != ip2 || as[0].TTL != 5*time.Minute {
		t.Fatalf("A after set: %#v", as)
	}
	// other kinds round-trip
	if _, err := p.AppendRecords(ctx, zone, []libdns.Record{
		libdns.MX{Name: name, Preference: 10, Target: "mail." + libdns.AbsoluteName("@", zone)},
		libdns.CAA{Name: name, Tag: "issue", Value: "letsencrypt.org"},
	}); err != nil {
		t.Fatal(err)
	}

	del, err := p.DeleteRecords(ctx, zone, []libdns.Record{libdns.RR{Name: acme, Type: "TXT"}, libdns.RR{Name: name}})
	if err != nil || len(del) != 5 {
		t.Fatalf("delete: %v, %d deleted (want 5): %#v", err, len(del), del)
	}
	after := count()
	for k, v := range before {
		if after[k] != v {
			t.Errorf("%s: %d before, %d after", k, v, after[k])
		}
	}
	for k, v := range after {
		if before[k] != v {
			t.Errorf("%s: %d before, %d after", k, before[k], v)
		}
	}
}
