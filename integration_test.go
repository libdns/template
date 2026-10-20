package hosterby

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// TestIntegration runs against the live API if HOSTERBY_ACCESS_KEY,
// HOSTERBY_SECRET_KEY and HOSTERBY_TEST_ZONE are set. It creates records only
// below a random libdns-test-* name and removes them afterwards.
//
// ALIAS records are accepted only at the zone apex, so the ALIAS test runs
// only with HOSTERBY_TEST_APEX_ALIAS=1 and if the apex has no A, AAAA or ALIAS
// records.
func TestIntegration(t *testing.T) {
	accessKey := os.Getenv("HOSTERBY_ACCESS_KEY")
	secretKey := os.Getenv("HOSTERBY_SECRET_KEY")
	zone := os.Getenv("HOSTERBY_TEST_ZONE")
	if accessKey == "" || secretKey == "" || zone == "" {
		t.Skip("HOSTERBY_ACCESS_KEY, HOSTERBY_SECRET_KEY and HOSTERBY_TEST_ZONE must be set")
	}
	zone = normalizeZone(zone)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	p := &Provider{AccessKey: accessKey, SecretKey: secretKey}

	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	// The API allows underscores only in TXT and SRV names.
	base := "libdns-test-" + hex.EncodeToString(suffix)
	t.Logf("using names below %s.%s", base, zone)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		records, err := p.GetRecords(ctx, zone)
		if err != nil {
			t.Fatalf("GetRecords: %v", err)
		}
		var leftovers []libdns.Record
		for _, r := range records {
			if name := r.RR().Name; name == base || strings.HasSuffix(name, "."+base) {
				leftovers = append(leftovers, r)
			}
		}
		if len(leftovers) == 0 {
			return
		}
		t.Logf("removing %d leftover records", len(leftovers))
		if _, err := p.DeleteRecords(ctx, zone, leftovers); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	// expect checks that the zone has exactly want records of name and type.
	expect := func(t *testing.T, name, typ string, want ...libdns.Record) {
		t.Helper()
		records, err := p.GetRecords(ctx, zone)
		if err != nil {
			t.Fatalf("GetRecords: %v", err)
		}
		var got []libdns.RR
		for _, r := range records {
			if rr := r.RR(); rr.Name == name && rr.Type == typ {
				got = append(got, rr)
			}
		}
		if len(got) != len(want) {
			t.Fatalf("%s %s records = %+v, want %+v", name, typ, got, want)
		}
		for _, w := range want {
			if !slices.Contains(got, w.RR()) {
				t.Fatalf("%s %s records = %+v, want %+v", name, typ, got, want)
			}
		}
	}

	t.Run("ListZones", func(t *testing.T) {
		zones, err := p.ListZones(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(zones, libdns.Zone{Name: zone}) {
			t.Fatalf("zones = %v, want %s among them", zones, zone)
		}
	})

	const ttl = 15 * time.Minute
	long := strings.Repeat("0123456789", 30)

	// For every record type: two values to append, and a value to replace them.
	tests := []struct {
		typ    string
		name   string
		apex   bool
		first  libdns.Record
		second libdns.Record
		set    libdns.Record
	}{
		{
			typ:    "A",
			first:  libdns.Address{TTL: ttl, IP: netip.MustParseAddr("192.0.2.1")},
			second: libdns.Address{TTL: ttl, IP: netip.MustParseAddr("192.0.2.2")},
			set:    libdns.Address{TTL: ttl, IP: netip.MustParseAddr("192.0.2.3")},
		},
		{
			typ:    "AAAA",
			first:  libdns.Address{TTL: ttl, IP: netip.MustParseAddr("2001:db8::1")},
			second: libdns.Address{TTL: ttl, IP: netip.MustParseAddr("2001:db8::2")},
			set:    libdns.Address{TTL: ttl, IP: netip.MustParseAddr("2001:db8::3")},
		},
		{
			typ:    "TXT",
			first:  libdns.TXT{TTL: ttl, Text: "first"},
			second: libdns.TXT{TTL: ttl, Text: `say "hi"; привет; ` + long},
			set:    libdns.TXT{TTL: ttl, Text: "v=spf1 -all"},
		},
		{
			typ:    "MX",
			first:  libdns.MX{TTL: ttl, Preference: 10, Target: "mx1.example.com."},
			second: libdns.MX{TTL: ttl, Preference: 20, Target: "mx2.example.com."},
			set:    libdns.MX{TTL: ttl, Preference: 30, Target: "mx3.example.com."},
		},
		{
			typ:    "NS",
			first:  libdns.NS{TTL: ttl, Target: "ns1.example.com."},
			second: libdns.NS{TTL: ttl, Target: "ns2.example.com."},
			set:    libdns.NS{TTL: ttl, Target: "ns3.example.com."},
		},
		{
			typ:    "SRV",
			name:   "_sip._tcp",
			first:  libdns.SRV{Service: "sip", Transport: "tcp", TTL: ttl, Priority: 10, Weight: 5, Port: 5060, Target: "sip1.example.com."},
			second: libdns.SRV{Service: "sip", Transport: "tcp", TTL: ttl, Priority: 20, Weight: 5, Port: 5060, Target: "sip2.example.com."},
			set:    libdns.SRV{Service: "sip", Transport: "tcp", TTL: ttl, Priority: 30, Weight: 0, Port: 5061, Target: "sip3.example.com."},
		},
		{
			typ:    "CAA",
			first:  libdns.CAA{TTL: ttl, Flags: 0, Tag: "issue", Value: "letsencrypt.org"},
			second: libdns.CAA{TTL: ttl, Flags: 0, Tag: "iodef", Value: "mailto:security@example.com"},
			set:    libdns.CAA{TTL: ttl, Flags: 0, Tag: "issuewild", Value: "letsencrypt.org"},
		},
		// CNAME and ALIAS sets can hold a single value only.
		{
			typ:   "CNAME",
			first: libdns.CNAME{TTL: ttl, Target: "target1.example.com."},
			set:   libdns.CNAME{TTL: ttl, Target: "target2.example.com."},
		},
		{
			typ:  "ALIAS",
			apex: true,
			// The targets must resolve, or apex lookups fail while the
			// record exists.
			first: libdns.RR{Type: "ALIAS", TTL: minTTL, Data: "example.com."},
			set:   libdns.RR{Type: "ALIAS", TTL: minTTL, Data: "www.example.com."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.typ, func(t *testing.T) {
			// Separate names keep CNAME from conflicting with other types.
			name := strings.ToLower(tt.typ) + "." + base
			if tt.name != "" {
				name = tt.name + "." + name
			}
			if tt.apex {
				name = "@"
				if os.Getenv("HOSTERBY_TEST_APEX_ALIAS") != "1" {
					t.Skip("set HOSTERBY_TEST_APEX_ALIAS=1 to test records at the zone apex")
				}
				records, err := p.GetRecords(ctx, zone)
				if err != nil {
					t.Fatalf("GetRecords: %v", err)
				}
				for _, r := range records {
					rr := r.RR()
					if rr.Name == name && (rr.Type == tt.typ || rr.Type == "A" || rr.Type == "AAAA") {
						t.Skipf("the zone apex already has %s records", rr.Type)
					}
				}
				t.Cleanup(func() {
					ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
					defer cancel()
					if _, err := p.DeleteRecords(ctx, zone, []libdns.Record{libdns.RR{Name: name, Type: tt.typ}}); err != nil {
						t.Errorf("cleanup: %v", err)
					}
				})
			}
			withName := func(r libdns.Record) libdns.Record {
				if r == nil {
					return nil
				}
				rr := r.RR()
				rr.Name = name
				parsed, err := rr.Parse()
				if err != nil {
					t.Fatal(err)
				}
				return parsed
			}
			first, second, set := withName(tt.first), withName(tt.second), withName(tt.set)

			// Append creates the record set.
			added, err := p.AppendRecords(ctx, zone, []libdns.Record{first})
			if err != nil {
				t.Fatalf("AppendRecords: %v", err)
			}
			if len(added) != 1 {
				t.Fatalf("AppendRecords returned %v, want 1 record", added)
			}
			expect(t, name, tt.typ, first)

			// Append extends the record set and skips existing records.
			if second != nil {
				added, err = p.AppendRecords(ctx, zone, []libdns.Record{first, second})
				if err != nil {
					t.Fatalf("AppendRecords: %v", err)
				}
				if len(added) != 1 {
					t.Fatalf("AppendRecords returned %v, want 1 record", added)
				}
				expect(t, name, tt.typ, first, second)
			}

			// Set replaces the record set.
			if _, err := p.SetRecords(ctx, zone, []libdns.Record{set}); err != nil {
				t.Fatalf("SetRecords: %v", err)
			}
			expect(t, name, tt.typ, set)

			// Delete removes only matching records.
			deleted, err := p.DeleteRecords(ctx, zone, []libdns.Record{first})
			if err != nil {
				t.Fatalf("DeleteRecords: %v", err)
			}
			if len(deleted) != 0 {
				t.Fatalf("DeleteRecords returned %v for a missing record", deleted)
			}
			deleted, err = p.DeleteRecords(ctx, zone, []libdns.Record{set})
			if err != nil {
				t.Fatalf("DeleteRecords: %v", err)
			}
			if len(deleted) != 1 {
				t.Fatalf("DeleteRecords returned %v, want 1 record", deleted)
			}
			expect(t, name, tt.typ)
		})
	}
}
