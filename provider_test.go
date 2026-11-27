package nameocean

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// fakeAPI is an in-memory stand-in for NameOcean's /api/v1/dns endpoints.
type fakeAPI struct {
	mu      sync.Mutex
	zone    string
	nextID  int64
	records []apiRecord
	calls   []string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	if r.Header.Get("Authorization") != "Bearer test-key" {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": "Invalid API key.", "code": "unauthorized"}`))
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// /api/v1/dns, /api/v1/dns/{zone}/records, /api/v1/dns/{zone}/records/{type}/{id}
	if len(parts) == 3 && r.Method == http.MethodGet {
		_ = json.NewEncoder(w).Encode(map[string]any{"zones": []map[string]any{{"name": f.zone, "serial": 1}}})
		return
	}
	if len(parts) < 5 || parts[3] != f.zone {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error": "You have no DNS zone named that.", "code": "not_found"}`))
		return
	}
	switch {
	case len(parts) == 5 && r.Method == http.MethodGet:
		_ = json.NewEncoder(w).Encode(map[string]any{"zone": f.zone, "records": f.records})
	case len(parts) == 5 && r.Method == http.MethodPost:
		var in apiRecord
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if msg := validate(in); msg != "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": msg, "code": "invalid"})
			return
		}
		for _, ex := range f.records {
			if in.Type == "CNAME" && ex.Type == "CNAME" && ex.Hostname == in.Hostname {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error": "The fields zone, hostname must make a unique set.", "code": "invalid"}`))
				return
			}
			if sameRecord(ex, in, false) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error": "The fields zone, hostname, ip must make a unique set.", "code": "invalid"}`))
				return
			}
		}
		f.nextID++
		in.ID = f.nextID
		if in.TTL == "" {
			in.TTL = "1h"
		}
		f.records = append(f.records, in)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(in)
	case len(parts) == 7 && r.Method == http.MethodPatch:
		id, _ := strconv.ParseInt(parts[6], 10, 64)
		var in map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&in)
		for i, rec := range f.records {
			if rec.ID == id && rec.Type == parts[5] {
				merged, _ := json.Marshal(rec)
				var m map[string]json.RawMessage
				_ = json.Unmarshal(merged, &m)
				for k, v := range in {
					if k != "id" && k != "type" {
						m[k] = v
					}
				}
				merged, _ = json.Marshal(m)
				var upd apiRecord
				_ = json.Unmarshal(merged, &upd)
				if msg := validate(upd); msg != "" {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
					return
				}
				f.records[i] = upd
				_ = json.NewEncoder(w).Encode(upd)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	case len(parts) == 7 && r.Method == http.MethodDelete:
		id, _ := strconv.ParseInt(parts[6], 10, 64)
		for i, rec := range f.records {
			if rec.ID == id && rec.Type == parts[5] {
				f.records = append(f.records[:i], f.records[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error": "No such record.", "code": "not_found"}`))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// validate checks what the real API checks that matters here.
func validate(r apiRecord) string {
	switch r.TTL {
	case "", "5m", "15m", "30m", "1h", "1d":
	default:
		return "ttl must be one of 5m, 15m, 30m, 1h, 1d"
	}
	if r.Hostname == "" || strings.HasSuffix(r.Hostname, ".") {
		return "Hostname is not valid"
	}
	if strings.HasSuffix(r.Target, ".") && r.Target != "." {
		return "Hostname is not valid"
	}
	if strings.Contains(r.Text, `"`) {
		return "Record must not contain any quotes."
	}
	return ""
}

func setup(t *testing.T, records ...apiRecord) (*Provider, *fakeAPI) {
	t.Helper()
	f := &fakeAPI{zone: "example.com"}
	for _, r := range records {
		f.nextID++
		r.ID = f.nextID
		f.records = append(f.records, r)
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &Provider{APIKey: "test-key", BaseURL: srv.URL + "/api/v1"}, f
}

func p(n int) *int { return &n }

func TestGetRecordsTypes(t *testing.T) {
	prov, _ := setup(t,
		apiRecord{Type: "A", Hostname: "@", IP: "192.0.2.1", TTL: "1h"},
		apiRecord{Type: "AAAA", Hostname: "www", IP: "2001:db8::1", TTL: "5m"},
		apiRecord{Type: "CNAME", Hostname: "blog", Target: "@", TTL: "1h"},
		apiRecord{Type: "MX", Hostname: "@", Target: "mail.example.net", Priority: p(10), TTL: "1d"},
		apiRecord{Type: "TXT", Hostname: "_acme-challenge", Text: "token value", TTL: "5m"},
		apiRecord{Type: "SRV", Hostname: "_sip._tcp", Target: "sip.example.com", Priority: p(1), Weight: p(5), Port: p(5060), TTL: "1h"},
		apiRecord{Type: "CAA", Hostname: "@", Flags: p(0), Tag: "issue", Value: "letsencrypt.org", TTL: "1h"},
		apiRecord{Type: "HTTPS", Hostname: "@", Target: ".", Priority: p(1), Params: "alpn=h2,h3", TTL: "1h"},
		apiRecord{Type: "ALIAS", Hostname: "@", Target: "app.example.net", TTL: "5m"},
		apiRecord{Type: "REDIRECT", Hostname: "old", Target: "https://example.com/"},
	)
	recs, err := prov.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 9 {
		t.Fatalf("got %d records, want 9 (REDIRECT left out): %#v", len(recs), recs)
	}
	if a, ok := recs[0].(libdns.Address); !ok || a.Name != "@" || a.IP != netip.MustParseAddr("192.0.2.1") || a.TTL != time.Hour {
		t.Errorf("A: %#v", recs[0])
	}
	if a, ok := recs[1].(libdns.Address); !ok || a.Name != "www" || a.TTL != 5*time.Minute {
		t.Errorf("AAAA: %#v", recs[1])
	}
	if c, ok := recs[2].(libdns.CNAME); !ok || c.Target != "example.com." {
		t.Errorf("CNAME to @: %#v", recs[2])
	}
	if m, ok := recs[3].(libdns.MX); !ok || m.Preference != 10 || m.Target != "mail.example.net." || m.TTL != 24*time.Hour {
		t.Errorf("MX: %#v", recs[3])
	}
	if x, ok := recs[4].(libdns.TXT); !ok || x.Text != "token value" || x.Name != "_acme-challenge" {
		t.Errorf("TXT: %#v", recs[4])
	}
	if s, ok := recs[5].(libdns.SRV); !ok || s.Service != "sip" || s.Transport != "tcp" || s.Name != "@" || s.Port != 5060 || s.Target != "sip.example.com." {
		t.Errorf("SRV: %#v", recs[5])
	}
	if c, ok := recs[6].(libdns.CAA); !ok || c.Tag != "issue" || c.Value != "letsencrypt.org" {
		t.Errorf("CAA: %#v", recs[6])
	}
	if h, ok := recs[7].(libdns.ServiceBinding); !ok || h.Target != "." || h.Priority != 1 || len(h.Params["alpn"]) != 2 {
		t.Errorf("HTTPS: %#v", recs[7])
	}
	if r, ok := recs[8].(libdns.RR); !ok || r.Type != "ALIAS" || r.Data != "app.example.net." {
		t.Errorf("ALIAS: %#v", recs[8])
	}
}

func TestAppendRecordsACME(t *testing.T) {
	prov, f := setup(t)
	ctx := context.Background()
	// apex and wildcard certificates: two values on one name, added concurrently
	var wg sync.WaitGroup
	for _, v := range []string{"one", "two"} {
		wg.Add(1)
		go func(v string) {
			defer wg.Done()
			got, err := prov.AppendRecords(ctx, "example.com.", []libdns.Record{
				libdns.TXT{Name: "_acme-challenge", Text: v, TTL: 0},
			})
			if err != nil || len(got) != 1 {
				t.Errorf("append %s: %v %#v", v, err, got)
			}
		}(v)
	}
	wg.Wait()
	if len(f.records) != 2 || f.records[0].TTL != "5m" {
		t.Fatalf("records: %#v", f.records)
	}
	del, err := prov.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.TXT{Name: "_acme-challenge", Text: "one"}})
	if err != nil || len(del) != 1 || del[0].(libdns.TXT).Text != "one" {
		t.Fatalf("delete: %v %#v", err, del)
	}
	if len(f.records) != 1 || f.records[0].Text != "two" {
		t.Fatalf("left: %#v", f.records)
	}
}

func TestAppendRecordsKinds(t *testing.T) {
	prov, f := setup(t)
	_, err := prov.AppendRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.Address{Name: "v6", IP: netip.MustParseAddr("2001:db8::5"), TTL: 20 * time.Minute},
		libdns.CNAME{Name: "www.example.com.", Target: "example.com."},
		libdns.MX{Name: "@", Preference: 5, Target: "mx.example.net.", TTL: 2 * time.Hour},
		libdns.SRV{Service: "xmpp", Transport: "tcp", Name: "chat", Priority: 1, Weight: 2, Port: 5222, Target: "x.example.net."},
		libdns.CAA{Name: "@", Tag: "issuewild", Value: ";"},
		libdns.RR{Name: "@", Type: "ALIAS", Data: "lb.example.net."},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []apiRecord{
		{Type: "AAAA", Hostname: "v6", IP: "2001:db8::5", TTL: "15m"},
		{Type: "CNAME", Hostname: "www", Target: "@", TTL: "5m"},
		{Type: "MX", Hostname: "@", Target: "mx.example.net", Priority: p(5), TTL: "1h"},
		{Type: "SRV", Hostname: "_xmpp._tcp.chat", Target: "x.example.net", Priority: p(1), Weight: p(2), Port: p(5222), TTL: "5m"},
		{Type: "CAA", Hostname: "@", Flags: p(0), Tag: "issuewild", Value: ";", TTL: "5m"},
		{Type: "ALIAS", Hostname: "@", Target: "lb.example.net", TTL: "5m"},
	}
	for i, w := range want {
		got := f.records[i]
		if !sameRecord(got, w, true) {
			t.Errorf("record %d: got %+v, want %+v", i, got, w)
		}
	}
}

func TestSetRecords(t *testing.T) {
	prov, f := setup(t,
		apiRecord{Type: "A", Hostname: "@", IP: "192.0.2.1", TTL: "1h"},
		apiRecord{Type: "A", Hostname: "@", IP: "192.0.2.2", TTL: "1h"},
		apiRecord{Type: "TXT", Hostname: "@", Text: "hello world", TTL: "1h"},
		apiRecord{Type: "AAAA", Hostname: "beta", IP: "2001:db8::3", TTL: "1h"},
	)
	ctx := context.Background()
	// libdns godoc, example 1: the A RRset becomes just .3; TXT stays
	got, err := prov.SetRecords(ctx, "example.com.", []libdns.Record{
		libdns.Address{Name: "@", IP: netip.MustParseAddr("192.0.2.3"), TTL: time.Hour},
	})
	if err != nil || len(got) != 1 {
		t.Fatalf("set: %v %#v", err, got)
	}
	var left []string
	for _, r := range f.records {
		left = append(left, r.Type+" "+r.Hostname+" "+r.IP+r.Text)
	}
	sort.Strings(left)
	want := []string{"A @ 192.0.2.3", "AAAA beta 2001:db8::3", "TXT @ hello world"}
	if strings.Join(left, "|") != strings.Join(want, "|") {
		t.Fatalf("zone after set: %v", left)
	}

	// setting what is already there changes nothing
	before := len(f.calls)
	if _, err := prov.SetRecords(ctx, "example.com.", []libdns.Record{
		libdns.Address{Name: "@", IP: netip.MustParseAddr("192.0.2.3"), TTL: time.Hour},
	}); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls[before:] {
		if !strings.HasPrefix(c, "GET ") {
			t.Errorf("unexpected write on a no-op set: %s", c)
		}
	}

	// a different TTL replaces the record
	if _, err := prov.SetRecords(ctx, "example.com.", []libdns.Record{
		libdns.Address{Name: "@", IP: netip.MustParseAddr("192.0.2.3"), TTL: 5 * time.Minute},
	}); err != nil {
		t.Fatal(err)
	}
	if last := f.calls[len(f.calls)-1]; !strings.HasPrefix(last, "PATCH ") {
		t.Errorf("TTL change should be a PATCH, last call %s", last)
	}
	n := 0
	for _, r := range f.records {
		if r.Type == "A" {
			n++
			if r.TTL != "5m" {
				t.Errorf("TTL not changed: %+v", r)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d A records after TTL change, want 1", n)
	}
}

func TestDeleteRecordsWildcards(t *testing.T) {
	prov, f := setup(t,
		apiRecord{Type: "TXT", Hostname: "x", Text: "a", TTL: "5m"},
		apiRecord{Type: "TXT", Hostname: "x", Text: "b", TTL: "1h"},
		apiRecord{Type: "A", Hostname: "x", IP: "192.0.2.9", TTL: "5m"},
		apiRecord{Type: "A", Hostname: "y", IP: "192.0.2.9", TTL: "5m"},
	)
	ctx := context.Background()
	// wrong TTL: nothing
	del, err := prov.DeleteRecords(ctx, "example.com", []libdns.Record{libdns.RR{Name: "x", Type: "TXT", TTL: time.Hour * 24}})
	if err != nil || len(del) != 0 {
		t.Fatalf("ttl mismatch deleted %v %#v", err, del)
	}
	// name + type: both TXT
	del, err = prov.DeleteRecords(ctx, "example.com", []libdns.Record{libdns.RR{Name: "x", Type: "TXT"}})
	if err != nil || len(del) != 2 {
		t.Fatalf("name+type: %v %#v", err, del)
	}
	// name only: the A on x, not the one on y
	del, err = prov.DeleteRecords(ctx, "example.com", []libdns.Record{libdns.RR{Name: "x"}})
	if err != nil || len(del) != 1 || len(f.records) != 1 || f.records[0].Hostname != "y" {
		t.Fatalf("name only: %v %#v %#v", err, del, f.records)
	}
	// missing records are ignored
	del, err = prov.DeleteRecords(ctx, "example.com", []libdns.Record{libdns.TXT{Name: "nope", Text: "z"}})
	if err != nil || len(del) != 0 {
		t.Fatalf("missing: %v %#v", err, del)
	}
	if _, err := prov.DeleteRecords(ctx, "example.com", []libdns.Record{libdns.RR{}}); err == nil {
		t.Error("delete without a name should fail")
	}
}

func TestListZonesAndErrors(t *testing.T) {
	prov, _ := setup(t)
	zones, err := prov.ListZones(context.Background())
	if err != nil || len(zones) != 1 || zones[0].Name != "example.com." {
		t.Fatalf("zones: %v %#v", err, zones)
	}
	if _, err := prov.GetRecords(context.Background(), "other.com."); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("unknown zone: %v", err)
	}
	prov.APIKey = "wrong"
	if _, err := prov.GetRecords(context.Background(), "example.com."); err == nil || !strings.Contains(err.Error(), "Invalid API key") {
		t.Errorf("bad key: %v", err)
	}
	empty := &Provider{BaseURL: prov.BaseURL}
	t.Setenv("NAMEOCEAN_API_KEY", "")
	if _, err := empty.GetRecords(context.Background(), "example.com."); err == nil || !strings.Contains(err.Error(), "no API key") {
		t.Errorf("no key: %v", err)
	}
	t.Setenv("NAMEOCEAN_API_KEY", "test-key")
	if _, err := empty.GetRecords(context.Background(), "example.com."); err != nil {
		t.Errorf("key from env: %v", err)
	}
}

func TestTTLRounding(t *testing.T) {
	cases := map[time.Duration]string{
		0:                 "5m",
		time.Second:       "5m",
		10 * time.Minute:  "5m", // tie goes to the shorter
		11 * time.Minute:  "15m",
		45 * time.Minute:  "30m",
		50 * time.Minute:  "1h",
		3 * time.Hour:     "1h",
		48 * time.Hour:    "1d",
		24 * time.Hour:    "1d",
		300 * time.Second: "5m",
	}
	for d, want := range cases {
		if got := ttlString(d); got != want {
			t.Errorf("ttlString(%v) = %s, want %s", d, got, want)
		}
	}
}

func TestSetRecordsChangesInPlace(t *testing.T) {
	prov, f := setup(t,
		apiRecord{Type: "CNAME", Hostname: "www", Target: "old.example.net", TTL: "1h"},
		apiRecord{Type: "A", Hostname: "v", IP: "192.0.2.1", TTL: "1h"},
		apiRecord{Type: "AAAA", Hostname: "v", IP: "2001:db8::1", TTL: "1h"},
	)
	ctx := context.Background()
	// one CNAME per name: changing the target must not add a second one first
	if _, err := prov.SetRecords(ctx, "example.com.", []libdns.Record{
		libdns.CNAME{Name: "www", Target: "new.example.net.", TTL: time.Hour},
	}); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 3 || f.records[0].Target != "new.example.net" || f.records[0].ID != 1 {
		t.Fatalf("CNAME not changed in place: %+v", f.records)
	}
	// setting AAAA leaves the A record alone
	if _, err := prov.SetRecords(ctx, "example.com.", []libdns.Record{
		libdns.Address{Name: "v", IP: netip.MustParseAddr("2001:db8::2"), TTL: time.Hour},
	}); err != nil {
		t.Fatal(err)
	}
	var a, aaaa []string
	for _, r := range f.records {
		switch r.Type {
		case "A":
			a = append(a, r.IP)
		case "AAAA":
			aaaa = append(aaaa, r.IP)
		}
	}
	if strings.Join(a, ",") != "192.0.2.1" || strings.Join(aaaa, ",") != "2001:db8::2" {
		t.Fatalf("A %v AAAA %v", a, aaaa)
	}
}

func TestHTTPSParamsOrder(t *testing.T) {
	prov, f := setup(t, apiRecord{Type: "HTTPS", Hostname: "h", Target: "t.example.com", Priority: p(1),
		Params: "alpn=h2,h3 port=443 ipv4hint=192.0.2.1", TTL: "5m"})
	del, err := prov.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.ServiceBinding{Scheme: "https", Name: "h", Priority: 1, Target: "t.example.com.", TTL: 5 * time.Minute,
			Params: libdns.SvcParams{"ipv4hint": {"192.0.2.1"}, "port": {"443"}, "alpn": {"h2", "h3"}}},
	})
	if err != nil || len(del) != 1 || len(f.records) != 0 {
		t.Fatalf("delete by params in another order: %v %#v %#v", err, del, f.records)
	}
}
