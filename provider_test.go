package hosterby

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

const (
	testZone    = "example.com."
	testOrderID = "42"
)

// fakeAPI is an in-memory fake of the API endpoints used by the provider.
type fakeAPI struct {
	domain   string // name of the zone, as returned by the API
	mu       sync.Mutex
	tokens   int      // number of tokens issued
	token    string   // currently valid token
	lists    int      // number of order list requests
	failures []int    // HTTP statuses to respond with before handling requests
	failOn   string   // if set, failures apply only to requests with this method
	sets     []rrset  // record sets of the zone
	writes   []string // "METHOD path" of handled write requests
}

func newTestProvider(t *testing.T, sets ...rrset) (*Provider, *fakeAPI) {
	t.Helper()
	api := &fakeAPI{domain: strings.TrimSuffix(testZone, "."), sets: sets}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /service/account/create/token", api.createToken)
	mux.HandleFunc("GET /dns/orders", api.auth(api.listOrders))
	mux.HandleFunc("GET /dns/orders/{id}/records", api.auth(api.listRecords))
	mux.HandleFunc("POST /dns/orders/{id}/records/{type}", api.auth(api.createRRset))
	mux.HandleFunc("PATCH /dns/orders/{id}/records/{type}/{name}", api.auth(api.updateRRset))
	mux.HandleFunc("DELETE /dns/orders/{id}/records/{type}/{name}", api.auth(api.deleteRRset))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &Provider{AccessKey: "ak", SecretKey: "sk", BaseURL: srv.URL}, api
}

func respond(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status >= 400 {
		code := strings.ToLower(strings.ReplaceAll(http.StatusText(status), " ", "_"))
		json.NewEncoder(w).Encode(map[string]any{
			"statusCode":  "error",
			"codeList":    map[string]any{"error": []string{code}},
			"messageList": map[string]any{"error": map[string]any{code: payload}},
			"payload":     []any{},
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"statusCode": "ok",
		"payload":    payload,
	})
}

func (api *fakeAPI) createToken(w http.ResponseWriter, r *http.Request) {
	api.mu.Lock()
	defer api.mu.Unlock()
	if r.Header.Get("Access-Key") != "ak" || r.Header.Get("Secret-Key") != "sk" {
		respond(w, http.StatusUnauthorized, "invalid keys")
		return
	}
	api.tokens++
	api.token = fmt.Sprintf("token-%d", api.tokens)
	respond(w, http.StatusOK, map[string]any{
		"accessToken": api.token,
		"dateExpires": time.Now().Add(time.Hour).Unix(),
	})
}

func (api *fakeAPI) auth(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		if api.token == "" || r.Header.Get("Access-Token") != api.token {
			respond(w, http.StatusUnauthorized, "access token expired")
			return
		}
		if len(api.failures) > 0 && (api.failOn == "" || api.failOn == r.Method) {
			status := api.failures[0]
			api.failures = api.failures[1:]
			respond(w, status, "injected failure")
			return
		}
		if r.Method != http.MethodGet {
			api.writes = append(api.writes, r.Method+" "+r.URL.Path)
		}
		next(w, r)
	}
}

func (api *fakeAPI) listOrders(w http.ResponseWriter, r *http.Request) {
	api.lists++
	respond(w, http.StatusOK, map[string]any{
		"orders": []map[string]any{
			{"id": testOrderID, "domainName": api.domain},
			{"id": "7", "domainName": "example.net"},
		},
	})
}

func (api *fakeAPI) listRecords(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, map[string]any{"records": api.sets})
}

func (api *fakeAPI) find(name, typ string) int {
	return slices.IndexFunc(api.sets, func(s rrset) bool {
		return s.Name == name && strings.EqualFold(s.Type, typ)
	})
}

func (api *fakeAPI) createRRset(w http.ResponseWriter, r *http.Request) {
	var set rrset
	if err := json.NewDecoder(r.Body).Decode(&set); err != nil {
		respond(w, http.StatusBadRequest, err.Error())
		return
	}
	set.Type = strings.ToUpper(r.PathValue("type"))
	if !strings.HasSuffix(set.Name, "."+api.domain+".") && set.Name != api.domain+"." {
		respond(w, http.StatusBadRequest, "name outside of zone")
		return
	}
	if !validTTL(set.TTL) {
		respond(w, http.StatusBadRequest, "invalid ttl")
		return
	}
	// Like the real API, creating an existing record set appends to it and
	// sets its TTL, but rejects values that are already in it.
	if i := api.find(set.Name, set.Type); i >= 0 {
		for _, rec := range set.Records {
			if slices.ContainsFunc(api.sets[i].Records, func(r record) bool { return r.Content == rec.Content }) {
				respond(w, http.StatusBadRequest, "duplicate record")
				return
			}
		}
		api.sets[i].TTL = set.TTL
		api.sets[i].Records = append(api.sets[i].Records, set.Records...)
		respond(w, http.StatusOK, map[string]any{"record": api.sets[i]})
		return
	}
	api.sets = append(api.sets, set)
	respond(w, http.StatusOK, map[string]any{"record": set})
}

func (api *fakeAPI) updateRRset(w http.ResponseWriter, r *http.Request) {
	i := api.find(r.PathValue("name"), r.PathValue("type"))
	if i < 0 {
		respond(w, http.StatusBadRequest, "requested resource is not found")
		return
	}
	var body struct {
		TTL     int      `json:"ttl"`
		Records []record `json:"records"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respond(w, http.StatusBadRequest, err.Error())
		return
	}
	if !validTTL(body.TTL) {
		respond(w, http.StatusBadRequest, "invalid ttl")
		return
	}
	api.sets[i].TTL = body.TTL
	api.sets[i].Records = body.Records
	respond(w, http.StatusOK, map[string]any{"record": api.sets[i]})
}

func validTTL(ttl int) bool {
	return ttl >= 600 && ttl <= 604800
}

func (api *fakeAPI) deleteRRset(w http.ResponseWriter, r *http.Request) {
	i := api.find(r.PathValue("name"), r.PathValue("type"))
	if i < 0 {
		respond(w, http.StatusBadRequest, "requested resource is not found")
		return
	}
	set := api.sets[i]
	api.sets = slices.Delete(api.sets, i, i+1)
	respond(w, http.StatusOK, map[string]any{"record": set})
}

func (api *fakeAPI) lookup(name, typ string) (rrset, bool) {
	api.mu.Lock()
	defer api.mu.Unlock()
	if i := api.find(name, typ); i >= 0 {
		return api.sets[i], true
	}
	return rrset{}, false
}

func txtSet(name string, ttl int, values ...string) rrset {
	set := rrset{Name: name, Type: "TXT", TTL: ttl}
	for _, v := range values {
		set.Records = append(set.Records, record{Content: quoteTXT(v)})
	}
	return set
}

// assertRRs checks that got and want contain the same records in any order.
func assertRRs(t *testing.T, got []libdns.Record, want ...libdns.RR) {
	t.Helper()
	var rrs []libdns.RR
	for _, r := range got {
		rrs = append(rrs, r.RR())
	}
	byContent := func(a, b libdns.RR) int {
		return strings.Compare(a.Name+a.Type+a.Data, b.Name+b.Type+b.Data)
	}
	slices.SortFunc(rrs, byContent)
	slices.SortFunc(want, byContent)
	if !slices.Equal(rrs, want) {
		t.Errorf("records mismatch\n got: %+v\nwant: %+v", rrs, want)
	}
}

func assertWrites(t *testing.T, api *fakeAPI, want ...string) {
	t.Helper()
	api.mu.Lock()
	got := api.writes
	api.mu.Unlock()
	if !slices.Equal(got, want) {
		t.Errorf("writes mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestGetRecords(t *testing.T) {
	p, _ := newTestProvider(t,
		rrset{Name: "example.com.", Type: "SOA", TTL: 3600, Records: []record{
			{Content: "ns1.example.net. hostmaster.example.net. 1 10800 3600 604800 3600"},
		}},
		rrset{Name: "example.com.", Type: "A", TTL: 900, Records: []record{
			{Content: "192.0.2.1"}, {Content: "192.0.2.2", Disabled: true},
		}},
		rrset{Name: "www.example.com.", Type: "CNAME", TTL: 3600, Records: []record{{Content: "example.com."}}},
		rrset{Name: "example.com.", Type: "MX", TTL: 3600, Records: []record{{Content: "10 mail.example.com."}}},
		rrset{Name: "_acme-challenge.example.com.", Type: "TXT", TTL: 600, Records: []record{
			{Content: `"abc" "def"`}, {Content: `"say \"hi\""`},
		}},
	)

	got, err := p.GetRecords(context.Background(), testZone)
	if err != nil {
		t.Fatal(err)
	}
	assertRRs(t, got,
		libdns.RR{Name: "@", Type: "SOA", TTL: time.Hour, Data: "ns1.example.net. hostmaster.example.net. 1 10800 3600 604800 3600"},
		libdns.RR{Name: "@", Type: "A", TTL: 15 * time.Minute, Data: "192.0.2.1"},
		libdns.RR{Name: "www", Type: "CNAME", TTL: time.Hour, Data: "example.com."},
		libdns.RR{Name: "@", Type: "MX", TTL: time.Hour, Data: "10 mail.example.com."},
		libdns.RR{Name: "_acme-challenge", Type: "TXT", TTL: 10 * time.Minute, Data: "abcdef"},
		libdns.RR{Name: "_acme-challenge", Type: "TXT", TTL: 10 * time.Minute, Data: `say "hi"`},
	)

	// Records must be returned as RR-type-specific structs.
	for _, r := range got {
		switch r.RR().Type {
		case "A":
			if _, ok := r.(libdns.Address); !ok {
				t.Errorf("A record returned as %T", r)
			}
		case "TXT":
			if _, ok := r.(libdns.TXT); !ok {
				t.Errorf("TXT record returned as %T", r)
			}
		}
	}
}

func TestAppendRecords(t *testing.T) {
	ctx := context.Background()

	t.Run("new record set", func(t *testing.T) {
		p, api := newTestProvider(t)
		got, err := p.AppendRecords(ctx, testZone, []libdns.Record{
			libdns.TXT{Name: "_acme-challenge", TTL: 2 * time.Minute, Text: "token1"},
			libdns.TXT{Name: "_acme-challenge", Text: "token2"},
		})
		if err != nil {
			t.Fatal(err)
		}
		// The TTL is raised to the minimum accepted by the API.
		assertRRs(t, got,
			libdns.RR{Name: "_acme-challenge", Type: "TXT", TTL: 10 * time.Minute, Data: "token1"},
			libdns.RR{Name: "_acme-challenge", Type: "TXT", TTL: 10 * time.Minute, Data: "token2"},
		)
		assertWrites(t, api, "POST /dns/orders/42/records/txt")
		set, _ := api.lookup("_acme-challenge.example.com.", "TXT")
		if want := []record{{Content: `"token1"`}, {Content: `"token2"`}}; !slices.Equal(set.Records, want) {
			t.Errorf("records = %+v, want %+v", set.Records, want)
		}
	})

	t.Run("existing record set", func(t *testing.T) {
		existing := txtSet("_acme-challenge.example.com.", 600, "old")
		existing.Records = append(existing.Records, record{Content: `"off"`, Disabled: true})
		p, api := newTestProvider(t, existing)

		got, err := p.AppendRecords(ctx, testZone, []libdns.Record{
			libdns.TXT{Name: "_acme-challenge", TTL: time.Minute, Text: "new"},
		})
		if err != nil {
			t.Fatal(err)
		}
		// The TTL of the existing record set is kept.
		assertRRs(t, got, libdns.RR{Name: "_acme-challenge", Type: "TXT", TTL: 10 * time.Minute, Data: "new"})
		assertWrites(t, api, "PATCH /dns/orders/42/records/txt/_acme-challenge.example.com.")

		set, _ := api.lookup("_acme-challenge.example.com.", "TXT")
		want := []record{{Content: `"old"`}, {Content: `"off"`, Disabled: true}, {Content: `"new"`}}
		if !slices.Equal(set.Records, want) || set.TTL != 600 {
			t.Errorf("set = %+v, want records %+v with TTL 600", set, want)
		}
	})

	t.Run("existing record", func(t *testing.T) {
		p, api := newTestProvider(t, rrset{Name: "example.com.", Type: "AAAA", TTL: 900, Records: []record{
			{Content: "2001:0db8:0000:0000:0000:0000:0000:0001"},
		}})
		got, err := p.AppendRecords(ctx, testZone, []libdns.Record{
			libdns.Address{Name: "@", IP: netip.MustParseAddr("2001:db8::1")},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("got %v, want no records", got)
		}
		assertWrites(t, api)
	})

	t.Run("disabled record", func(t *testing.T) {
		p, api := newTestProvider(t, rrset{Name: "example.com.", Type: "A", TTL: 900, Records: []record{
			{Content: "192.0.2.1", Disabled: true},
		}})
		got, err := p.AppendRecords(ctx, testZone, []libdns.Record{
			libdns.Address{Name: "@", IP: netip.MustParseAddr("192.0.2.1")},
		})
		if err != nil {
			t.Fatal(err)
		}
		assertRRs(t, got, libdns.RR{Name: "@", Type: "A", TTL: 15 * time.Minute, Data: "192.0.2.1"})
		set, _ := api.lookup("example.com.", "A")
		if want := []record{{Content: "192.0.2.1"}}; !slices.Equal(set.Records, want) {
			t.Errorf("records = %+v, want %+v", set.Records, want)
		}
	})

	t.Run("invalid data", func(t *testing.T) {
		p, api := newTestProvider(t)
		_, err := p.AppendRecords(ctx, testZone, []libdns.Record{
			libdns.RR{Name: "a", Type: "A", Data: "not an address"},
		})
		if err == nil || !strings.Contains(err.Error(), "invalid A record") {
			t.Errorf("err = %v, want invalid A record", err)
		}
		if api.tokens != 0 {
			t.Errorf("API was called for invalid input")
		}
	})

	t.Run("unsupported type", func(t *testing.T) {
		p, api := newTestProvider(t)
		_, err := p.AppendRecords(ctx, testZone, []libdns.Record{
			libdns.TXT{Name: "a", Text: "ok"},
			libdns.RR{Name: "b", Type: "HTTPS", Data: `1 . alpn="h2"`},
		})
		if err == nil || !strings.Contains(err.Error(), "unsupported record type") {
			t.Errorf("err = %v, want unsupported record type", err)
		}
		if api.tokens != 0 {
			t.Errorf("API was called for invalid input")
		}
	})
}

func TestSetRecords(t *testing.T) {
	ctx := context.Background()

	// Example 1 from the libdns documentation.
	t.Run("replace record set", func(t *testing.T) {
		p, api := newTestProvider(t,
			rrset{Name: "example.com.", Type: "A", TTL: 3600, Records: []record{{Content: "192.0.2.1"}, {Content: "192.0.2.2"}}},
			txtSet("example.com.", 3600, "hello world"),
		)
		got, err := p.SetRecords(ctx, testZone, []libdns.Record{
			libdns.Address{Name: "@", TTL: time.Hour, IP: netip.MustParseAddr("192.0.2.3")},
		})
		if err != nil {
			t.Fatal(err)
		}
		assertRRs(t, got, libdns.RR{Name: "@", Type: "A", TTL: time.Hour, Data: "192.0.2.3"})
		assertWrites(t, api, "PATCH /dns/orders/42/records/a/example.com.")

		all, err := p.GetRecords(ctx, testZone)
		if err != nil {
			t.Fatal(err)
		}
		assertRRs(t, all,
			libdns.RR{Name: "@", Type: "A", TTL: time.Hour, Data: "192.0.2.3"},
			libdns.RR{Name: "@", Type: "TXT", TTL: time.Hour, Data: "hello world"},
		)
	})

	// Example 2 from the libdns documentation.
	t.Run("create and keep other sets", func(t *testing.T) {
		aaaa := func(name string, ips ...string) rrset {
			set := rrset{Name: name, Type: "AAAA", TTL: 3600}
			for _, ip := range ips {
				set.Records = append(set.Records, record{Content: ip})
			}
			return set
		}
		p, api := newTestProvider(t,
			aaaa("alpha.example.com.", "2001:db8::1", "2001:db8::2"),
			aaaa("beta.example.com.", "2001:db8::3", "2001:db8::4"),
		)
		_, err := p.SetRecords(ctx, testZone, []libdns.Record{
			libdns.Address{Name: "alpha", TTL: time.Hour, IP: netip.MustParseAddr("2001:db8::1")},
			libdns.Address{Name: "alpha", TTL: time.Hour, IP: netip.MustParseAddr("2001:db8::2")},
			libdns.Address{Name: "alpha", TTL: time.Hour, IP: netip.MustParseAddr("2001:db8::5")},
			libdns.TXT{Name: "gamma", TTL: time.Hour, Text: "new"},
		})
		if err != nil {
			t.Fatal(err)
		}
		assertWrites(t, api,
			"PATCH /dns/orders/42/records/aaaa/alpha.example.com.",
			"POST /dns/orders/42/records/txt",
		)
		all, err := p.GetRecords(ctx, testZone)
		if err != nil {
			t.Fatal(err)
		}
		assertRRs(t, all,
			libdns.RR{Name: "alpha", Type: "AAAA", TTL: time.Hour, Data: "2001:db8::1"},
			libdns.RR{Name: "alpha", Type: "AAAA", TTL: time.Hour, Data: "2001:db8::2"},
			libdns.RR{Name: "alpha", Type: "AAAA", TTL: time.Hour, Data: "2001:db8::5"},
			libdns.RR{Name: "beta", Type: "AAAA", TTL: time.Hour, Data: "2001:db8::3"},
			libdns.RR{Name: "beta", Type: "AAAA", TTL: time.Hour, Data: "2001:db8::4"},
			libdns.RR{Name: "gamma", Type: "TXT", TTL: time.Hour, Data: "new"},
		)
	})
}

func TestDeleteRecords(t *testing.T) {
	ctx := context.Background()
	seed := func() []rrset {
		return []rrset{
			txtSet("_acme-challenge.example.com.", 600, "token1", "token2"),
			{Name: "_acme-challenge.example.com.", Type: "CNAME", TTL: 600, Records: []record{{Content: "x.example.com."}}},
			{Name: "www.example.com.", Type: "A", TTL: 900, Records: []record{{Content: "192.0.2.1"}}},
		}
	}

	tests := []struct {
		name       string
		input      []libdns.Record
		want       []libdns.RR
		wantWrites []string
	}{
		{
			name:  "single value",
			input: []libdns.Record{libdns.TXT{Name: "_acme-challenge", Text: "token1"}},
			want:  []libdns.RR{{Name: "_acme-challenge", Type: "TXT", TTL: 10 * time.Minute, Data: "token1"}},
			wantWrites: []string{
				"PATCH /dns/orders/42/records/txt/_acme-challenge.example.com.",
			},
		},
		{
			name: "last values",
			input: []libdns.Record{
				libdns.TXT{Name: "_acme-challenge", Text: "token1"},
				libdns.TXT{Name: "_acme-challenge", TTL: 10 * time.Minute, Text: "token2"},
			},
			want: []libdns.RR{
				{Name: "_acme-challenge", Type: "TXT", TTL: 10 * time.Minute, Data: "token1"},
				{Name: "_acme-challenge", Type: "TXT", TTL: 10 * time.Minute, Data: "token2"},
			},
			wantWrites: []string{
				"DELETE /dns/orders/42/records/txt/_acme-challenge.example.com.",
			},
		},
		{
			name:  "TTL below the minimum",
			input: []libdns.Record{libdns.TXT{Name: "_acme-challenge", TTL: time.Minute, Text: "token1"}},
			want:  []libdns.RR{{Name: "_acme-challenge", Type: "TXT", TTL: 10 * time.Minute, Data: "token1"}},
			wantWrites: []string{
				"PATCH /dns/orders/42/records/txt/_acme-challenge.example.com.",
			},
		},
		{
			name:  "any type and value",
			input: []libdns.Record{libdns.RR{Name: "_acme-challenge"}},
			want: []libdns.RR{
				{Name: "_acme-challenge", Type: "TXT", TTL: 10 * time.Minute, Data: "token1"},
				{Name: "_acme-challenge", Type: "TXT", TTL: 10 * time.Minute, Data: "token2"},
				{Name: "_acme-challenge", Type: "CNAME", TTL: 10 * time.Minute, Data: "x.example.com."},
			},
			wantWrites: []string{
				"DELETE /dns/orders/42/records/txt/_acme-challenge.example.com.",
				"DELETE /dns/orders/42/records/cname/_acme-challenge.example.com.",
			},
		},
		{
			name:  "fully qualified name",
			input: []libdns.Record{libdns.RR{Name: "www.example.com.", Type: "A"}},
			want:  []libdns.RR{{Name: "www", Type: "A", TTL: 15 * time.Minute, Data: "192.0.2.1"}},
			wantWrites: []string{
				"DELETE /dns/orders/42/records/a/www.example.com.",
			},
		},
		{
			name: "no match",
			input: []libdns.Record{
				libdns.TXT{Name: "_acme-challenge", Text: "token3"},
				libdns.TXT{Name: "_acme-challenge", TTL: time.Hour, Text: "token1"},
				libdns.TXT{Name: "missing", Text: "token1"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, api := newTestProvider(t, seed()...)
			got, err := p.DeleteRecords(ctx, testZone, tt.input)
			if err != nil {
				t.Fatal(err)
			}
			assertRRs(t, got, tt.want...)
			assertWrites(t, api, tt.wantWrites...)
		})
	}
}

func TestListZones(t *testing.T) {
	p, _ := newTestProvider(t)
	zones, err := p.ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []libdns.Zone{{Name: "example.com."}, {Name: "example.net."}}
	if !slices.Equal(zones, want) {
		t.Errorf("zones = %v, want %v", zones, want)
	}
}

func TestEmptyName(t *testing.T) {
	ctx := context.Background()
	p, api := newTestProvider(t, rrset{Name: "example.com.", Type: "A", TTL: 900, Records: []record{{Content: "192.0.2.1"}}})
	if _, err := p.DeleteRecords(ctx, testZone, []libdns.Record{libdns.RR{}}); !errors.Is(err, errNoName) {
		t.Errorf("DeleteRecords: err = %v, want %v", err, errNoName)
	}
	if _, err := p.AppendRecords(ctx, testZone, []libdns.Record{libdns.TXT{Text: "x"}}); !errors.Is(err, errNoName) {
		t.Errorf("AppendRecords: err = %v, want %v", err, errNoName)
	}
	if api.tokens != 0 {
		t.Errorf("API was called for invalid input")
	}
}

func TestOrderCache(t *testing.T) {
	ctx := context.Background()
	p, api := newTestProvider(t)

	for range 2 {
		if _, err := p.GetRecords(ctx, testZone); err != nil {
			t.Fatal(err)
		}
	}
	if api.lists != 1 {
		t.Errorf("orders listed %d times, want 1", api.lists)
	}

	p.ordersExpiry = time.Now()
	if _, err := p.GetRecords(ctx, testZone); err != nil {
		t.Fatal(err)
	}
	if api.lists != 2 {
		t.Errorf("orders listed %d times after expiry, want 2", api.lists)
	}
}

func TestUnknownZone(t *testing.T) {
	p, _ := newTestProvider(t)
	_, err := p.GetRecords(context.Background(), "unknown.example.")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("err = %v, want zone not found", err)
	}
}

func TestZoneNameNormalization(t *testing.T) {
	p, api := newTestProvider(t)
	_, err := p.AppendRecords(context.Background(), "Example.COM", []libdns.Record{
		libdns.TXT{Name: "test", Text: "x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := api.lookup("test.example.com.", "TXT"); !ok {
		t.Errorf("record not created under normalized name")
	}
}

func TestIDNZone(t *testing.T) {
	ctx := context.Background()
	p, api := newTestProvider(t, txtSet("_acme-challenge.пример.тест.", 600, "token1"))
	api.domain = "пример.тест"
	const zone = "xn--e1afmkfd.xn--e1aybc."

	got, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}
	assertRRs(t, got, libdns.RR{Name: "_acme-challenge", Type: "TXT", TTL: 10 * time.Minute, Data: "token1"})

	_, err = p.AppendRecords(ctx, zone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "token2"},
		libdns.TXT{Name: "_acme-challenge.xn--d1acufc", Text: "token3"},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertWrites(t, api,
		"PATCH /dns/orders/42/records/txt/_acme-challenge.пример.тест.",
		"POST /dns/orders/42/records/txt",
	)
	if _, ok := api.lookup("_acme-challenge.домен.пример.тест.", "TXT"); !ok {
		t.Errorf("record not created with a Unicode name")
	}

	zones, err := p.ListZones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(zones, libdns.Zone{Name: zone}) {
		t.Errorf("zones = %v, want %s among them", zones, zone)
	}
}

func TestTokenRenewal(t *testing.T) {
	ctx := context.Background()
	p, api := newTestProvider(t)

	if _, err := p.GetRecords(ctx, testZone); err != nil {
		t.Fatal(err)
	}

	// Revoke the token on the server side.
	api.mu.Lock()
	api.token = "revoked"
	api.mu.Unlock()

	if _, err := p.GetRecords(ctx, testZone); err != nil {
		t.Fatal(err)
	}
	if api.tokens != 2 {
		t.Errorf("tokens issued = %d, want 2", api.tokens)
	}
}

func TestInvalidCredentials(t *testing.T) {
	p, _ := newTestProvider(t)
	p.SecretKey = "wrong"
	_, err := p.GetRecords(context.Background(), testZone)
	if err == nil || !strings.Contains(err.Error(), "access token") {
		t.Errorf("err = %v, want access token error", err)
	}
}

func TestRetry(t *testing.T) {
	ctx := context.Background()

	t.Run("idempotent request", func(t *testing.T) {
		p, api := newTestProvider(t)
		api.failures = []int{http.StatusServiceUnavailable, http.StatusBadGateway}
		if _, err := p.GetRecords(ctx, testZone); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("non-idempotent request", func(t *testing.T) {
		p, api := newTestProvider(t)
		api.failures = []int{http.StatusServiceUnavailable}
		api.failOn = http.MethodPost
		_, err := p.AppendRecords(ctx, testZone, []libdns.Record{libdns.TXT{Name: "a", Text: "b"}})
		var apiErr *apiError
		if !errors.As(err, &apiErr) || apiErr.statusCode != http.StatusServiceUnavailable {
			t.Errorf("err = %v, want HTTP 503", err)
		}
	})

	t.Run("client error", func(t *testing.T) {
		p, api := newTestProvider(t)
		api.failures = []int{http.StatusBadRequest}
		_, err := p.GetRecords(ctx, testZone)
		var apiErr *apiError
		if !errors.As(err, &apiErr) || apiErr.statusCode != http.StatusBadRequest {
			t.Fatalf("err = %v, want HTTP 400", err)
		}
		if want := "bad_request (injected failure)"; !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want it to contain %q", err, want)
		}
	})
}

func TestContextCancellation(t *testing.T) {
	p, _ := newTestProvider(t)
	unlock, err := p.lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = p.AppendRecords(ctx, testZone, []libdns.Record{libdns.TXT{Name: "a", Text: "b"}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want %v", err, context.DeadlineExceeded)
	}
}

func TestConcurrentAppend(t *testing.T) {
	ctx := context.Background()
	p, api := newTestProvider(t)

	const n = 10
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.AppendRecords(ctx, testZone, []libdns.Record{
				libdns.TXT{Name: "_acme-challenge", Text: fmt.Sprintf("token%d", i)},
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	set, _ := api.lookup("_acme-challenge.example.com.", "TXT")
	if len(set.Records) != n {
		t.Errorf("got %d records, want %d", len(set.Records), n)
	}
}

func TestTXTQuoting(t *testing.T) {
	long := strings.Repeat("a", 300)
	tests := []struct {
		text    string
		content string
	}{
		{"", `""`},
		{"token", `"token"`},
		{`say "hi"`, `"say \"hi\""`},
		{`back\slash`, `"back\\slash"`},
		{long, `"` + long[:255] + `" "` + long[255:] + `"`},
		// Multi-byte characters are not split between chunks.
		{strings.Repeat("a", 254) + "ж", `"` + strings.Repeat("a", 254) + `" "ж"`},
		// Invalid UTF-8 is split at the maximum length.
		{strings.Repeat("\x80", 300), `"` + strings.Repeat("\x80", 255) + `" "` + strings.Repeat("\x80", 45) + `"`},
	}
	for _, tt := range tests {
		if got := quoteTXT(tt.text); got != tt.content {
			t.Errorf("quoteTXT(%q) = %q, want %q", tt.text, got, tt.content)
		}
		got, err := unquoteTXT(tt.content)
		if err != nil || got != tt.text {
			t.Errorf("unquoteTXT(%q) = %q, %v, want %q", tt.content, got, err, tt.text)
		}
	}
}

func TestUnquoteTXT(t *testing.T) {
	tests := []struct {
		content string
		want    string
		wantErr bool
	}{
		{content: "unquoted", want: "unquoted"},
		{content: `"a"  "b"`, want: "ab"},
		{content: `"\;"`, want: ";"},
		{content: `"del: \127, ctrl: \001"`, want: "del: \x7f, ctrl: \x01"},
		{content: `"\12"`, want: "12"},
		{content: `"\256"`, wantErr: true},
		{content: `"open`, wantErr: true},
		{content: `"a" b`, wantErr: true},
	}
	for _, tt := range tests {
		got, err := unquoteTXT(tt.content)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("unquoteTXT(%q) = %q, %v, want %q (error: %v)", tt.content, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestTTLSeconds(t *testing.T) {
	tests := map[time.Duration]int{
		0:                                     600,
		time.Second:                           600,
		5 * time.Minute:                       600,
		20*time.Minute + 500*time.Millisecond: 1200,
		30 * 24 * time.Hour:                   604800,
	}
	for ttl, want := range tests {
		if got := ttlSeconds(ttl); got != want {
			t.Errorf("ttlSeconds(%v) = %d, want %d", ttl, got, want)
		}
	}
}
