package mittwald

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// fakeAPI is the part of the mStudio API the provider uses, for one project.
type fakeAPI struct {
	mu     sync.Mutex
	zones  map[string]map[string]any // zone ID -> zone as the API returns it
	nextID int
	event  int
	url    string // where the fake listens, for Provider.apiURL
}

func unsetSets() map[string]any {
	return map[string]any{"combinedARecords": map[string]any{}, "cname": map[string]any{}, "mx": map[string]any{},
		"txt": map[string]any{}, "srv": map[string]any{}, "caa": map[string]any{}}
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{zones: map[string]map[string]any{}}
	root := unsetSets()
	root["combinedARecords"] = map[string]any{"managedBy": map[string]any{"ingressId": "00000000-0000-0000-0000-000000000001"}}
	root["mx"] = map[string]any{"managed": true}
	f.zones["root"] = map[string]any{"id": "root", "domain": "example.com", "recordSet": root}
	f.zones["other"] = map[string]any{"id": "other", "domain": "other.example", "recordSet": unsetSets()}

	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	f.url = srv.URL + "/v2"
	return f
}

var slotKey = map[string]string{"a": "combinedARecords", "cname": "cname", "mx": "mx", "txt": "txt", "srv": "srv", "caa": "caa"}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v2")
	write := func(code int, v any) {
		if r.Method != http.MethodGet {
			f.event++
			w.Header().Set("ETag", fmt.Sprint(f.event))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if v != nil {
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && path == "/projects":
		write(200, []map[string]any{{"id": "p1"}})
	case r.Method == http.MethodGet && path == "/projects/p1/dns-zones":
		var list []map[string]any
		for _, id := range slices.Sorted(func(yield func(string) bool) {
			for id := range f.zones {
				if !yield(id) {
					return
				}
			}
		}) {
			list = append(list, f.zones[id])
		}
		write(200, list)
	case r.Method == http.MethodPost && path == "/dns-zones":
		var body struct{ Name, ParentZoneId string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		parent := f.zones[body.ParentZoneId]
		f.nextID++
		id := fmt.Sprintf("z%d", f.nextID)
		f.zones[id] = map[string]any{"id": id, "domain": body.Name + "." + parent["domain"].(string), "recordSet": unsetSets()}
		write(201, map[string]string{"id": id})
	case r.Method == http.MethodPut && len(parts) == 4 && parts[0] == "dns-zones" && parts[2] == "record-sets":
		z := f.zones[parts[1]]
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		sets := z["recordSet"].(map[string]any)
		if parts[3] == "cname" && len(body) > 0 {
			for k, v := range sets {
				if k != "cname" && len(v.(map[string]any)) > 0 {
					write(412, map[string]string{"type": "VError", "message": "zone contains active records - unable to set CNAME"})
					return
				}
			}
		}
		sets[slotKey[parts[3]]] = body
		write(204, nil)
	default:
		write(404, map[string]string{"message": "not found: " + r.Method + " " + path})
	}
}

func (f *fakeAPI) zoneNamed(domain string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, z := range f.zones {
		if z["domain"] == domain {
			return z
		}
	}
	return nil
}

func (f *fakeAPI) set(domain, key string) map[string]any {
	z := f.zoneNamed(domain)
	if z == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return z["recordSet"].(map[string]any)[key].(map[string]any)
}

func TestAppendAndDeleteTXTCreatesAndKeepsTheZone(t *testing.T) {
	f := newFakeAPI(t)
	p := &Provider{APIToken: "t", apiURL: f.url}
	ctx := context.Background()

	for _, text := range []string{"one", "two"} {
		added, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{libdns.TXT{Name: "_acme-challenge", Text: text}})
		if err != nil || len(added) != 1 {
			t.Fatalf("append %q: %v, %v", text, added, err)
		}
	}
	txt := f.set("_acme-challenge.example.com", "txt")
	if got := fmt.Sprint(txt["entries"]); got != "[one two]" {
		t.Fatalf("entries = %s", got)
	}
	if auto := txt["settings"].(map[string]any)["ttl"].(map[string]any)["auto"]; auto != true {
		t.Errorf("TTL 0 should be auto, got %v", txt["settings"])
	}

	deleted, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.TXT{Name: "_acme-challenge", Text: "one"}})
	if err != nil || len(deleted) != 1 {
		t.Fatalf("delete: %v, %v", deleted, err)
	}
	if got := fmt.Sprint(f.set("_acme-challenge.example.com", "txt")["entries"]); got != "[two]" {
		t.Fatalf("entries = %s", got)
	}
	if _, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.TXT{Name: "_acme-challenge", Text: "two"}}); err != nil {
		t.Fatal(err)
	}
	if s := f.set("_acme-challenge.example.com", "txt"); len(s) != 0 {
		t.Errorf("want the set unset, got %v", s)
	}
	if f.zoneNamed("_acme-challenge.example.com") == nil {
		t.Error("the zone of the name stays")
	}
}

func TestSetAKeepsAAAA(t *testing.T) {
	f := newFakeAPI(t)
	p := &Provider{APIToken: "t", apiURL: f.url}
	ctx := context.Background()
	if _, err := p.SetRecords(ctx, "example.com.", []libdns.Record{
		libdns.Address{Name: "www", TTL: 300 * time.Second, IP: netip.MustParseAddr("2001:db8::1")},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.SetRecords(ctx, "example.com.", []libdns.Record{
		libdns.Address{Name: "www", TTL: 300 * time.Second, IP: netip.MustParseAddr("192.0.2.1")},
	}); err != nil {
		t.Fatal(err)
	}
	a := f.set("www.example.com", "combinedARecords")
	if fmt.Sprint(a["a"]) != "[192.0.2.1]" || fmt.Sprint(a["aaaa"]) != "[2001:db8::1]" {
		t.Errorf("got %v", a)
	}
}

func TestGetRecordsSkipsManagedAndUnsetSets(t *testing.T) {
	f := newFakeAPI(t)
	p := &Provider{APIToken: "t", apiURL: f.url}
	ctx := context.Background()
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{
		libdns.TXT{Name: "@", Text: "v=spf1 -all"},
		libdns.CNAME{Name: "shop", Target: "shops.example.net."},
	}); err != nil {
		t.Fatal(err)
	}
	recs, err := p.GetRecords(ctx, "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range recs {
		rr := r.RR()
		got = append(got, rr.Name+" "+rr.Type+" "+rr.Data)
	}
	slices.Sort(got)
	if want := []string{"@ TXT v=spf1 -all", "shop CNAME shops.example.net."}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestChangesStayInTheRequestedZone(t *testing.T) {
	f := newFakeAPI(t)
	p := &Provider{APIToken: "t", apiURL: f.url}
	ctx := context.Background()
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{libdns.TXT{Name: "@", Text: "apex"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.DeleteRecords(ctx, "sub.example.com.", []libdns.Record{libdns.RR{Name: "example.com."}}); err == nil {
		t.Error("a name above the zone must be refused")
	}
	if len(f.set("example.com", "txt")) == 0 {
		t.Error("the apex TXT must stay")
	}
}

func TestZoneInAnySpelling(t *testing.T) {
	f := newFakeAPI(t)
	p := &Provider{APIToken: "t", apiURL: f.url}
	ctx := context.Background()
	if _, err := p.AppendRecords(ctx, "Example.COM.", []libdns.Record{libdns.TXT{Name: "www", Text: "x"}}); err != nil {
		t.Fatal(err)
	}
	recs, err := p.GetRecords(ctx, "Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].RR().Name != "www" {
		t.Errorf("want www relative to the zone, got %v", recs)
	}
}

func TestCNAMEOnANameWithOtherRecordsFails(t *testing.T) {
	f := newFakeAPI(t)
	p := &Provider{APIToken: "t", apiURL: f.url}
	ctx := context.Background()
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{libdns.TXT{Name: "x", Text: "t"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.SetRecords(ctx, "example.com.", []libdns.Record{libdns.CNAME{Name: "x", Target: "y.example.net."}}); err == nil {
		t.Error("a CNAME next to a TXT must fail")
	}
}

func TestDeleteMatchesEmptyFieldsAsWildcards(t *testing.T) {
	f := newFakeAPI(t)
	p := &Provider{APIToken: "t", apiURL: f.url}
	ctx := context.Background()
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{
		libdns.TXT{Name: "m", Text: "a"}, libdns.TXT{Name: "m", Text: "b"},
		libdns.MX{Name: "m", Preference: 10, Target: "mx.example.net."},
	}); err != nil {
		t.Fatal(err)
	}
	deleted, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "m", Type: "TXT"}})
	if err != nil || len(deleted) != 2 {
		t.Fatalf("delete all TXT: %v, %v", deleted, err)
	}
	if len(f.set("m.example.com", "txt")) != 0 || len(f.set("m.example.com", "mx")) == 0 {
		t.Error("only the TXT set is emptied")
	}
	// A target with or without trailing dot is the same.
	deleted, err = p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.MX{Name: "m", Preference: 10, Target: "MX.example.net"}})
	if err != nil || len(deleted) != 1 {
		t.Fatalf("delete MX: %v, %v", deleted, err)
	}
}

func TestDeleteByTypeWithoutData(t *testing.T) {
	f := newFakeAPI(t)
	p := &Provider{APIToken: "t", apiURL: f.url}
	ctx := context.Background()
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{
		libdns.Address{Name: "www", IP: netip.MustParseAddr("192.0.2.1")},
		libdns.Address{Name: "www", IP: netip.MustParseAddr("192.0.2.2")},
		libdns.MX{Name: "www", Preference: 10, Target: "mx.example.net."},
	}); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"A", "MX"} {
		if _, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "www", Type: typ}}); err != nil {
			t.Fatalf("delete all %s: %v", typ, err)
		}
	}
	if len(f.set("www.example.com", "combinedARecords")) != 0 || len(f.set("www.example.com", "mx")) != 0 {
		t.Error("want both sets unset")
	}
}

func TestAppendComparesExactly(t *testing.T) {
	f := newFakeAPI(t)
	p := &Provider{APIToken: "t", apiURL: f.url}
	ctx := context.Background()
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{libdns.TXT{Name: "t", Text: "a"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{libdns.TXT{Name: "t", Text: ""}}); err == nil {
		t.Error("an empty TXT is not accepted by mStudio and must not pass as a duplicate")
	}
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "t", Type: "A"}}); err == nil {
		t.Error("an A record without address cannot be appended")
	}
}

func TestRejectsWhatMStudioCannotHold(t *testing.T) {
	f := newFakeAPI(t)
	p := &Provider{APIToken: "t", apiURL: f.url}
	ctx := context.Background()
	for _, rec := range []libdns.Record{
		libdns.TXT{Name: "*", Text: "wildcard"},
		libdns.NS{Name: "sub", Target: "ns.example.net."},
		libdns.TXT{Name: "short", TTL: 30 * time.Second, Text: "ttl"},
	} {
		if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{rec}); err == nil {
			t.Errorf("%v: want an error", rec.RR())
		}
	}
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{
		libdns.TXT{Name: "two", TTL: 300 * time.Second, Text: "a"},
		libdns.TXT{Name: "two", TTL: 600 * time.Second, Text: "b"},
	}); err == nil {
		t.Error("two TTLs in one set: want an error")
	}
}

func TestConcurrentAppendsKeepEveryRecord(t *testing.T) {
	f := newFakeAPI(t)
	p := &Provider{APIToken: "t", apiURL: f.url}
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{libdns.TXT{Name: "_acme-challenge", Text: fmt.Sprint(i)}}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n := len(f.set("_acme-challenge.example.com", "txt")["entries"].([]any)); n != 8 {
		t.Errorf("want 8 entries, got %d", n)
	}
}

func TestWaitingForAnotherCallEndsWithTheContext(t *testing.T) {
	p := &Provider{APIToken: "t"}
	if err := p.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p.unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := p.GetRecords(ctx, "example.com."); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("want the deadline, got %v", err)
	}
}

func TestListZones(t *testing.T) {
	f := newFakeAPI(t)
	p := &Provider{APIToken: "t", apiURL: f.url}
	if _, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{libdns.TXT{Name: "sub", Text: "x"}}); err != nil {
		t.Fatal(err)
	}
	zones, err := p.ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, z := range zones {
		names = append(names, z.Name)
	}
	slices.Sort(names)
	if want := []string{"example.com.", "other.example."}; !slices.Equal(names, want) {
		t.Errorf("got %v, want %v", names, want)
	}
}

type fakeRunner struct {
	responses []*http.Response
	calls     int
}

func (f *fakeRunner) Do(*http.Request) (*http.Response, error) {
	resp := f.responses[min(f.calls, len(f.responses)-1)]
	f.calls++
	return resp, nil
}

func response(code int, body string, headers ...string) *http.Response {
	h := http.Header{}
	for i := 0; i+1 < len(headers); i += 2 {
		h.Set(headers[i], headers[i+1])
	}
	return &http.Response{StatusCode: code, Header: h, Body: io.NopCloser(strings.NewReader(body))}
}

func do(t *testing.T, r *apiRunner, method string) (*http.Response, error) {
	t.Helper()
	req, _ := http.NewRequest(method, "https://api.example/v2/x", strings.NewReader("{}"))
	return r.Do(req)
}

func TestRunnerRepeatsOnlyA412OfAnEventNotReached(t *testing.T) {
	inner := &fakeRunner{responses: []*http.Response{
		response(201, "", "ETag", "1"),
		response(412, `{"message":"lastEventID not reached","type":"FailedPrecondition"}`),
		response(204, ""),
		response(412, `{"message":"contains active records - unable to set CNAME","type":"VError"}`),
	}}
	r := &apiRunner{inner: inner, now: time.Now}
	for _, want := range []int{201, 204, 412} {
		resp, err := do(t, r, http.MethodPut)
		if err != nil || resp.StatusCode != want {
			t.Fatalf("want %d, got %v, %v", want, resp, err)
		}
	}
	if inner.calls != 4 {
		t.Errorf("calls=%d, want 4: the conflict is not repeated", inner.calls)
	}
}

func TestRunnerNeverRepeatsAPostAfterAServerError(t *testing.T) {
	inner := &fakeRunner{responses: []*http.Response{response(500, ""), response(201, "")}}
	r := &apiRunner{inner: inner, now: time.Now}
	if resp, _ := do(t, r, http.MethodPost); resp.StatusCode != 500 || inner.calls != 1 {
		t.Errorf("POST: status %d after %d calls", resp.StatusCode, inner.calls)
	}
}

func TestRunnerFailsInsteadOfWaitingLongForTheRateLimit(t *testing.T) {
	inner := &fakeRunner{responses: []*http.Response{response(200, "", "X-Ratelimit-Remaining", "0", "X-Ratelimit-Reset", "300")}}
	r := &apiRunner{inner: inner, now: time.Now}
	if _, err := do(t, r, http.MethodGet); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := do(t, r, http.MethodGet); !errors.Is(err, errRateLimited) {
		t.Errorf("want errRateLimited, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Error("it must not wait")
	}
}
