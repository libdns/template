package enum

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestTXT(t *testing.T) {
	for _, tc := range []struct{ text, quoted string }{
		{"hello world", `"hello world"`},
		{`a"b\c`, `"a\"b\\c"`},
		{"ä", `"\195\164"`},
	} {
		if got := quoteTXT(tc.text); got != tc.quoted {
			t.Errorf("quoteTXT(%q) = %s, want %s", tc.text, got, tc.quoted)
		}

		if got := unquoteTXT(tc.quoted); got != tc.text {
			t.Errorf("unquoteTXT(%s) = %q, want %q", tc.quoted, got, tc.text)
		}
	}

	if got := unquoteTXT(`"abc" "def"`); got != "abcdef" {
		t.Errorf("unquoteTXT of split strings = %q", got)
	}
}

func TestSetRecordsCreatesMissingSet(t *testing.T) {
	var calls []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)

		if r.Header.Get("Authorization") != "Bearer key" {
			t.Errorf("unexpected Authorization header %q", r.Header.Get("Authorization"))
		}

		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)

		switch r.URL.Path {
		case "/enum.api.v1.DnsService/GetZoneByName":
			if req["name"] != "example.com" || req["projectId"] != "proj" {
				t.Errorf("unexpected zone request %v", req)
			}

			_, _ = w.Write([]byte(`{"zone":{"id":"zone","name":"example.com"}}`))
		case "/enum.api.v1.DnsService/UpdateRecordSet":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":"not_found","message":"record set not found"}`))
		case "/enum.api.v1.DnsService/CreateRecordSet":
			if req["name"] != "_acme-challenge.example.com" || req["ttl"] != float64(120) {
				t.Errorf("unexpected create request %v", req)
			}

			_, _ = w.Write([]byte(`{"recordSet":{"name":"_acme-challenge.example.com.","type":"TXT","ttl":120,"records":[{"content":"\"token\""}]}}`))
		default:
			t.Errorf("unexpected call %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	p := &Provider{APIKey: "key", ProjectID: "proj", baseURL: srv.URL}

	records, err := p.SetRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", TTL: 120 * time.Second, Text: "token"},
	})
	if err != nil {
		t.Fatal(err)
	}

	want := libdns.TXT{Name: "_acme-challenge", TTL: 120 * time.Second, Text: "token"}
	if len(records) != 1 || records[0].RR() != want.RR() {
		t.Errorf("got %+v, want %+v", records, want)
	}

	if len(calls) != 3 {
		t.Errorf("got calls %v", calls)
	}
}
