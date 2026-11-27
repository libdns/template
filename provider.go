// Package nameocean implements the libdns interfaces for NameOcean DNS
// (https://nameocean.net/dns/), through NameOcean's API v1
// (https://nameocean.net/developers/api/).
package nameocean

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/libdns/libdns"
)

// Provider manages records in NameOcean DNS zones. The zero value works when
// NAMEOCEAN_API_KEY is set in the environment.
type Provider struct {
	// APIKey is a NameOcean API key with the dns:read and dns:write scopes
	// (Dashboard → API). It may be limited to the zones it should touch.
	// Defaults to the NAMEOCEAN_API_KEY environment variable.
	APIKey string `json:"api_key,omitempty"`

	// BaseURL overrides the API address. Default: https://nameocean.net/api/v1
	BaseURL string `json:"base_url,omitempty"`

	// HTTPClient is used for API calls. Default: a client with a 30 second timeout.
	HTTPClient *http.Client `json:"-"`

	// mu serializes the read-modify-write in SetRecords and DeleteRecords
	// within this process.
	mu sync.Mutex
}

// GetRecords lists all the records in the zone. NameOcean's HTTP redirect
// records are not DNS records and are left out.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	recs, err := p.listRecords(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]libdns.Record, 0, len(recs))
	for _, r := range recs {
		if r.Type == "REDIRECT" {
			continue
		}
		rec, err := toLibdns(r, zone)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

// AppendRecords adds records to the zone and returns them as created. It never
// changes existing records.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var created []libdns.Record
	for _, rec := range records {
		in, err := fromLibdns(rec, zone)
		if err != nil {
			return created, err
		}
		got, err := p.createRecord(ctx, zone, in)
		if err != nil {
			return created, fmt.Errorf("adding %s %s: %w", in.Type, rec.RR().Name, err)
		}
		out, err := toLibdns(got, zone)
		if err != nil {
			return created, err
		}
		created = append(created, out)
	}
	return created, nil
}

// SetRecords makes the input records the only records of their (name, type)
// pairs in the zone. Records that already match are kept (a different TTL is
// changed in place); other records of the same (name, type) are changed in
// place to the remaining input records; what is still missing is added and
// what is left over is deleted. Other records are not touched.
//
// It is not atomic: NameOcean's per-record API has no batch call, so an error
// part-way can leave some changes made. Deletions come last, so a name keeps
// answering during the change.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	existing, err := p.listRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	type key struct{ name, typ string }
	want := map[key][]apiRecord{}
	var order []apiRecord
	for _, rec := range records {
		in, err := fromLibdns(rec, zone)
		if err != nil {
			return nil, err
		}
		k := key{in.Hostname, in.Type}
		want[k] = append(want[k], in)
		order = append(order, in)
	}

	// First each wanted record takes an existing one with the same data
	// (ignoring TTL), at most once. NameOcean keeps one record per (name, data)
	// and one CNAME per name, so adding before deleting would fail there.
	used := map[int64]bool{}
	match := make([]*apiRecord, len(order))
	for i, in := range order {
		for j := range existing {
			ex := &existing[j]
			if !used[ex.ID] && sameRecord(*ex, in, false) {
				used[ex.ID] = true
				match[i] = ex
				break
			}
		}
	}
	// Then the rest take a leftover record of the same (name, type), which is
	// changed in place; only what is left after that is added or deleted.
	reuse := make([]*apiRecord, len(order))
	for i, in := range order {
		if match[i] != nil {
			continue
		}
		for j := range existing {
			ex := &existing[j]
			if !used[ex.ID] && strings.EqualFold(ex.Hostname, in.Hostname) && ex.Type == in.Type {
				used[ex.ID] = true
				reuse[i] = ex
				break
			}
		}
	}
	var drop []apiRecord
	for _, ex := range existing {
		if _, ok := want[key{ex.Hostname, ex.Type}]; ok && !used[ex.ID] {
			drop = append(drop, ex)
		}
	}

	var result []libdns.Record
	for i, in := range order {
		got := in
		switch {
		case match[i] != nil && match[i].TTL == in.TTL:
			got = *match[i]
		case match[i] != nil:
			if got, err = p.updateRecord(ctx, zone, *match[i], in); err != nil {
				return result, fmt.Errorf("changing the TTL of %s %s: %w", in.Type, in.Hostname, err)
			}
		case reuse[i] != nil:
			if got, err = p.updateRecord(ctx, zone, *reuse[i], in); err != nil {
				return result, fmt.Errorf("changing %s %s: %w", in.Type, in.Hostname, err)
			}
		default:
			if got, err = p.createRecord(ctx, zone, in); err != nil {
				return result, fmt.Errorf("adding %s %s: %w", in.Type, in.Hostname, err)
			}
		}
		out, err := toLibdns(got, zone)
		if err != nil {
			return result, err
		}
		result = append(result, out)
	}
	for _, d := range drop {
		if err := p.deleteRecord(ctx, zone, d); err != nil {
			return result, fmt.Errorf("deleting %s %s: %w", d.Type, d.Hostname, err)
		}
	}
	return result, nil
}

// DeleteRecords deletes the records of the zone that match the input. The name
// is required; an empty type, a zero TTL or empty data match any value. Records
// that are not in the zone are ignored. It returns the records it deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	existing, err := p.listRecords(ctx, zone)
	if err != nil {
		return nil, err
	}
	var deleted []libdns.Record
	done := map[string]bool{}
	for _, rec := range records {
		rr := rec.RR()
		if rr.Name == "" {
			return deleted, fmt.Errorf("nameocean: DeleteRecords needs a record name")
		}
		var want apiRecord
		if rr.Data != "" {
			if want, err = fromLibdns(rec, zone); err != nil {
				return deleted, err
			}
		}
		name := strings.ToLower(libdns.RelativeName(libdns.AbsoluteName(rr.Name, zone), zone))
		for _, ex := range existing {
			id := ex.Type + "/" + fmt.Sprint(ex.ID)
			if done[id] || ex.Type == "REDIRECT" || strings.ToLower(ex.Hostname) != name {
				continue
			}
			if rr.Type != "" && !strings.EqualFold(rr.Type, ex.Type) {
				continue
			}
			if rr.TTL != 0 && ttlString(rr.TTL) != ex.TTL {
				continue
			}
			if rr.Data != "" && !sameRecord(ex, want, false) {
				continue
			}
			if err := p.deleteRecord(ctx, zone, ex); err != nil {
				return deleted, fmt.Errorf("deleting %s %s: %w", ex.Type, ex.Hostname, err)
			}
			done[id] = true
			out, err := toLibdns(ex, zone)
			if err != nil {
				return deleted, err
			}
			deleted = append(deleted, out)
		}
	}
	return deleted, nil
}

// ListZones returns the zones the API key can see.
func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	names, err := p.listZones(ctx)
	if err != nil {
		return nil, err
	}
	zones := make([]libdns.Zone, 0, len(names))
	for _, n := range names {
		zones = append(zones, libdns.Zone{Name: n + "."})
	}
	return zones, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ libdns.ZoneLister     = (*Provider)(nil)
)
