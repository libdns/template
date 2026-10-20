// Package hosterby implements a DNS record management client compatible with
// the libdns interfaces for [hoster.by].
//
// # Authentication
//
// The provider authenticates with an access key and a secret key, which can
// be issued in the hoster.by control panel. Short-lived access tokens are
// created from them and renewed automatically.
//
// # Record sets
//
// The API manages record sets (RRsets): all records of the same name and type
// are written together and share one TTL. Consequently:
//
//   - Appending or deleting a record rewrites its record set. This is
//     serialized within a [Provider] value, but not across clients.
//   - Each record set is written with a separate request, so a failed call
//     may leave the record sets written before the failure changed.
//   - Appending to an existing record set keeps its TTL. Within a call, the
//     first TTL given for a record set is used.
//   - TTLs are clamped to the API range of 10 minutes to 7 days, and records
//     without a TTL get 10 minutes.
//   - Disabled records are hidden from [Provider.GetRecords] and preserved
//     by Append and Delete. Appending a disabled record enables it.
//
// # Record types
//
// [Provider.GetRecords] returns all types. Only A, AAAA, ALIAS, CAA, CNAME,
// MX, NS, SRV and TXT records can be written.
//
// [hoster.by]: https://hoster.by
package hosterby

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with hoster.by.
type Provider struct {
	// AccessKey is the access key of the API service account.
	AccessKey string `json:"access_key,omitempty"`

	// SecretKey is the secret key of the API service account.
	SecretKey string `json:"secret_key,omitempty"`

	// BaseURL overrides the default API endpoint, https://serviceapi.hoster.by.
	BaseURL string `json:"base_url,omitempty"`

	// HTTPClient overrides the default HTTP client, which has a 30 second
	// timeout.
	HTTPClient *http.Client `json:"-"`

	// writeLock serializes record set updates. Unlike a mutex, a channel
	// allows waiting with a context.
	writeLock     chan struct{}
	writeLockOnce sync.Once

	authMu      sync.Mutex
	token       string
	tokenExpiry time.Time

	ordersMu     sync.Mutex
	orders       map[string]dnsOrder // keyed by normalized zone name
	ordersExpiry time.Time
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	zone = normalizeZone(zone)
	_, sets, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}

	var records []libdns.Record
	for _, set := range sets {
		for _, rec := range set.Records {
			if rec.Disabled {
				continue
			}
			r, err := parseRecord(set, rec, zone)
			if err != nil {
				return nil, fmt.Errorf("hosterby: parsing %s record %q: %w", set.Type, set.Name, err)
			}
			records = append(records, r)
		}
	}
	return records, nil
}

// AppendRecords adds records to the zone and returns the added ones. Records
// that already exist are skipped.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zone = normalizeZone(zone)
	inputs, err := prepare(zone, records)
	if err != nil {
		return nil, err
	}

	unlock, err := p.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	order, sets, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	index := indexRRsets(sets)

	var (
		dirty   []setKey
		created = make(map[setKey]bool)
		added   []libdns.Record
	)
	for _, in := range inputs {
		set, ok := index[in.key]
		if !ok {
			set = &rrset{Name: in.key.name, Type: in.key.typ, TTL: ttlSeconds(in.rr.TTL)}
			index[in.key] = set
			created[in.key] = true
		}

		i := set.find(in.rr.Data, zone)
		switch {
		case i < 0:
			set.Records = append(set.Records, record{Content: in.content})
		case set.Records[i].Disabled:
			set.Records[i].Disabled = false
		default:
			continue
		}
		if !slices.Contains(dirty, in.key) {
			dirty = append(dirty, in.key)
		}

		r, err := withTTL(in.rr, set)
		if err != nil {
			return nil, fmt.Errorf("hosterby: %w", err)
		}
		added = append(added, r)
	}

	for _, key := range dirty {
		set := *index[key]
		if created[key] {
			err = p.createRRset(ctx, order, set)
		} else {
			err = p.updateRRset(ctx, order, set)
		}
		if err != nil {
			return nil, fmt.Errorf("hosterby: writing %s records of %q: %w", set.Type, set.Name, err)
		}
	}
	return added, nil
}

// SetRecords makes the input records the only records of their (name, type)
// pairs in the zone, replacing all others, including disabled ones. It returns
// the records that were set.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zone = normalizeZone(zone)
	inputs, err := prepare(zone, records)
	if err != nil {
		return nil, err
	}

	var (
		keys    []setKey
		desired = make(map[setKey]*rrset)
		results []libdns.Record
	)
	for _, in := range inputs {
		set, ok := desired[in.key]
		if !ok {
			set = &rrset{Name: in.key.name, Type: in.key.typ, TTL: ttlSeconds(in.rr.TTL)}
			desired[in.key] = set
			keys = append(keys, in.key)
		}
		if set.find(in.rr.Data, zone) >= 0 {
			continue
		}
		set.Records = append(set.Records, record{Content: in.content})

		r, err := withTTL(in.rr, set)
		if err != nil {
			return nil, fmt.Errorf("hosterby: %w", err)
		}
		results = append(results, r)
	}

	unlock, err := p.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	order, sets, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	existing := indexRRsets(sets)

	for _, key := range keys {
		set := *desired[key]
		if _, ok := existing[key]; ok {
			err = p.updateRRset(ctx, order, set)
		} else {
			err = p.createRRset(ctx, order, set)
		}
		if err != nil {
			return nil, fmt.Errorf("hosterby: writing %s records of %q: %w", set.Type, set.Name, err)
		}
	}
	return results, nil
}

// DeleteRecords deletes matching records from the zone and returns them. An
// empty type, TTL or data matches any value. TTLs are clamped to the API range
// before comparison.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zone = normalizeZone(zone)
	for _, r := range records {
		if r.RR().Name == "" {
			return nil, errNoName
		}
	}

	unlock, err := p.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	order, sets, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}

	var (
		dirty   []int
		deleted []libdns.Record
	)
	for _, r := range records {
		rr := r.RR()
		name := absoluteName(rr.Name, zone)
		data := ""
		if rr.Data != "" {
			data = canonicalData(rr)
		}

		for i := range sets {
			set := &sets[i]
			if set.Name != name ||
				(rr.Type != "" && rr.Type != set.Type) ||
				(rr.TTL != 0 && ttlSeconds(rr.TTL) != set.TTL) {
				continue
			}

			kept := set.Records[:0]
			for _, rec := range set.Records {
				if rec.Disabled {
					kept = append(kept, rec)
					continue
				}
				parsed, err := parseRecord(*set, rec, zone)
				if err != nil || (data != "" && parsed.RR().Data != data) {
					kept = append(kept, rec)
					continue
				}
				deleted = append(deleted, parsed)
			}
			if len(kept) != len(set.Records) {
				set.Records = kept
				if !slices.Contains(dirty, i) {
					dirty = append(dirty, i)
				}
			}
		}
	}

	for _, i := range dirty {
		set := sets[i]
		if len(set.Records) == 0 {
			err = p.deleteRRset(ctx, order, set)
		} else {
			err = p.updateRRset(ctx, order, set)
		}
		if err != nil {
			return nil, fmt.Errorf("hosterby: deleting %s records of %q: %w", set.Type, set.Name, err)
		}
	}
	return deleted, nil
}

// ListZones lists the zones of the account, with internationalized names in
// Punycode.
func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	orders, err := p.listOrders(ctx)
	if err != nil {
		return nil, fmt.Errorf("hosterby: listing DNS orders: %w", err)
	}
	zones := make([]libdns.Zone, 0, len(orders))
	for _, o := range orders {
		zones = append(zones, libdns.Zone{Name: normalizeZone(o.DomainName)})
	}
	return zones, nil
}

// zone returns the order and the record sets of the normalized zone.
func (p *Provider) zone(ctx context.Context, zone string) (dnsOrder, []rrset, error) {
	order, err := p.lookupOrder(ctx, zone)
	if err != nil {
		return dnsOrder{}, nil, fmt.Errorf("hosterby: %w", err)
	}
	sets, err := p.listRRsets(ctx, order)
	if err != nil {
		return dnsOrder{}, nil, fmt.Errorf("hosterby: listing records of %q: %w", zone, err)
	}
	return order, sets, nil
}

// lock acquires the write lock, honoring context cancellation.
func (p *Provider) lock(ctx context.Context) (unlock func(), err error) {
	p.writeLockOnce.Do(func() { p.writeLock = make(chan struct{}, 1) })
	select {
	case p.writeLock <- struct{}{}:
		return func() { <-p.writeLock }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// setKey identifies a record set within a zone.
type setKey struct {
	name string // lower-case FQDN with trailing dot
	typ  string
}

var errNoName = errors.New(`hosterby: record name is required (use "@" for the zone apex)`)

// input is a record to be written, prepared for the API.
type input struct {
	key     setKey
	rr      libdns.RR // with data in the canonical libdns form
	content string    // API representation
}

// prepare validates records and converts them for writing.
func prepare(zone string, records []libdns.Record) ([]input, error) {
	inputs := make([]input, 0, len(records))
	for _, r := range records {
		rr := r.RR()
		if rr.Name == "" {
			return nil, errNoName
		}
		if !writableTypes[rr.Type] {
			return nil, fmt.Errorf("hosterby: unsupported record type %q for %q", rr.Type, rr.Name)
		}
		parsed, err := rr.Parse()
		if err != nil {
			return nil, fmt.Errorf("hosterby: invalid %s record %q: %w", rr.Type, rr.Name, err)
		}
		rr = parsed.RR()
		content := rr.Data
		if rr.Type == "TXT" {
			content = quoteTXT(rr.Data)
		}
		inputs = append(inputs, input{
			key:     setKey{name: absoluteName(rr.Name, zone), typ: rr.Type},
			rr:      rr,
			content: content,
		})
	}
	return inputs, nil
}

func indexRRsets(sets []rrset) map[setKey]*rrset {
	index := make(map[setKey]*rrset, len(sets))
	for i := range sets {
		key := setKey{name: sets[i].Name, typ: sets[i].Type}
		index[key] = &sets[i]
	}
	return index
}

// find returns the index of the record with the given canonical data, or -1.
func (s *rrset) find(data, zone string) int {
	for i, rec := range s.Records {
		r, err := parseRecord(*s, rec, zone)
		if err == nil && r.RR().Data == data {
			return i
		}
	}
	return -1
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ libdns.ZoneLister     = (*Provider)(nil)
)
