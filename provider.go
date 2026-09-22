// Package mittwald implements a DNS record management client compatible with
// the libdns interfaces for mittwald mStudio (https://www.mittwald.de).
//
// mStudio keeps one "DNS zone" per name: a domain and every name below it
// (www, _acme-challenge, _dmarc) are separate zones, each with one record set
// per type (A and AAAA together, CNAME, MX, TXT, SRV and CAA). This package
// creates the zone of a name when a record is added to it and leaves it in
// place when its records are removed: a new zone takes a while until the
// nameservers serve it, and names like _acme-challenge are used again.
//
// Record sets that mStudio manages (the addresses of a name connected to an
// ingress, the mail exchangers of mittwald's mail service) are not returned
// by GetRecords. Writing A, AAAA or MX records to such a name replaces the
// managed set.
//
// Changes are not atomic: a call that fails may have applied part of its
// records.
package mittwald

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/libdns/libdns"
	generatedv2 "github.com/mittwald/api-client-go/mittwaldv2/generated/clients"
	"github.com/mittwald/api-client-go/mittwaldv2/generated/schemas/dnsv2"
)

// Provider facilitates DNS record manipulation with mittwald mStudio.
type Provider struct {
	// APIToken is an mStudio API token of a user with access to the projects
	// of the domains.
	APIToken string `json:"api_token,omitempty"`

	// apiURL replaces the API's address in tests.
	apiURL string

	// busy serializes all calls, since a record set is changed by reading
	// and writing it as a whole; see lock.
	busy          chan struct{}
	busyOnce      sync.Once
	client        generatedv2.Client
	projectByZone map[string]string // zone name -> project ID
}

// lock waits until no other call of p runs, or ctx ends.
func (p *Provider) lock(ctx context.Context) error {
	p.busyOnce.Do(func() { p.busy = make(chan struct{}, 1) })
	select {
	case p.busy <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Provider) unlock() { <-p.busy }

// setup creates the client on first use. The lock must be held.
func (p *Provider) setup() error {
	if p.client != nil {
		return nil
	}
	if p.APIToken == "" {
		return errors.New("mittwald: api_token is not set")
	}
	apiURL := p.apiURL
	if apiURL == "" {
		apiURL = defaultAPIURL
	}
	c, err := newClient(p.APIToken, apiURL)
	if err != nil {
		return err
	}
	p.client = c
	return nil
}

// projectOf returns the ID of the project that holds the name or a zone
// above it. The lock must be held.
func (p *Provider) projectOf(ctx context.Context, name string) (string, error) {
	lookup := func() (string, bool) {
		for n := name; ; {
			if id, ok := p.projectByZone[n]; ok {
				return id, true
			}
			_, parent, found := strings.Cut(n, ".")
			if !found {
				return "", false
			}
			n = parent
		}
	}
	if id, ok := lookup(); ok {
		return id, nil
	}
	ids, err := listProjectIDs(ctx, p.client)
	if err != nil {
		return "", err
	}
	p.projectByZone = map[string]string{}
	for _, id := range ids {
		zones, err := listProjectZones(ctx, p.client, id)
		if err != nil {
			return "", err
		}
		for _, z := range zones {
			p.projectByZone[z.Domain] = id
		}
	}
	if id, ok := lookup(); ok {
		return id, nil
	}
	return "", fmt.Errorf("mittwald: %q is not in any mStudio project of this token", name)
}

// zonesUnder returns the mStudio zones of the project that holds zone, and
// the root zone (the domain) at or above zone. The lock must be held.
func (p *Provider) zonesUnder(ctx context.Context, zone string) (root dnsv2.Zone, zones []dnsv2.Zone, err error) {
	name := fqdnNoDot(zone)
	projectID, err := p.projectOf(ctx, name)
	if err != nil {
		return dnsv2.Zone{}, nil, err
	}
	zones, err = listProjectZones(ctx, p.client, projectID)
	if err != nil {
		return dnsv2.Zone{}, nil, err
	}
	for _, z := range zones {
		if (z.Domain == name || strings.HasSuffix(name, "."+z.Domain)) && !hasZoneAbove(zones, z.Domain) {
			return z, zones, nil
		}
	}
	return dnsv2.Zone{}, nil, fmt.Errorf("mittwald: no root zone for %q", name)
}

// hasZoneAbove reports whether a zone of the list is a parent domain of domain.
func hasZoneAbove(zones []dnsv2.Zone, domain string) bool {
	return slices.ContainsFunc(zones, func(z dnsv2.Zone) bool { return strings.HasSuffix(domain, "."+z.Domain) })
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	zone = normalZone(zone)
	if err := p.lock(ctx); err != nil {
		return nil, err
	}
	defer p.unlock()
	if err := p.setup(); err != nil {
		return nil, err
	}
	_, zones, err := p.zonesUnder(ctx, zone)
	if err != nil {
		return nil, err
	}
	name := fqdnNoDot(zone)
	var recs []libdns.Record
	for _, z := range zones {
		if z.Domain != name && !strings.HasSuffix(z.Domain, "."+name) {
			continue
		}
		r, err := recordsOf(z, zone)
		if err != nil {
			return nil, err
		}
		recs = append(recs, r...)
	}
	return recs, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return p.change(ctx, zone, records, false, func(current, input []libdns.Record) ([]libdns.Record, []libdns.Record) {
		var added []libdns.Record
		for _, r := range input {
			if !slices.ContainsFunc(current, func(c libdns.Record) bool { return equalRecord(c.RR(), r.RR()) }) {
				current = append(current, r)
				added = append(added, r)
			}
		}
		return current, added
	})
}

// SetRecords sets the records in the zone, either by updating existing records
// or creating new ones. It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return p.change(ctx, zone, records, false, func(current, input []libdns.Record) ([]libdns.Record, []libdns.Record) {
		current = slices.DeleteFunc(current, func(c libdns.Record) bool {
			return slices.ContainsFunc(input, func(r libdns.Record) bool { return r.RR().Type == c.RR().Type })
		})
		return append(current, input...), input
	})
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return p.change(ctx, zone, records, true, func(current, input []libdns.Record) ([]libdns.Record, []libdns.Record) {
		var deleted []libdns.Record
		current = slices.DeleteFunc(current, func(c libdns.Record) bool {
			if slices.ContainsFunc(input, func(r libdns.Record) bool { return sameRecord(c.RR(), r.RR()) }) {
				deleted = append(deleted, c)
				return true
			}
			return false
		})
		return current, deleted
	})
}

// ListZones returns the domains of all mStudio projects of the token.
func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	if err := p.lock(ctx); err != nil {
		return nil, err
	}
	defer p.unlock()
	if err := p.setup(); err != nil {
		return nil, err
	}
	ids, err := listProjectIDs(ctx, p.client)
	if err != nil {
		return nil, err
	}
	var out []libdns.Zone
	for _, id := range ids {
		zones, err := listProjectZones(ctx, p.client, id)
		if err != nil {
			return nil, err
		}
		for _, z := range zones {
			if !hasZoneAbove(zones, z.Domain) {
				out = append(out, libdns.Zone{Name: withDot(z.Domain)})
			}
		}
	}
	return out, nil
}

// change applies edit to the records of every name in records and writes the
// record sets that the result of edit touches. edit gets the current records
// of one name and the input records for it, and returns the new records of
// the name and those to return to the caller. filter allows input records
// without type or data, as patterns for DeleteRecords.
func (p *Provider) change(ctx context.Context, zone string, records []libdns.Record, filter bool,
	edit func(current, input []libdns.Record) (next, result []libdns.Record)) ([]libdns.Record, error) {
	zone = normalZone(zone)
	if err := p.lock(ctx); err != nil {
		return nil, err
	}
	defer p.unlock()
	if err := p.setup(); err != nil {
		return nil, err
	}

	// Group the input by name, keeping the order of first appearance.
	var names []string
	byName := map[string][]libdns.Record{}
	for _, r := range records {
		r, err := typed(r, filter)
		if err != nil {
			return nil, err
		}
		rr := r.RR()
		if rr.Name == "" {
			return nil, errors.New("mittwald: a record needs a name")
		}
		if rr.Type != "" {
			if _, err := slotOf(rr.Type); err != nil {
				return nil, err
			}
		}
		name := fqdnNoDot(libdns.AbsoluteName(rr.Name, zone))
		if strings.HasPrefix(name, "*") {
			return nil, fmt.Errorf("mittwald: wildcard names are not supported (%s)", name)
		}
		if _, ok := byName[name]; !ok {
			names = append(names, name)
		}
		byName[name] = append(byName[name], r)
	}

	root, zones, err := p.zonesUnder(ctx, zone)
	if err != nil {
		return nil, err
	}
	var result []libdns.Record
	for _, name := range names {
		if zoneName := fqdnNoDot(zone); name != zoneName && !strings.HasSuffix(name, "."+zoneName) {
			return result, fmt.Errorf("mittwald: %s is not in zone %s", name, zone)
		}
		var z dnsv2.Zone
		if i := slices.IndexFunc(zones, func(z dnsv2.Zone) bool { return z.Domain == name }); i >= 0 {
			z = zones[i]
		}
		var current []libdns.Record
		if z.Id != "" {
			if current, err = recordsOf(z, zone); err != nil {
				return result, err
			}
		}
		next, res := edit(current, byName[name])
		if len(res) == 0 {
			continue
		}

		// The sets the result touches; those that end up empty are unset
		// first, since a CNAME can only be set on a name without other records.
		var unset, set []slot
		for _, r := range res {
			s, _ := slotOf(r.RR().Type)
			if slices.Contains(unset, s) || slices.Contains(set, s) {
				continue
			}
			if slices.ContainsFunc(next, func(n libdns.Record) bool { t, _ := slotOf(n.RR().Type); return t == s }) {
				set = append(set, s)
			} else {
				unset = append(unset, s)
			}
		}
		if z.Id == "" {
			if z.Id, err = createZone(ctx, p.client, root.Id, strings.TrimSuffix(name, "."+root.Domain)); err != nil {
				return result, err
			}
		}
		for _, s := range append(unset, set...) {
			body, err := bodyFor(s, next)
			if err != nil {
				return result, err
			}
			if err := setRecordSet(ctx, p.client, z.Id, s, body); err != nil {
				return result, err
			}
		}
		result = append(result, res...)
	}
	return result, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ libdns.ZoneLister     = (*Provider)(nil)
)
