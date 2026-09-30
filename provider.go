// Package enum implements a DNS record management client compatible
// with the libdns interfaces for enum.
package enum

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with enum.
type Provider struct {
	// APIKey of a service account.
	APIKey string `json:"api_key,omitempty"`

	ProjectID string `json:"project_id,omitempty"`

	baseURL string
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}

	sets, err := p.listRecordSets(ctx, zoneID)
	if err != nil {
		return nil, err
	}

	var records []libdns.Record
	for _, set := range sets {
		for _, r := range libdnsRecords(set, zone) {
			records = append(records, r.record)
		}
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
// It keeps the TTL of an existing record set.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}

	var added []libdns.Record
	for _, record := range records {
		rr := record.RR()

		set, err := p.addRecordSetValue(ctx, zoneID, apiName(rr.Name, zone), rr.Type, ttlSeconds(rr.TTL), apiContent(rr))
		if err != nil {
			return added, err
		}

		r, _ := libdns.RR{
			Name: rr.Name,
			TTL:  time.Duration(set.TTL) * time.Second,
			Type: rr.Type,
			Data: rr.Data,
		}.Parse()

		added = append(added, r)
	}

	return added, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
// It uses the TTL of the first record of each record set. Each record set is
// replaced atomically, the call as a whole is not.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}

	type key struct{ name, typ string }

	var order []key
	sets := make(map[key]*recordSet)

	for _, record := range records {
		rr := record.RR()
		k := key{apiName(rr.Name, zone), rr.Type}

		set, ok := sets[k]
		if !ok {
			set = &recordSet{Name: k.name, Type: k.typ, TTL: ttlSeconds(rr.TTL)}
			sets[k] = set
			order = append(order, k)
		}

		set.Records = append(set.Records, recordValue{Content: apiContent(rr)})
	}

	var results []libdns.Record
	for _, k := range order {
		set, err := p.updateRecordSet(ctx, zoneID, *sets[k])
		if isNotFound(err) {
			set, err = p.createRecordSet(ctx, zoneID, *sets[k])
		}
		if err != nil {
			return results, err
		}

		for _, r := range libdnsRecords(set, zone) {
			results = append(results, r.record)
		}
	}

	return results, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}

	sets, err := p.listRecordSets(ctx, zoneID)
	if err != nil {
		return nil, err
	}

	var deleted []libdns.Record
	for _, set := range sets {
		for _, existing := range libdnsRecords(set, zone) {
			if !matchesAny(existing.record.RR(), records) {
				continue
			}

			if err := p.removeRecordSetValue(ctx, zoneID, set.Name, set.Type, existing.content); err != nil {
				return deleted, err
			}

			deleted = append(deleted, existing.record)
		}
	}

	return deleted, nil
}

func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	zones, err := p.listZones(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]libdns.Zone, 0, len(zones))
	for _, z := range zones {
		result = append(result, libdns.Zone{Name: z.Name + "."})
	}

	return result, nil
}

func (p *Provider) getZoneID(ctx context.Context, zone string) (string, error) {
	if p.APIKey == "" || p.ProjectID == "" {
		return "", errors.New("enum: api_key and project_id are required")
	}

	z, err := p.getZoneByName(ctx, strings.TrimSuffix(strings.ToLower(zone), "."))
	if err != nil {
		return "", fmt.Errorf("enum: looking up zone %s: %w", zone, err)
	}

	return z.ID, nil
}

type existingRecord struct {
	record  libdns.Record
	content string
}

func libdnsRecords(set recordSet, zone string) []existingRecord {
	name := libdns.RelativeName(set.Name, strings.ToLower(zone))
	ttl := time.Duration(set.TTL) * time.Second

	var records []existingRecord
	for _, v := range set.Records {
		if v.Disabled {
			continue
		}

		data := v.Content
		if set.Type == "TXT" {
			data = unquoteTXT(data)
		}

		r, _ := libdns.RR{Name: name, TTL: ttl, Type: set.Type, Data: data}.Parse()

		records = append(records, existingRecord{record: r, content: v.Content})
	}

	return records
}

func matchesAny(existing libdns.RR, inputs []libdns.Record) bool {
	for _, input := range inputs {
		parsed, _ := input.RR().Parse()
		in := parsed.RR()

		if strings.EqualFold(in.Name, existing.Name) &&
			(in.Type == "" || in.Type == existing.Type) &&
			(in.TTL == 0 || in.TTL == existing.TTL) &&
			(in.Data == "" || in.Data == existing.Data) {
			return true
		}
	}

	return false
}

func apiName(name, zone string) string {
	return strings.TrimSuffix(strings.ToLower(libdns.AbsoluteName(name, zone)), ".")
}

func apiContent(rr libdns.RR) string {
	if rr.Type == "TXT" {
		return quoteTXT(rr.Data)
	}

	return rr.Data
}

func ttlSeconds(ttl time.Duration) int {
	return int(ttl / time.Second)
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ libdns.ZoneLister     = (*Provider)(nil)
)
