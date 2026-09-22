package mittwald

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/mittwald/api-client-go/mittwaldv2/generated/clients/domainclientv2"
	"github.com/mittwald/api-client-go/mittwaldv2/generated/schemas/dnsv2"
)

// TTL limits of the API for a set with an explicit TTL.
const (
	minTTL = 60 * time.Second
	maxTTL = 86400 * time.Second
)

// slot is one record set of a zone. A and AAAA share one.
type slot = domainclientv2.UpdateRecordSetRequestPathRecordSet

const (
	slotA     = domainclientv2.UpdateRecordSetRequestPathRecordSetA
	slotCAA   = domainclientv2.UpdateRecordSetRequestPathRecordSetCaa
	slotCNAME = domainclientv2.UpdateRecordSetRequestPathRecordSetCname
	slotMX    = domainclientv2.UpdateRecordSetRequestPathRecordSetMx
	slotSRV   = domainclientv2.UpdateRecordSetRequestPathRecordSetSrv
	slotTXT   = domainclientv2.UpdateRecordSetRequestPathRecordSetTxt
)

func slotOf(rrType string) (slot, error) {
	switch rrType {
	case "A", "AAAA":
		return slotA, nil
	case "CAA":
		return slotCAA, nil
	case "CNAME":
		return slotCNAME, nil
	case "MX":
		return slotMX, nil
	case "SRV":
		return slotSRV, nil
	case "TXT":
		return slotTXT, nil
	}
	return "", fmt.Errorf("record type %q is not supported by mStudio", rrType)
}

/*
The generated client decodes a oneOf into every alternative that accepts the
JSON, and an unset record set ({}) is accepted by several of them: it comes
back as RecordUnset and, for example, as a CNAME with an empty target. A set
is therefore only read when it is not unset. A set that mStudio manages
(managedBy an ingress, managed mail exchangers) is not read either.
*/

// ttlOf returns the TTL of a set; "auto" is 0 (served as 60 seconds).
func ttlOf(s dnsv2.RecordSettings) time.Duration {
	if s.Ttl != nil && s.Ttl.AlternativeTtlSeconds != nil {
		return time.Duration(s.Ttl.AlternativeTtlSeconds.Seconds) * time.Second
	}
	return 0
}

// withDot returns a host name the way libdns records carry it.
func withDot(name string) string {
	return strings.TrimSuffix(name, ".") + "."
}

// recordsOf returns the records of the custom record sets of a zone, named
// relative to zone.
func recordsOf(z dnsv2.Zone, zone string) ([]libdns.Record, error) {
	name := libdns.RelativeName(withDot(z.Domain), zone)
	var recs []libdns.Record
	rs := z.RecordSet
	if a := rs.CombinedARecords.AlternativeCombinedACustom; a != nil && rs.CombinedARecords.AlternativeRecordUnset == nil {
		ttl := ttlOf(a.Settings)
		for _, s := range append(append([]string{}, stringsOf(a.A)...), stringsOf(a.Aaaa)...) {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("zone %s: %w", z.Domain, err)
			}
			recs = append(recs, libdns.Address{Name: name, TTL: ttl, IP: ip})
		}
	}
	if c := rs.Cname.AlternativeRecordCNAMEComponent; c != nil && rs.Cname.AlternativeRecordUnset == nil {
		recs = append(recs, libdns.CNAME{Name: name, TTL: ttlOf(c.Settings), Target: withDot(c.Fqdn)})
	}
	if m := rs.Mx.AlternativeRecordMXCustom; m != nil && rs.Mx.AlternativeRecordUnset == nil {
		for _, r := range m.Records {
			recs = append(recs, libdns.MX{Name: name, TTL: ttlOf(m.Settings), Preference: uint16(r.Priority), Target: withDot(r.Fqdn)})
		}
	}
	if t := rs.Txt.AlternativeRecordTXTComponent; t != nil && rs.Txt.AlternativeRecordUnset == nil {
		for _, e := range t.Entries {
			recs = append(recs, libdns.TXT{Name: name, TTL: ttlOf(t.Settings), Text: e})
		}
	}
	if s := rs.Srv.AlternativeRecordSRVComponent; s != nil && rs.Srv.AlternativeRecordUnset == nil {
		for _, r := range s.Records {
			var priority, weight uint16
			if r.Priority != nil {
				priority = uint16(*r.Priority)
			}
			if r.Weight != nil {
				weight = uint16(*r.Weight)
			}
			rr := libdns.RR{Name: name, TTL: ttlOf(s.Settings), Type: "SRV", Data: fmt.Sprintf("%d %d %d %s", priority, weight, r.Port, withDot(r.Fqdn))}
			rec, err := rr.Parse()
			if err != nil {
				return nil, fmt.Errorf("zone %s: %w", z.Domain, err)
			}
			recs = append(recs, rec)
		}
	}
	if c := rs.Caa.AlternativeRecordCAAComponent; c != nil && rs.Caa.AlternativeRecordUnset == nil {
		for _, r := range c.Records {
			recs = append(recs, libdns.CAA{Name: name, TTL: ttlOf(c.Settings), Flags: uint8(r.Flags), Tag: string(r.Tag), Value: r.Value})
		}
	}
	return recs, nil
}

func stringsOf[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = string(s)
	}
	return out
}

// bodyFor builds the body that makes set s hold exactly the records of recs
// that belong to it; no such record unsets it. All of them must have the same
// TTL; 0 means "auto".
func bodyFor(s slot, recs []libdns.Record) (domainclientv2.UpdateRecordSetRequestBody, error) {
	var mine []libdns.Record
	for _, r := range recs {
		if rs, err := slotOf(r.RR().Type); err == nil && rs == s {
			mine = append(mine, r)
		}
	}
	if len(mine) == 0 {
		return domainclientv2.UpdateRecordSetRequestBody{AlternativeRecordUnset: &dnsv2.RecordUnset{}}, nil
	}
	ttl := mine[0].RR().TTL
	for _, r := range mine[1:] {
		if r.RR().TTL != ttl {
			return domainclientv2.UpdateRecordSetRequestBody{}, fmt.Errorf("%s: mStudio keeps one TTL per record set (%s); found %s and %s", r.RR().Name, s, ttl, r.RR().TTL)
		}
	}
	settings := dnsv2.RecordSettings{Ttl: &dnsv2.RecordSettingsTtl{AlternativeTtlAuto: &dnsv2.TtlAuto{Auto: true}}}
	if ttl != 0 {
		if ttl < minTTL || ttl > maxTTL {
			return domainclientv2.UpdateRecordSetRequestBody{}, fmt.Errorf("TTL %s is outside %s..%s", ttl, minTTL, maxTTL)
		}
		settings = dnsv2.RecordSettings{Ttl: &dnsv2.RecordSettingsTtl{AlternativeTtlSeconds: &dnsv2.TtlSeconds{Seconds: int64(ttl / time.Second)}}}
	}

	switch s {
	case slotA:
		body := &dnsv2.CombinedACustom{A: []dnsv2.CombinedAManagedARecord{}, Aaaa: []dnsv2.CombinedAManagedAAAARecord{}, Settings: settings}
		for _, r := range mine {
			ip := r.(libdns.Address).IP
			if ip.Is4() {
				body.A = append(body.A, dnsv2.CombinedAManagedARecord(ip.String()))
			} else {
				body.Aaaa = append(body.Aaaa, dnsv2.CombinedAManagedAAAARecord(ip.String()))
			}
		}
		return domainclientv2.UpdateRecordSetRequestBody{AlternativeCombinedACustom: body}, nil
	case slotCNAME:
		if len(mine) > 1 {
			return domainclientv2.UpdateRecordSetRequestBody{}, fmt.Errorf("%s: a name has at most one CNAME", mine[0].RR().Name)
		}
		return domainclientv2.UpdateRecordSetRequestBody{AlternativeRecordCNAMEComponent: &dnsv2.RecordCNAMEComponent{
			Fqdn: strings.TrimSuffix(mine[0].(libdns.CNAME).Target, "."), Settings: settings,
		}}, nil
	case slotMX:
		body := &dnsv2.RecordMXCustom{Settings: settings}
		for _, r := range mine {
			mx := r.(libdns.MX)
			body.Records = append(body.Records, dnsv2.RecordMXRecord{Priority: int64(mx.Preference), Fqdn: strings.TrimSuffix(mx.Target, ".")})
		}
		return domainclientv2.UpdateRecordSetRequestBody{AlternativeRecordMXCustom: body}, nil
	case slotTXT:
		body := &dnsv2.RecordTXTComponent{Settings: settings}
		for _, r := range mine {
			body.Entries = append(body.Entries, r.(libdns.TXT).Text)
		}
		return domainclientv2.UpdateRecordSetRequestBody{AlternativeRecordTXTComponent: body}, nil
	case slotSRV:
		body := &dnsv2.RecordSRVComponent{Settings: settings}
		for _, r := range mine {
			srv := r.(libdns.SRV)
			priority, weight := int64(srv.Priority), int64(srv.Weight)
			body.Records = append(body.Records, dnsv2.RecordSRVRecord{
				Priority: &priority, Weight: &weight, Port: int64(srv.Port), Fqdn: strings.TrimSuffix(srv.Target, "."),
			})
		}
		return domainclientv2.UpdateRecordSetRequestBody{AlternativeRecordSRVComponent: body}, nil
	case slotCAA:
		body := &dnsv2.RecordCAAComponent{Settings: settings}
		for _, r := range mine {
			caa := r.(libdns.CAA)
			body.Records = append(body.Records, dnsv2.RecordCAARecord{Flags: int64(caa.Flags), Tag: dnsv2.RecordCAARecordTag(caa.Tag), Value: caa.Value})
		}
		return domainclientv2.UpdateRecordSetRequestBody{AlternativeRecordCAAComponent: body}, nil
	}
	return domainclientv2.UpdateRecordSetRequestBody{}, fmt.Errorf("unknown record set %s", s)
}

// sameRecord reports whether zone record z is what r describes. An empty type,
// a zero TTL or empty data in r match anything, as DeleteRecords requires.
func sameRecord(z, r libdns.RR) bool {
	if r.Type != "" && r.Type != z.Type {
		return false
	}
	if r.TTL != 0 && r.TTL != z.TTL {
		return false
	}
	return r.Data == "" || canonical(z.Type, r.Data) == canonical(z.Type, z.Data)
}

// canonical makes two presentations of the same data equal: host names with
// and without trailing dot, in any case.
func canonical(rrType, data string) string {
	switch rrType {
	case "CNAME", "MX", "SRV":
		return strings.ToLower(strings.TrimSuffix(data, "."))
	}
	return data
}

// typed returns the libdns struct of a record's type, whatever type the
// caller passed. With filter set, a record without type or data (a pattern
// for DeleteRecords) stays an RR.
func typed(r libdns.Record, filter bool) (libdns.Record, error) {
	rr := r.RR()
	if filter && (rr.Type == "" || rr.Data == "") {
		return rr, nil
	}
	if rr.Type == "TXT" && rr.Data == "" {
		return nil, fmt.Errorf("mittwald: %s: mStudio does not accept an empty TXT record", rr.Name)
	}
	return rr.Parse()
}

// equalRecord reports whether two records have the same type and data; a
// record set has one TTL, so the TTL does not tell records apart.
func equalRecord(a, b libdns.RR) bool {
	return a.Type == b.Type && canonical(a.Type, a.Data) == canonical(b.Type, b.Data)
}
