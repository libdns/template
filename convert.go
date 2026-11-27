package nameocean

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// NameOcean accepts these TTLs only; any other TTL is rounded to the closest one.
var ttls = []struct {
	name string
	d    time.Duration
}{
	{"5m", 5 * time.Minute},
	{"15m", 15 * time.Minute},
	{"30m", 30 * time.Minute},
	{"1h", time.Hour},
	{"1d", 24 * time.Hour},
}

// ttlString rounds d to the closest TTL NameOcean accepts (ties go to the shorter
// one). Zero, which libdns uses for "do not cache", becomes the shortest, 5m.
func ttlString(d time.Duration) string {
	best := ttls[0]
	for _, t := range ttls[1:] {
		if abs(t.d-d) < abs(best.d-d) {
			best = t
		}
	}
	return best.name
}

func ttlDuration(s string) time.Duration {
	for _, t := range ttls {
		if t.name == s {
			return t.d
		}
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	if n, err := strconv.Atoi(s); err == nil {
		return time.Duration(n) * time.Second
	}
	return time.Hour
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// hostname is a libdns name ("www", "@", or a FQDN with a trailing dot) as the
// API wants it: relative to the zone, "@" for the zone itself, lower case.
func hostname(name, zone string) string {
	return strings.ToLower(libdns.RelativeName(libdns.AbsoluteName(name, zone), zone))
}

// apiTarget is a libdns target as the API stores it: a full name without the
// trailing dot, "@" for the zone itself, "." (HTTPS/SVCB) unchanged.
func apiTarget(target, zone string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "." || t == "@" {
		return t
	}
	t = strings.TrimSuffix(t, ".")
	if t == apiZone(zone) {
		return "@"
	}
	return t
}

// fqdn is an API target as libdns writes it: a full name with the trailing dot.
func fqdn(target, zone string) string {
	switch target {
	case "@":
		return apiZone(zone) + "."
	case ".":
		return "."
	}
	return strings.TrimSuffix(target, ".") + "."
}

func intp(n uint64) *int {
	v := int(n)
	return &v
}

func num(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// toLibdns turns an API record into the libdns struct for its type
// (libdns.RR for ALIAS, PTR and DS, which libdns has no struct for).
func toLibdns(r apiRecord, zone string) (libdns.Record, error) {
	rr := libdns.RR{Name: r.Hostname, TTL: ttlDuration(r.TTL), Type: r.Type}
	switch r.Type {
	case "A", "AAAA":
		rr.Data = r.IP
	case "CNAME", "NS", "PTR", "ALIAS":
		rr.Data = fqdn(r.Target, zone)
	case "MX":
		rr.Data = fmt.Sprintf("%d %s", num(r.Priority), fqdn(r.Target, zone))
	case "TXT":
		rr.Data = r.Text
	case "SRV":
		rr.Data = fmt.Sprintf("%d %d %d %s", num(r.Priority), num(r.Weight), num(r.Port), fqdn(r.Target, zone))
	case "CAA":
		rr.Data = fmt.Sprintf("%d %s %s", num(r.Flags), r.Tag, strconv.Quote(r.Value))
	case "HTTPS", "SVCB":
		rr.Data = strings.TrimSpace(fmt.Sprintf("%d %s %s", num(r.Priority), fqdn(r.Target, zone), r.Params))
	case "DS":
		rr.Data = fmt.Sprintf("%d %d %d %s", num(r.KeyTag), num(r.Algorithm), num(r.DigestType), r.Digest)
	default:
		return nil, fmt.Errorf("nameocean: unexpected record type %q", r.Type)
	}
	rec, err := rr.Parse()
	if err != nil {
		return nil, fmt.Errorf("nameocean: %s %s: %w", r.Type, r.Hostname, err)
	}
	return rec, nil
}

// fromLibdns turns any libdns record into the API's form.
func fromLibdns(rec libdns.Record, zone string) (apiRecord, error) {
	rr := rec.RR()
	typ := strings.ToUpper(rr.Type)
	r := apiRecord{Type: typ, Hostname: hostname(rr.Name, zone), TTL: ttlString(rr.TTL)}
	if rr.Name == "" {
		return r, fmt.Errorf("nameocean: record without a name (use \"@\" for the zone itself)")
	}
	fields := strings.Fields(rr.Data)
	need := func(n int, form string) error {
		if len(fields) < n {
			return fmt.Errorf("nameocean: %s %s: expected %q, got %q", typ, rr.Name, form, rr.Data)
		}
		return nil
	}
	parseUint := func(s string, bits int) (*int, error) {
		v, err := strconv.ParseUint(s, 10, bits)
		if err != nil {
			return nil, fmt.Errorf("nameocean: %s %s: %q is not a number", typ, rr.Name, s)
		}
		return intp(v), nil
	}
	var err error
	switch typ {
	case "A", "AAAA":
		ip, perr := netip.ParseAddr(strings.TrimSpace(rr.Data))
		if perr != nil {
			return r, fmt.Errorf("nameocean: %s %s: %q is not an IP address", typ, rr.Name, rr.Data)
		}
		r.Type = "A"
		if ip.Is6() && !ip.Is4In6() {
			r.Type = "AAAA"
		}
		r.IP = ip.String()
	case "CNAME", "NS", "PTR", "ALIAS":
		if err = need(1, "target"); err == nil {
			r.Target = apiTarget(fields[0], zone)
		}
	case "MX":
		if err = need(2, "preference target"); err == nil {
			if r.Priority, err = parseUint(fields[0], 16); err == nil {
				r.Target = apiTarget(fields[1], zone)
			}
		}
	case "TXT":
		r.Text = rr.Data
	case "SRV":
		if err = need(4, "priority weight port target"); err == nil {
			if r.Priority, err = parseUint(fields[0], 16); err == nil {
				if r.Weight, err = parseUint(fields[1], 16); err == nil {
					if r.Port, err = parseUint(fields[2], 16); err == nil {
						r.Target = apiTarget(fields[3], zone)
					}
				}
			}
		}
	case "CAA":
		parts := strings.SplitN(strings.TrimSpace(rr.Data), " ", 3)
		if len(parts) != 3 {
			return r, fmt.Errorf("nameocean: CAA %s: expected 'flags tag \"value\"', got %q", rr.Name, rr.Data)
		}
		if r.Flags, err = parseUint(parts[0], 8); err == nil {
			r.Tag = parts[1]
			r.Value = parts[2]
			if v, uerr := strconv.Unquote(parts[2]); uerr == nil {
				r.Value = v
			}
		}
	case "HTTPS", "SVCB":
		if err = need(2, "priority target [params]"); err == nil {
			if r.Priority, err = parseUint(fields[0], 16); err == nil {
				r.Target = apiTarget(fields[1], zone)
				r.Params = strings.Join(fields[2:], " ")
			}
		}
	case "DS":
		if err = need(4, "key_tag algorithm digest_type digest"); err == nil {
			if r.KeyTag, err = parseUint(fields[0], 16); err == nil {
				if r.Algorithm, err = parseUint(fields[1], 8); err == nil {
					if r.DigestType, err = parseUint(fields[2], 8); err == nil {
						r.Digest = strings.ToUpper(strings.Join(fields[3:], ""))
					}
				}
			}
		}
	default:
		return r, fmt.Errorf("nameocean: record type %q is not supported", rr.Type)
	}
	return r, err
}

// sameRecord says whether two API records have the same name, type and data
// (and TTL, when withTTL is set).
func sameRecord(a, b apiRecord, withTTL bool) bool {
	if !strings.EqualFold(a.Hostname, b.Hostname) || a.Type != b.Type {
		return false
	}
	if withTTL && a.TTL != b.TTL {
		return false
	}
	switch a.Type {
	case "A", "AAAA":
		ia, ea := netip.ParseAddr(a.IP)
		ib, eb := netip.ParseAddr(b.IP)
		return ea == nil && eb == nil && ia == ib
	case "TXT":
		return a.Text == b.Text
	case "CAA":
		return num(a.Flags) == num(b.Flags) && strings.EqualFold(a.Tag, b.Tag) && a.Value == b.Value
	case "DS":
		return num(a.KeyTag) == num(b.KeyTag) && num(a.Algorithm) == num(b.Algorithm) &&
			num(a.DigestType) == num(b.DigestType) && strings.EqualFold(a.Digest, b.Digest)
	}
	return strings.EqualFold(strings.TrimSuffix(a.Target, "."), strings.TrimSuffix(b.Target, ".")) &&
		num(a.Priority) == num(b.Priority) && num(a.Weight) == num(b.Weight) &&
		num(a.Port) == num(b.Port) && sameParams(a.Params, b.Params)
}

// sameParams compares HTTPS/SVCB parameters by meaning: NameOcean stores them
// in RFC 9460 key order, libdns writes them in its own order.
func sameParams(a, b string) bool {
	if a == b {
		return true
	}
	pa, ea := libdns.ParseSvcParams(a)
	pb, eb := libdns.ParseSvcParams(b)
	if ea != nil || eb != nil {
		return false
	}
	if len(pa) != len(pb) {
		return false
	}
	for k, va := range pa {
		vb, ok := pb[k]
		if !ok || strings.Join(va, ",") != strings.Join(vb, ",") {
			return false
		}
	}
	return true
}
