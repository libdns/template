package hosterby

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/libdns/libdns"
	"golang.org/x/net/idna"
)

// rrset is a record set as represented by the API.
type rrset struct {
	Name    string   `json:"name"`
	TTL     int      `json:"ttl"`
	Type    string   `json:"type"`
	Records []record `json:"records"`
}

// record is a single value of an rrset.
type record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

// writableTypes are the record types the API can write.
var writableTypes = map[string]bool{
	"A":     true,
	"AAAA":  true,
	"ALIAS": true,
	"CAA":   true,
	"CNAME": true,
	"MX":    true,
	"NS":    true,
	"SRV":   true,
	"TXT":   true,
}

const (
	// minTTL and maxTTL bound the TTLs accepted by the API. minTTL is also
	// used for a zero TTL, which libdns defines as "should not be cached".
	minTTL = 10 * time.Minute
	maxTTL = 7 * 24 * time.Hour

	// maxTXTChunk is the maximum length of a single character-string in a
	// TXT record (RFC 1035 §3.3.14).
	maxTXTChunk = 255
)

// normalizeZone returns the zone in lower-case ASCII with a trailing dot.
func normalizeZone(zone string) string {
	return toASCII(strings.ToLower(strings.TrimSuffix(zone, "."))) + "."
}

// toASCII converts internationalized domain names to Punycode. Names that
// can't be converted are returned as is.
func toASCII(name string) string {
	if ascii, err := idna.Punycode.ToASCII(name); err == nil {
		return ascii
	}
	return name
}

// absoluteName returns the lower-case FQDN, with a trailing dot, of a record
// name relative to the normalized zone.
func absoluteName(name, zone string) string {
	return strings.ToLower(libdns.AbsoluteName(name, zone))
}

// ttlSeconds converts a libdns TTL to seconds within the API range.
func ttlSeconds(ttl time.Duration) int {
	return int(min(max(ttl, minTTL), maxTTL) / time.Second)
}

// parseRecord converts a single value of set into a typed libdns record.
func parseRecord(set rrset, rec record, zone string) (libdns.Record, error) {
	data := rec.Content
	if set.Type == "TXT" {
		var err error
		if data, err = unquoteTXT(data); err != nil {
			return nil, err
		}
	}
	return libdns.RR{
		Name: libdns.RelativeName(set.Name, zone),
		Type: set.Type,
		TTL:  time.Duration(set.TTL) * time.Second,
		Data: data,
	}.Parse()
}

// withTTL returns rr as a typed record with the TTL of set.
func withTTL(rr libdns.RR, set *rrset) (libdns.Record, error) {
	rr.TTL = time.Duration(set.TTL) * time.Second
	return rr.Parse()
}

// canonicalData returns the record data in the canonical libdns form, so that
// equal values such as "2001:db8:0::1" and "2001:db8::1" compare equal.
func canonicalData(rr libdns.RR) string {
	rec, err := rr.Parse()
	if err != nil {
		return rr.Data
	}
	return rec.RR().Data
}

var txtEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

// quoteTXT encodes text as a sequence of quoted character-strings, splitting
// it into chunks of at most maxTXTChunk bytes without breaking valid UTF-8
// sequences.
func quoteTXT(text string) string {
	var chunks []string
	for {
		n := min(len(text), maxTXTChunk)
		if n < len(text) {
			// Split at the start of a character, if there is one in reach.
			for i := n; i > n-utf8.UTFMax; i-- {
				if utf8.RuneStart(text[i]) {
					n = i
					break
				}
			}
		}
		chunks = append(chunks, `"`+txtEscaper.Replace(text[:n])+`"`)
		text = text[n:]
		if text == "" {
			return strings.Join(chunks, " ")
		}
	}
}

// unquoteTXT decodes a sequence of quoted character-strings, as found in zone
// files, into a single string. Content that isn't quoted is returned as is.
func unquoteTXT(content string) (string, error) {
	s := strings.TrimSpace(content)
	if !strings.HasPrefix(s, `"`) {
		return content, nil
	}

	var sb strings.Builder
	for s != "" {
		if s[0] != '"' {
			return "", fmt.Errorf("invalid TXT content %q: expected quote", content)
		}
		i := 1
		for ; i < len(s) && s[i] != '"'; i++ {
			if s[i] != '\\' {
				sb.WriteByte(s[i])
				continue
			}
			i++
			if i == len(s) {
				break
			}
			// \DDD is the octet with the decimal value DDD (RFC 1035 §5.1).
			if d := s[i:min(i+3, len(s))]; len(d) == 3 && strings.Trim(d, "0123456789") == "" {
				n, _ := strconv.Atoi(d)
				if n > 255 {
					return "", fmt.Errorf(`invalid TXT content %q: escape \%s out of range`, content, d)
				}
				sb.WriteByte(byte(n))
				i += 2
				continue
			}
			sb.WriteByte(s[i])
		}
		if i >= len(s) {
			return "", fmt.Errorf("invalid TXT content %q: unterminated string", content)
		}
		s = strings.TrimLeft(s[i+1:], " \t")
	}
	return sb.String(), nil
}
