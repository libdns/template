NameOcean for [`libdns`](https://github.com/libdns/libdns)
=======================

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/libdns/nameocean)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for [NameOcean DNS](https://nameocean.net/dns/) (ns1–ns4.nameocean.net), using NameOcean's [API v1](https://nameocean.net/developers/api/). It lets Go programs, such as [Caddy](https://github.com/caddy-dns/nameocean), manage records in zones hosted at NameOcean, for example to solve ACME DNS-01 challenges.

## Configuration

```go
p := &nameocean.Provider{
	APIKey: "no_live_...", // or leave empty to use NAMEOCEAN_API_KEY
}
recs, err := p.GetRecords(ctx, "example.com.")
```

| Field | JSON | Description |
|---|---|---|
| `APIKey` | `api_key` | A NameOcean API key with the `dns:read` and `dns:write` scopes. Create one in the dashboard under [API](https://nameocean.net/dashboard/api/). A key can be limited to the zones it should touch and to source IP addresses. Defaults to the `NAMEOCEAN_API_KEY` environment variable. |
| `BaseURL` | `base_url` | API address. Default `https://nameocean.net/api/v1`. |
| `HTTPClient` | (none) | HTTP client for API calls. Default: 30 second timeout. |

The zone must be a DNS zone on the same NameOcean account.

## Caveats

- **TTLs:** NameOcean accepts 5m, 15m, 30m, 1h and 1d. Any other TTL is rounded to the closest of these (a tie goes to the shorter one); a zero TTL becomes 5m.
- **SetRecords is not atomic.** NameOcean's per-record API has no batch call. SetRecords adds the new records first and deletes the old ones of the same (name, type) afterwards, so a name keeps answering during the change, but an error part-way can leave some changes made. Records that already match are left alone.
- **Record types:** A, AAAA, CNAME, MX, TXT, SRV, CAA, NS, HTTPS and SVCB come back as the matching libdns structs; ALIAS (NameOcean's apex alias), PTR and DS as `libdns.RR`. NameOcean's HTTP redirect records are not DNS records and are not listed.
- Targets are returned fully qualified with a trailing dot; a target that is the zone itself is stored as `@` by NameOcean and returned as the zone's name.
- Retries: GET and DELETE are retried twice on connection errors, 429 and 5xx; POST is not, so a record is never added twice.

## Tests

`go test ./...` runs the unit tests against an in-memory fake of the API (it enforces the same uniqueness rules as NameOcean). To run against the real API (adds, changes and removes records under `libdns-test` and `_acme-challenge.libdns-test`, and checks the zone is as before):

```sh
NAMEOCEAN_API_KEY=... LIBDNS_NAMEOCEAN_TEST_ZONE=example.com. go test -run TestLive -v
```

The libdns test suite ([`libdnstest`](https://github.com/libdns/libdns/tree/master/libdnstest), libdns v1.2.0-alpha.1) passes ListZones, GetRecords, AppendRecords and DeleteRecords against a real zone, with every record type. Its SetRecords test fails only where it expects a 10 minute TTL back, because NameOcean rounds that to 5m.

