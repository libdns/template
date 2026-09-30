enum for [`libdns`](https://github.com/libdns/libdns)
=======================

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/libdns/enum)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for [enum DNS](https://enum.co), allowing you to manage DNS records.

## Configuration

| Field | JSON | Description |
|---|---|---|
| `APIKey` | `api_key` | API key of a service account with access to the project |
| `ProjectID` | `project_id` | ID of the project that owns the zones, e.g. `proj-01kmyy3t719crcnrrvk1mgyjd0` |

Create a service account and an API key with `enumctl` or in the enum console.

## Example

```go
provider := enum.Provider{
	APIKey:    os.Getenv("ENUM_API_KEY"),
	ProjectID: os.Getenv("ENUM_PROJECT_ID"),
}

records, err := provider.AppendRecords(ctx, "example.com.", []libdns.Record{
	libdns.TXT{Name: "_acme-challenge", Text: "token"},
})
```

## Caveats

- Supported record types: A, AAAA, CAA, CNAME, MX, NS, SRV and TXT.
- enum stores records as record sets (name, type) with one TTL. `AppendRecords` keeps the TTL of an existing set. `SetRecords` uses the TTL of the first record of each set.
- A TTL of 0 uses the per-type default (300s for A and AAAA, 86400s for NS, 3600s otherwise). Other TTLs must be at least 60s, or 3600s for NS.
- The apex NS records are managed by enum and cannot be changed.

## Testing

See [libdnstest](libdnstest/README.md) to run the libdns test suite against your own zone.
