mittwald mStudio for [`libdns`](https://github.com/libdns/libdns)
=======================

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/libdns/mittwald)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for the DNS of [mittwald mStudio](https://studio.mittwald.de), allowing you to manage DNS records of domains in mStudio projects.

## Configuration

| Field | JSON | Description |
|---|---|---|
| `APIToken` | `api_token` | An mStudio API token of a user with access to the projects of the domains |

The provider finds a domain in the projects the token's user can access; no project ID is needed.

```go
p := &mittwald.Provider{APIToken: os.Getenv("MITTWALD_API_TOKEN")}
recs, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{
	libdns.TXT{Name: "_acme-challenge", Text: "token"},
})
```

## Caveats

- **One zone per name.** mStudio stores every name as its own zone. The provider creates the zone of a name when a record is added to it and keeps it when its records are removed: a new zone takes a while until the nameservers serve it, and names like `_acme-challenge` are used again. For ACME DNS challenges, allow for a longer propagation timeout the first time a name is used.
- **One set per type.** A name holds one set per type: A and AAAA together, CNAME, MX, TXT, SRV and CAA. All records of a set share one TTL. A TTL of 0 means mStudio's "auto" (served as 60 seconds); other TTLs must be between 60 seconds and one day.
- **Supported types:** A, AAAA, CNAME, MX, TXT, SRV and CAA. Wildcard names (`*`) are not supported by mStudio.
- **Managed records.** mStudio sets the addresses of a name connected to an ingress and the mail exchangers of its mail service. `GetRecords` does not return them; writing A, AAAA or MX records to such a name replaces them.
- **Not atomic.** A call that fails may have applied part of its records.
- **Rate limit.** mStudio allows an API user a number of requests per period. When the limit is used up, requests wait for its reset, as long as the context allows.

## License

MIT
