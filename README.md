hoster.by for [`libdns`](https://github.com/libdns/libdns)
=======================

[![Go Reference](https://pkg.go.dev/badge/github.com/libdns/hosterby.svg)](https://pkg.go.dev/github.com/libdns/hosterby)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for [hoster.by](https://hoster.by), allowing you to manage DNS records via the [hoster.by API](https://serviceapi.hoster.by/rest_api_docs.html).

## Authenticating

The provider needs the access key and secret key of an API service account, which can be generated in the hoster.by control panel under *hoster API* (see [the guide](https://hoster.by/help/hoster-api/kak-upravlyat-uslugami-pri-pomoshchi-hoster-api-zapusk-servisa-i-generatsiya-klyuchey/)).

hoster.by offers two kinds of keys:

- *Temporary* keys expire after at most six months and have to be regenerated before that.
- *Permanent* keys don't expire, but only work from a single static IPv4 address.

The keys need access to the DNS hosting service: listing the services, and listing, adding, changing and deleting the records of the types you intend to manage. For ACME DNS challenges, the TXT record permissions are sufficient.

The zone must be a domain with the hoster.by DNS hosting service on the same account.

## Example

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/libdns/hosterby"
	"github.com/libdns/libdns"
)

func main() {
	provider := &hosterby.Provider{
		AccessKey: "YOUR_ACCESS_KEY",
		SecretKey: "YOUR_SECRET_KEY",
	}

	records, err := provider.AppendRecords(context.Background(), "example.by.", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", TTL: 10 * time.Minute, Text: "token"},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(records)
}
```

## Configuration

| Field        | Description                                                  |
|--------------|--------------------------------------------------------------|
| `AccessKey`  | Access key of the API service account. Required.             |
| `SecretKey`  | Secret key of the API service account. Required.             |
| `BaseURL`    | API endpoint. Defaults to `https://serviceapi.hoster.by`.    |
| `HTTPClient` | Custom HTTP client. Defaults to a client with a 30s timeout. |

## Caveats

- The API manages record sets: all records with the same name and type are written together. Appending or deleting a record rewrites its record set. This is serialized within one `Provider` value, but not across clients.
- Each record set is written with a separate request, so a failed call may leave the record sets written before the failure changed.
- All records of a record set share one TTL, and appending keeps the existing TTL. TTLs are clamped to the API range of 10 minutes to 7 days, and records without a TTL get 10 minutes.
- Internationalized zones and names are handled in Punycode (e.g. `xn--80aaa.xn--90ais.`). At the time of writing, the API fails to return the records of internationalized zones (`dns_error_getting_records_data`), so they can't be managed yet.
- Disabled records are hidden from `GetRecords` and preserved by `AppendRecords` and `DeleteRecords`. Appending a disabled record enables it. `SetRecords` replaces them like any other record.
- Only A, AAAA, ALIAS, CAA, CNAME, MX, NS, SRV and TXT records can be written. `GetRecords` returns all types, including SOA. The API allows underscores only in TXT and SRV names, and ALIAS records only at the zone apex.

## Testing

Unit tests use an in-memory fake of the API:

```sh
go test ./...
```

The integration test uses the live API and covers all writable types. It creates records only below a random `libdns-test-*` name, with documentation IP addresses and `example.com` targets, and removes them afterwards. The keys need permissions to list services and to list, add, change and delete records of all types:

```sh
HOSTERBY_ACCESS_KEY=... HOSTERBY_SECRET_KEY=... HOSTERBY_TEST_ZONE=example.by go test -run Integration -v ./...
```

ALIAS records are accepted only at the zone apex, so the ALIAS test briefly changes how the zone resolves. It runs only with `HOSTERBY_TEST_APEX_ALIAS=1` and if the apex has no A, AAAA or ALIAS records.
