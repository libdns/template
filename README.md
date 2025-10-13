## Abstract Provider for `libdns`

This package helps reduce duplicated and fragmented code across different DNS providers by implementing the core logic for the main `libdns` interfaces:

* `RecordGetter`
* `RecordAppender`
* `RecordSetter`
* `RecordDeleter`
* `ZoneLister`

As defined in the [libdns contracts](https://github.com/libdns/libdns/blob/master/libdns.go).

It works on the principle that this *provider helper* fetches all records for a zone, generates a change list, and passes that list to the `client` to apply.

By doing so, the only thing you need to implement is a [`client`](client.go).
This approach allows faster development of new providers and ensures more consistent behavior, since all contract logic is handled and maintained in one central place.


---

## Client

A client implementation should follow this interface signature:

```go
GetDNSList(ctx context.Context, domain string) ([]libdns.Record, error)
SetDNSList(ctx context.Context, domain string, change ChangeList) ([]libdns.Record, error)
```

A simple implementation could look like this:

```go
func (c *client) create(ctx context.Context, domain string, record *libdns.RR) error {
	// ...
	return nil
}

func (c *client) remove(ctx context.Context, domain string, record *libdns.RR) error {
	// ...
	return nil
}

func (c *client) SetDNSList(ctx context.Context, domain string, change ChangeList) ([]libdns.Record, error) {

	for record := range change.Iterate(provider.Delete) {
		if err := c.remove(ctx, domain, record); err != nil {
			return nil, err
		}
	}

	for record := range change.Iterate(provider.Create) {
		if err := c.create(ctx, domain, record); err != nil {
			return nil, err
		}
	}

	return nil, nil
}
```

---

## Provider

Because Go doesn’t support class-level abstraction, this package provides helper functions that your provider can call directly:

```go
type Provider struct {
	client Client
	mutex  sync.RWMutex
}

func (p *Provider) getClient() Client {
	// initialize client...
	return p.client
}

func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return GetRecords(ctx, &p.mutex, p.getClient(), zone)
}

func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return AppendRecords(ctx, &p.mutex, p.getClient(), zone, recs)
}

func (p *Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return SetRecords(ctx, &p.mutex, p.getClient(), zone, recs)
}

func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return DeleteRecords(ctx, &p.mutex, p.getClient(), zone, recs)
}

var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
```

---

### Implemented Interfaces

| Interface               | Implementation Function           |
| ----------------------- | --------------------------------- |
| `libdns.RecordGetter`   | [GetRecords](record_get.go)       |
| `libdns.RecordAppender` | [AppendRecords](record_get.go)    |
| `libdns.RecordSetter`   | [SetRecords](record_set.go)       |
| `libdns.RecordDeleter`  | [DeleteRecords](record_delete.go) |
| `libdns.ZoneLister`     | [ListZones](zone_list.go)         |

---
