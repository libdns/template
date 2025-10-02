# Abstract Provider for `libdns`

This package helps reduce duplicated and fragmented code for different DNS providers that support replacing the **entire DNS zone file**.

It implements the basic logic for the following `libdns` interfaces:

- `RecordGetter`
- `RecordAppender`
- `RecordSetter`
- `RecordDeleter`
- `ZoneLister`

By doing so, the only thing you need to implement is a `client` that can get and set zone files.  
As a result, we should see more consistent providers since this package ensures all logic required by the contracts is handled and maintained in a single place.

---

## Client Interface

To create a `Provider`, you need a [client](client.go) that implements these methods:

```
GetDNSList(ctx context.Context, domain string) ([]libdns.Record, error)
SetDNSList(ctx context.Context, domain string, records []*libdns.RR) error
```

## Example Provider

An example implementation could look like this:

```go
type Provider struct {
    client Client
    mutex  sync.RWMutex
}

func (p *Provider) getClient() Client {
    if p.client == nil {
        // initialize client...
    }
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
## Test Provider

This library also has a test helper which you can use to test your implementation [read here more info](test/README.md) about this.