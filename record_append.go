package provider

import (
	"context"
	"sync"

	"github.com/libdns/libdns"
)

// AppendRecords appends new records to the change list performing validation.
//
// The assumption is that when the full list is returned to the provider, the
// provider will handle any necessary validation and return an error if any
// issues are found.
func AppendRecords(ctx context.Context, mutex sync.Locker, client Client, zone string, records []libdns.Record) ([]libdns.Record, error) {

	if unlock := lock(mutex); unlock != nil {
		defer unlock()
	}

	existing, err := GetRecords(ctx, nil, client, zone)

	if err != nil {
		return nil, err
	}

	var change = make(ChangeList, 0, len(existing)+len(records))

	for _, record := range RecordIterator(&existing) {
		change = append(change, &ChangeRecord{record: &record, state: NoChange})
	}

	for _, record := range RecordIterator(&records) {
		change = append(change, &ChangeRecord{record: &record, state: Create})
	}

	items, err := client.SetDNSList(ctx, zone, change)

	if err != nil {
		return nil, err
	}

	if nil == items {
		items, err = GetRecords(ctx, nil, client, zone)

		if err != nil {
			return nil, err
		}
	}

	var ret = make([]libdns.Record, 0)

	for origin, record := range RecordIterator(&items) {
		if false == IsInList(&record, &existing) {
			ret = append(ret, *origin)
		}
	}

	return ret, nil
}
