package provider

import (
	"context"
	"sync"

	"github.com/libdns/libdns"
)

func DeleteRecords(ctx context.Context, mutex sync.Locker, client Client, zone string, deletes []libdns.Record) ([]libdns.Record, error) {

	var unlock = lock(mutex)

	if nil != unlock {
		defer unlock()
	}

	records, err := GetRecords(ctx, nil, client, zone)

	if err != nil {
		return nil, err
	}

	var items = make([]*libdns.RR, 0)
	var removed = make([]libdns.Record, 0)

	for _, record := range RecordIterator(&records) {
		if false == isEligibleForRemoval(&record, &deletes) {
			items = append(items, &record)
		}
	}

	if len(records) == len(items) {
		return []libdns.Record{}, nil
	}

	if err := client.SetDNSList(ctx, zone, items); err != nil {
		return nil, err
	}

	if nil != unlock {
		unlock()
	}

	if unlock := rlock(mutex); nil != unlock {
		defer unlock()
	}

	current, err := GetRecords(ctx, nil, client, zone)

	if err != nil {
		return nil, err
	}

	for origin, record := range RecordIterator(&records) {
		if false == IsInList(&record, &current) && isEligibleForRemoval(&record, &deletes) {
			removed = append(removed, *origin)
		}
	}

	return removed, nil
}
