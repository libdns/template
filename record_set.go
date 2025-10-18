package provider

import (
	"context"
	"sync"

	"github.com/libdns/libdns"
)

// SetRecords updates existing records by marking them as either NoChange or Delete
// based on the given input, and appends the input records with state Create.
// This ensures compliance with the libdns contract and produces the expected results.
//
// Example provided by the contract can be found here:
// https://github.com/libdns/libdns/blob/master/libdns.go#L182-L216
func SetRecords(ctx context.Context, mutex sync.Locker, client Client, zone string, records []libdns.Record) ([]libdns.Record, error) {

	var unlock = lock(mutex)
	var ret = make([]libdns.Record, 0)

	if nil != unlock {
		defer unlock()
	}

	existing, err := GetRecords(ctx, nil, client, zone)

	if err != nil {
		return nil, err
	}

	var change = make(ChangeList, 0)

	for _, record := range RecordIterator(&existing) {

		var state = NoChange

		if found := lookupByNameAndType(&record, &records); found != nil {

			var rr = (*found).RR()

			// only mark as delete when differs
			if rr.Data != record.Data || rr.TTL != record.TTL {
				state = Delete
			}
		}

		change = append(change, &ChangeRecord{record: &record, state: state})
	}

	for _, item := range RecordIterator(&records) {

		if IsInList(&item, &existing, true) {
			continue
		}

		change = append(change, &ChangeRecord{record: &item, state: Create})
	}

	if len(change) == 0 {
		return ret, nil
	}

	curr, err := client.SetDNSList(ctx, zone, change)

	if err != nil {
		return nil, err
	}

	if nil != unlock {
		unlock()
	}

	if unlock := rlock(mutex); nil != unlock {
		defer unlock()
	}

	if nil == curr {
		curr, err = GetRecords(ctx, nil, client, zone)

		if err != nil {
			return nil, err
		}
	}

	for x, record := range RecordIterator(&curr) {
		if false == IsInList(&record, &existing, true) && nil != lookupByNameAndType(&record, &records) {
			ret = append(ret, *x)
		}
	}

	return ret, nil
}
