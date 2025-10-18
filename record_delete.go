package provider

import (
	"context"
	"sync"

	"github.com/libdns/libdns"
)

// DeleteRecords marks the input records for deletion when they exactly match
// or partially match existing records, following the rules defined in the
// libdns contract.
//
// For more details, see:
// https://github.com/libdns/libdns/blob/master/libdns.go#L228C1-L237C43
func DeleteRecords(ctx context.Context, mutex sync.Locker, client Client, zone string, deletes []libdns.Record) ([]libdns.Record, error) {

	var unlock = lock(mutex)

	if nil != unlock {
		defer unlock()
	}

	records, err := GetRecords(ctx, nil, client, zone)

	if err != nil {
		return nil, err
	}

	var change = make(ChangeList, 0)
	var states ChangeState

	for _, record := range RecordIterator(&records) {
		var state = NoChange

		if isEligibleForRemoval(&record, &deletes) {
			state = Delete
		}

		states = states | state
		change = append(change, &ChangeRecord{record: &record, state: state})
	}

	if Delete != (Delete & states) {
		return []libdns.Record{}, nil
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

	var removed = make([]libdns.Record, 0)

	for origin, record := range RecordIterator(&records) {
		if false == IsInList(&record, &curr, false) && isEligibleForRemoval(&record, &deletes) {
			removed = append(removed, *origin)
		}
	}

	return removed, nil
}
