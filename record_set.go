package provider

import (
	"context"
	"sync"

	"github.com/libdns/libdns"
)

func SetRecords(ctx context.Context, mutex sync.Locker, client Client, zone string, records []libdns.Record) ([]libdns.Record, error) {

	var unlock = lock(mutex)

	if nil != unlock {
		defer unlock()
	}

	existing, err := GetRecords(ctx, nil, client, zone)

	if err != nil {
		return nil, err
	}

	var set = make([]*libdns.RR, 0)
	var ret = make([]libdns.Record, 0)

	for _, record := range RecordIterator(&existing) {
		if nil == lookupByNameAndType(&record, &records) {
			set = append(set, &record)
		}
	}

	for _, item := range RecordIterator(&records) {
		set = append(set, &item)
	}

	if err := client.SetDNSList(ctx, zone, set); err != nil {
		return nil, err
	}

	if nil != unlock {
		unlock()
	}

	if unlock := rlock(mutex); nil != unlock {
		defer unlock()
	}

	curr, err := GetRecords(ctx, nil, client, zone)

	if err != nil {
		return nil, err
	}

	for x, record := range RecordIterator(&curr) {
		if false == IsInList(&record, &existing) && nil != lookupByNameAndType(&record, &records) {
			ret = append(ret, *x)
		}
	}

	return ret, nil
}
