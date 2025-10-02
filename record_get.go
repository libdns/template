package provider

import (
	"context"
	"sync"

	"github.com/libdns/libdns"
)

func GetRecords(ctx context.Context, mutex sync.Locker, client Client, zone string) ([]libdns.Record, error) {

	if unlock := rlock(mutex); nil != unlock {
		defer unlock()
	}

	list, err := client.GetDNSList(ctx, zone)

	if err != nil {
		return nil, err
	}

	type recordParser interface {
		Parse() (libdns.Record, error)
	}

	for i, c := 0, len(list); i < c; i++ {
		if v, ok := list[i].(recordParser); ok {
			x, err := v.Parse()

			if err != nil {
				return nil, err
			}

			list[i] = x
		}
	}

	return list, nil
}
