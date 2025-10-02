package provider

import (
	"iter"
	"strings"

	"github.com/libdns/libdns"
)

func RecordIterator(records *[]libdns.Record) iter.Seq2[*libdns.Record, libdns.RR] {
	return func(yield func(*libdns.Record, libdns.RR) bool) {
		for _, record := range *records {
			if !yield(&record, record.RR()) {
				return
			}
		}
	}
}

func lookup(item *libdns.RR, records *[]libdns.Record, lookup func(a, b *libdns.RR) bool) *libdns.Record {
	next, stop := iter.Pull2(RecordIterator(records))

	defer stop()

	for {
		origin, check, ok := next()

		if !ok {
			return nil
		}

		if lookup(item, &check) {
			return origin
		}
	}
}

func lookupByNameAndType(item *libdns.RR, records *[]libdns.Record) *libdns.Record {
	return lookup(item, records, func(a, b *libdns.RR) bool {
		return strings.EqualFold(a.Name, b.Name) && a.Type == b.Type
	})
}

func IsInList(item *libdns.RR, records *[]libdns.Record) bool {
	return nil != lookup(item, records, func(a, b *libdns.RR) bool {
		return strings.EqualFold(a.Name, b.Name) && a.Type == b.Type && a.Data == b.Data
	})
}

func isEligibleForRemoval(item *libdns.RR, records *[]libdns.Record) bool {
	return nil != lookup(item, records, func(a, b *libdns.RR) bool {
		return strings.EqualFold(a.Name, b.Name) && (b.Type == "" || a.Type == b.Type) && (b.Data == "" || a.Data == b.Data) && (b.TTL == 0 || a.TTL == b.TTL)
	})
}
