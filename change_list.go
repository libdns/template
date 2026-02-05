package provider

import (
	"iter"

	"github.com/libdns/libdns"
)

type ChangeState uint8

const (
	NoChange ChangeState = 1 << iota
	Delete
	Create
)

type ChangeRecord struct {
	record *libdns.RR
	state  ChangeState
}

type ChangeList interface {
	// Iterate wil return an iterator that returns records that
	// match the given state. For example, when called like
	// `Iterate(Delete)` will only return records marked for
	// removal. The ChangeState can be combined to iterate
	// multiple states like `Iterate(Delete|Create)` which
	// will return all records that are marked delete or
	// as created.
	Iterate(state ChangeState) iter.Seq[*libdns.RR]
	// Creates will return a slice of records that are
	// marked for creating
	Creates() []*libdns.RR
	// Deletes will return a slice of records that are
	// marked for deleting
	Deletes() []*libdns.RR
	// GetList will return a slice of records that
	// represents the new dns list which can be used
	// to update the whole set for a zone
	GetList() []*libdns.RR
	// Has wil check if this list has records for
	// given state
	Has(state ChangeState) bool
	// addRecord is not exported because the record
	// list is immutable
	addRecord(record *libdns.RR, state ChangeState)
}

type changes struct {
	records []*ChangeRecord
	state   ChangeState
}

func NewChangeList(size ...int) ChangeList {

	var records []*ChangeRecord

	switch len(size) {
	case 1:
		records = make([]*ChangeRecord, size[0])
	case 2:
		records = make([]*ChangeRecord, size[0], size[1])
	default:
		records = make([]*ChangeRecord, 0)
	}

	return &changes{
		records: records,
	}
}

func (c *changes) addRecord(record *libdns.RR, state ChangeState) {
	c.records = append(c.records, &ChangeRecord{record: record, state: state})
	c.state |= state
}

func (c *changes) Has(state ChangeState) bool {
	return 0 != (c.state & state)
}

func (c *changes) Iterate(state ChangeState) iter.Seq[*libdns.RR] {
	return func(yield func(*libdns.RR) bool) {
		for i, x := 0, len(c.records); i < x; i++ {
			if c.records[i].state == (c.records[i].state & state) {
				if false == yield(c.records[i].record) {
					return
				}
			}
		}
	}
}

func (c *changes) Creates() []*libdns.RR {
	return c.list(Create)
}

func (c *changes) Deletes() []*libdns.RR {
	return c.list(Delete)
}

func (c *changes) GetList() []*libdns.RR {
	return c.list(Create | NoChange)
}

func (c *changes) list(state ChangeState) []*libdns.RR {
	var items = make([]*libdns.RR, 0)

	for record := range c.Iterate(state) {
		items = append(items, record)
	}

	return items
}
