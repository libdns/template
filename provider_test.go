package namesilo

import (
	"context"
	"os"
	"testing"

	"github.com/libdns/libdns"
)

var (
	APIToken = os.Getenv("LIBDNS_NAMESILO_TOKEN")
	zone     = os.Getenv("LIBDNS_NAMESILO_ZONE")
)

var (
	record0ID = ""
	record1ID = ""
	record2ID = ""
)

func TestAppendRecords(t *testing.T) {

	provider := Provider{APIToken: APIToken}

	ctx := context.Background()

	newRecords := []libdns.Record{
		{
			Type:  "CNAME",
			Name:  "test898008",
			Value: "wikipedia.com",
		},
		{
			Type:  "CNAME",
			Name:  "test289808",
			Value: "wikipedia.com",
		},
	}

	records, err := provider.AppendRecords(ctx, zone, newRecords)
	if err != nil {
		t.Errorf("%v", err)
	}

	if len(newRecords) != len(records) {
		t.Errorf("Number of appended records does not match number of records")
	}

	record0ID = records[0].ID
	record1ID = records[1].ID
}

func TestGetRecords(t *testing.T) {

	provider := Provider{APIToken: APIToken}

	ctx := context.Background()

	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Errorf("%v", err)
	}

	if len(records) == 0 {
		t.Errorf("No records")
	}
}

func TestSetRecords(t *testing.T) {
	provider := Provider{APIToken: APIToken}

	ctx := context.Background()

	changedRecords := []libdns.Record{
		{
			Type:  "CNAME",
			Name:  "test652753",
			Value: "wikipedia.com",
		},
		{
			ID:    record1ID,
			Type:  "CNAME",
			Name:  "test289808",
			Value: "google.com",
		},
	}

	records, err := provider.SetRecords(ctx, zone, changedRecords)
	if err != nil {
		t.Fatalf("appending records failed: %v", err)
	}

	if len(changedRecords) != len(records) {
		t.Fatalf("Number of appended records does not match number of records")
	}

	record1ID = records[0].ID
	record2ID = records[1].ID
}

func TestDeleteRecords(t *testing.T) {

	provider := Provider{APIToken: APIToken}

	ctx := context.Background()

	deletedRecords := []libdns.Record{
		{
			ID: record0ID,
		},
		{
			ID: record1ID,
		},
		{
			ID: record2ID,
		},
	}

	records, err := provider.DeleteRecords(ctx, zone, deletedRecords)
	if err != nil {
		t.Errorf("deleting records failed: %v", err)
	}

	if len(deletedRecords) != len(records) {
		t.Errorf("Number of deleted records does not match number of records")
	}
}
