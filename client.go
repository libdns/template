package provider

import (
	"context"

	"github.com/libdns/libdns"
)

type Domain interface {
	Name() string
}

type Client interface {
	// GetDNSList returns all DNS records available for the given zone.
	//
	// The returned records can be of the opaque RR type. If the provider supports
	// parsing, the records will be automatically parsed before being returned.
	GetDNSList(ctx context.Context, domain string) ([]libdns.Record, error)

	// SetDNSList processes a ChangeList and updates DNS records based on their state.
	//
	// This allows the client to focus only on handling the changes, while the provider
	// logic for appending, setting, and deleting records is centralized.
	//
	// Example: iterating through individual changes
	//
	//    // Remove records marked for deletion
	//    for remove := range change.Iterate(Delete) {
	//        // remove record
	//    }
	//
	//    // Create records marked for creation
	//    for create := range change.Iterate(Create) {
	//        // create record
	//    }
	//
	// Example: updating the whole zone at once
	//
	//    // Generate a filtered list of all changes
	//    updatedRecords := change.GetList()
	//
	//    // Use this list to update the entire zone file in a single call
	//    client.UpdateZone(ctx, domain, updatedRecords)
	//
	// Notes:
	//  - If the client API supports full-zone updates and returns the new record set,
	//    this can be returned. The provider uses this to validate records and skip
	//    extra API calls.
	//  - For clients that do not support full-zone updates or handle records individually,
	//    returning nil is fine.
	SetDNSList(ctx context.Context, domain string, change ChangeList) ([]libdns.Record, error)
}

type ZoneAwareClient interface {
	Client
	Domains(ctx context.Context) ([]Domain, error)
}
