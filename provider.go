// Package dinahosting implements a DNS record management client compatible
// with the libdns interfaces for Dinahosting (https://es.dinahosting.com/api).
package dinahosting

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

const (
	endpointBase = "https://dinahosting.com/special/api.php"
)

// Provider facilitates DNS record manipulation with Dinahosting.
type Provider struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// GetRecords lists all the records in the zone.
//
// API docs: https://es.dinahosting.com/api/documentation
//
// Full endpoint; https://dinahosting.com/special/api.php?AUTH_USER=user&AUTH_PWD=pass&domain=example.com&responseType=json&command=Domain_Zone_GetAll
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	endpoint, err := url.Parse(endpointBase)
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Add("AUTH_USER", p.Username)
	params.Add("AUTH_PWD", p.Password)
	params.Add("domain", strings.TrimSuffix(zone, "."))
	params.Add("responseType", "json")
	params.Add("command", "Domain_Zone_GetAll")
	endpoint.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}

	var response struct {
		TrID         string `json:"trId,omitempty"`
		ResponseCode int16  `json:"responseCode,omitempty"`
		Message      string `json:"message,omitempty"`
		Records      []struct {
			RecordType          string `json:"type,omitempty"`
			Hostname            string `json:"hostname,omitempty"`
			DestinationHostname string `json:"destinationHostname,omitempty"`
			Ip                  string `json:"ip,omitempty"`
			Address             string `json:"address,omitempty"`
			Text                string `json:"text,omitempty"`
		} `json:"data,omitempty"`
		Command string `json:"command,omitempty"`
	}

	r, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	json.NewDecoder(r.Body).Decode(&response)

	var records []libdns.Record

	for _, record := range response.Records {
		var value string
		if record.DestinationHostname != "" {
			value = record.DestinationHostname
		} else if record.Ip != "" {
			value = record.Ip
		} else if record.Address != "" {
			value = record.Address
		} else if record.Text != "" {
			value = record.Text
		}

		records = append(records, libdns.Record{
			Type:  record.RecordType,
			Name:  record.Hostname,
			Value: value,
		})

	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return nil, fmt.Errorf("TODO: not implemented")
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return nil, fmt.Errorf("TODO: not implemented")
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return nil, fmt.Errorf("TODO: not implemented")
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
