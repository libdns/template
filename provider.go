// Package dinahosting implements a DNS record management client compatible
// with the libdns interfaces for Dinahosting (https://es.dinahosting.com/api).
package libdns_dinahosting

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
// Full endpoint: https://dinahosting.com/special/api.php?AUTH_USER=user&AUTH_PWD=pass&domain=example.com&responseType=json&command=Domain_Zone_GetAll
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
//
// API docs: https://es.dinahosting.com/api/documentation
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {

	endpoint, err := url.Parse(endpointBase)
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Add("AUTH_USER", p.Username)
	params.Add("AUTH_PWD", p.Password)
	params.Add("domain", strings.TrimSuffix(zone, "."))
	params.Add("responseType", "json")

	client := &http.Client{Timeout: 10 * time.Second}

	var response struct {
		TrID         string `json:"trId,omitempty"`
		ResponseCode int16  `json:"responseCode,omitempty"`
		Message      string `json:"message,omitempty"`
		Data         string `json:"data,omitempty"`
		Command      string `json:"command,omitempty"`
	}

	var results []libdns.Record

	// Each recordy type require a different command action as a param
	for _, record := range records {

		// Check if record type is supported/implemented
		if record.Type != "TXT" && record.Type != "A" {
			return nil, fmt.Errorf("record type %s is not supported or not implemented yet", record.Type)
		}

		// TXT record
		if record.Type == "TXT" {
			params.Add("command", "Domain_Zone_AddTypeTXT")
			params.Add("hostname", record.Name)
			params.Add("text", record.Value)
			endpoint.RawQuery = params.Encode()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
			if err != nil {
				return nil, err
			}

			r, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			defer r.Body.Close()

			json.NewDecoder(r.Body).Decode(&response)

			if response.Message == "Success." {
				results = append(results, record)
			} else {
				return nil, fmt.Errorf("could not create TXT record. Error on API request")
			}
		}
		// A record
		if record.Type == "A" {
			params.Add("command", "Domain_Zone_AddTypeA")
			params.Add("hostname", record.Name)
			params.Add("text", record.Value)
			endpoint.RawQuery = params.Encode()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
			if err != nil {
				return nil, err
			}

			r, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			defer r.Body.Close()

			json.NewDecoder(r.Body).Decode(&response)

			if response.Message == "Sucess" {
				results = append(results, record)
			} else {
				return nil, fmt.Errorf("could not create A record. Error on API request")
			}
		}
	}
	return results, nil
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
