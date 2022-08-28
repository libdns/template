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

type command string

// API commands as per the spec
const (
	domain_Zone_GetAll        command = "Domain_Zone_GetAll"
	domain_Zone_AddTypeA      command = "Domain_Zone_AddTypeA"
	domain_Zone_DeleteTypeA   command = "Domain_Zone_DeleteTypeA"
	domain_Zone_AddTypeTXT    command = "Domain_Zone_AddTypeTXT"
	domain_Zone_DeleteTypeTXT command = "Domain_Zone_DeleteTypeTXT"
)

// Provider facilitates DNS record manipulation with Dinahosting.
type Provider struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// Struct for parsing API responses (not all fields will be used for any given response)
type dinaResponse struct {
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

// GetRecords lists all the records in the zone.
//
// API docs: https://es.dinahosting.com/api/documentation
//
// Full endpoint: https://dinahosting.com/special/api.php?AUTH_USER=user&AUTH_PWD=pass&domain=example.com&responseType=json&command=Domain_Zone_GetAll
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {

	endpoint, err := p.buildQuery(zone, domain_Zone_GetAll)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	r, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var response dinaResponse
	if err := json.NewDecoder(r.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("API response parsing failed: %s", err)
	}

	if response.Message != "Success." {
		return nil, fmt.Errorf("could retrieve records. Dinahosting API error code: %d", response.ResponseCode)
	}

	var records []libdns.Record

	// API response is not consistent with record value naming
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

	if len(records) == 0 {
		return nil, fmt.Errorf("empty input Record list")
	}

	client := &http.Client{Timeout: 10 * time.Second}

	var response dinaResponse
	var results []libdns.Record

	// Each record type require a different command action as a param
	for _, record := range records {
		// Check if record type is supported/implemented
		if record.Type != "TXT" && record.Type != "A" {
			return nil, fmt.Errorf("creating %s records is not supported or not implemented yet", record.Type)
		}

		var endpoint *url.URL
		var err error
		// TXT record
		if record.Type == "TXT" {
			endpoint, err = p.buildQueryWithRecord(zone, domain_Zone_AddTypeTXT, record)
			if err != nil {
				return nil, err
			}
		} else if record.Type == "A" {
			endpoint, err = p.buildQueryWithRecord(zone, domain_Zone_AddTypeA, record)
			if err != nil {
				return nil, err
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return nil, err
		}

		r, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer r.Body.Close()

		if err := json.NewDecoder(r.Body).Decode(&response); err != nil {
			return nil, fmt.Errorf("API response parsing failed: %s", err)
		}

		if response.Message == "Success." {
			results = append(results, record)
		} else {
			return nil, fmt.Errorf("could not create %s record. Dinahosting API error code: %d", record.Type, response.ResponseCode)
		}
	}

	return results, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
//
// API docs: https://es.dinahosting.com/api/documentation
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {

	if len(records) == 0 {
		return nil, fmt.Errorf("empty input Record list")
	}

	// Get all records for the zone, needed to check for existing records
	existingRecords, err := p.GetRecords(ctx, zone)
	if err != nil {
		return nil, err
	}
	var toDelete []libdns.Record
	var results []libdns.Record
	for _, record := range records {
		saved := 0
		for _, existingRecord := range existingRecords {
			// If record already exist we need to delete it and create it again with the new value
			// as API does not have update
			if saved == 0 {
				if record.Name == existingRecord.Name && record.Type == existingRecord.Type && record.Value != existingRecord.Value {
					toDelete = append(toDelete, existingRecord)
					results = append(results, record)
					saved = 1
				} else if record.Name == existingRecord.Name && record.Type == existingRecord.Type && record.Value == existingRecord.Value {
					break
				} else {
					results = append(results, record)
					saved = 1
				}
			}
		}
	}

	if len(toDelete) > 0 {
		if _, err := p.DeleteRecords(ctx, zone, toDelete); err != nil {
			return nil, err
		}
	}
	if _, err := p.AppendRecords(ctx, zone, results); err != nil {
		return nil, err
	}

	return results, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
//
// API docs: https://es.dinahosting.com/api/documentation
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {

	client := &http.Client{Timeout: 10 * time.Second}

	var response dinaResponse
	var results []libdns.Record

	for _, record := range records {
		// Check if record type is supported/implemented
		if record.Type != "TXT" && record.Type != "A" {
			return nil, fmt.Errorf("deleting record type %s is not supported or not implemented yet", record.Type)
		}

		var endpoint *url.URL
		var err error
		// Delete TXT record
		if record.Type == "TXT" {
			endpoint, err = p.buildQueryWithRecord(zone, domain_Zone_DeleteTypeTXT, record)
			if err != nil {
				return nil, err
			}
			// Delete A record
		} else if record.Type == "A" {
			endpoint, err = p.buildQueryWithRecord(zone, domain_Zone_DeleteTypeA, record)
			if err != nil {
				return nil, err
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return nil, err
		}

		r, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer r.Body.Close()

		if err := json.NewDecoder(r.Body).Decode(&response); err != nil {
			return nil, fmt.Errorf("API response parsing failed: %s", err)
		}

		if response.Message == "Success." {
			results = append(results, record)
		} else {
			return nil, fmt.Errorf("deletion of %s record failed, Dinahosting API error code: %d", record.Type, response.ResponseCode)
		}
	}
	return results, nil
}

// Build the api endpoint string with the default values, if Domain_Zone_GetAll
// command is present, also include it.
func (p *Provider) buildQuery(zone string, command command) (*url.URL, error) {

	endpoint, err := url.Parse(endpointBase)
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Add("AUTH_USER", p.Username)
	params.Add("AUTH_PWD", p.Password)
	params.Add("domain", strings.TrimSuffix(zone, "."))
	params.Add("responseType", "json")

	if command == domain_Zone_GetAll {
		params.Add("command", "Domain_Zone_GetAll")
	}

	endpoint.RawQuery = params.Encode()
	return endpoint, nil

}
func (p *Provider) buildQueryWithRecord(zone string, command command, record libdns.Record) (*url.URL, error) {
	endpoint, err := p.buildQuery(zone, command)
	if err != nil {
		return nil, err
	}
	params := endpoint.Query()
	if command == domain_Zone_AddTypeTXT {
		params.Add("command", string(domain_Zone_AddTypeTXT))
		params.Add("hostname", record.Name)
		params.Add("text", record.Value)
	} else if command == domain_Zone_AddTypeA {
		params.Add("command", "Domain_Zone_AddTypeA")
		params.Add("hostname", record.Name)
		params.Add("ip", record.Value)
	} else if command == domain_Zone_DeleteTypeTXT {
		params.Add("command", "Domain_Zone_DeleteTypeTXT")
		params.Add("hostname", record.Name)
		params.Add("value", record.Value)
	} else if command == domain_Zone_DeleteTypeA {
		params.Add("command", "Domain_Zone_DeleteTypeA")
		params.Add("hostname", record.Name)
		params.Add("ip", record.Value)
	}
	endpoint.RawQuery = params.Encode()
	return endpoint, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
