// Package ipv64 implements a DNS record management client compatible
// with the libdns interfaces for IPV64.net.
package ipv64

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with IPV64.net.
type Provider struct {
	APIToken string `json:"api_token,omitempty"`
}

// ipv64 API request structure
type ipv64Request struct {
	Hostname string `json:"hostname"`
	Type     string `json:"type"`
	Value    string `json:"value"`
}

// ipv64 API response structure
type ipv64Response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// AppendRecords creates TXT records for ACME DNS-01 challenge
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	for _, rec := range records {
		if rec.Type == "TXT" {
			err := p.setTXT(zone, rec.Value)
			if err != nil {
				return nil, err
			}
		}
	}
	return records, nil
}

// DeleteRecords removes TXT records for ACME DNS-01 challenge
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	for _, rec := range records {
		if rec.Type == "TXT" {
			err := p.deleteTXT(zone, rec.Value)
			if err != nil {
				return nil, err
			}
		}
	}
	return records, nil
}

// Set TXT record via ipv64 API
func (p *Provider) setTXT(zone string, value string) error {
	reqBody := ipv64Request{
		Hostname: zone,
		Type:     "TXT",
		Value:    value,
	}
	return p.callAPI("https://ipv64.net/api/dns/set", reqBody)
}

// Delete TXT record via ipv64 API
func (p *Provider) deleteTXT(zone string, value string) error {
	reqBody := ipv64Request{
		Hostname: zone,
		Type:     "TXT",
		Value:    value,
	}
	return p.callAPI("https://ipv64.net/api/dns/delete", reqBody)
}

// Generic API caller
func (p *Provider) callAPI(url string, body ipv64Request) error {
	jsonData, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+p.APIToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("ipv64 API error: %s", resp.Status)
	}

	return nil
}
