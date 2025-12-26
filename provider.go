package ipv64

import (
	"github.com/libdns/libdns"

	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type Provider struct {
	APIToken string `json:"api_token,omitempty"`
}

type ipv64Request struct {
	Hostname string `json:"hostname"`
	Type     string `json:"type"`
	Value    string `json:"value"`
}

func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	for i, rec := range records {
		if rec.Type != libdns.RecordTypeTXT {
			continue
		}

		if err := p.setTXT(rec.Name, rec.Value); err != nil {
			return nil, err
		}

		records[i].ID = rec.Name + ":" + rec.Value
	}
	return records, nil
}

func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	for _, rec := range records {
		if rec.Type != libdns.RecordTypeTXT {
			continue
		}

		if err := p.deleteTXT(rec.Name, rec.Value); err != nil {
			return nil, err
		}
	}
	return records, nil
}

func (p *Provider) setTXT(name, value string) error {
	body := ipv64Request{
		Hostname: name,
		Type:     "TXT",
		Value:    value,
	}
	return p.callAPI("https://ipv64.net/api/dns/set", body)
}

func (p *Provider) deleteTXT(name, value string) error {
	body := ipv64Request{
		Hostname: name,
		Type:     "TXT",
		Value:    value,
	}
	return p.callAPI("https://ipv64.net/api/dns/delete", body)
}

func (p *Provider) callAPI(url string, body ipv64Request) error {
	jsonData, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+p.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("ipv64 API error: %s", resp.Status)
	}

	return nil
}
