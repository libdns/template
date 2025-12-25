// Package ipv64 implements a DNS record management client compatible
// with the libdns interfaces for IPV64.net. 
package ipv64

import ( 
	"context"
	"fmt" 
	"net/http" 
	"bytes" 
	"encoding/json" 

	"github.com/libdns/libdns" 
)

// Provider facilitates DNS record manipulation with <TODO: PROVIDER NAME>.
type Provider struct { 
	APIToken string `json:"api_token,omitempty"` 
}

// Struktur für ipv64 API-Requests
type ipv64Request struct { 
	Hostname string `json:"hostname"` 
	Type string `json:"type"` 
	Value string `json:"value"` 
}

// Struktur für ipv64 API-Responses 
type ipv64Response struct { 
	Status string `json:"status"` 
	Message string `json:"message"` 
}

// TXT-Record setzen 
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) { 
	for _, rec := range records { 
		if rec.Type == "TXT" { 
			err := p.setTXT(zone, rec.Value) if 
			err != nil { 
				return nil, err 
			} 
		} 
	} 
	return records, nil 
}

// ipv64 TXT setzen 
func (p *Provider) setTXT(zone string, value string) error { 
	reqBody := ipv64Request{ 
		Hostname: zone, 
		Type: "TXT", 
		Value: value, 
	} 
	
	return p.callAPI("https://ipv64.net/api/dns/set", reqBody) 
}

// ipv64 TXT löschen 
func (p *Provider) deleteTXT(zone string, value string) error { 
	reqBody := ipv64Request{ 
		Hostname: zone, 
		Type: "TXT", 
		Value: value, 
	} 
	
	return p.callAPI("https://ipv64.net/api/dns/delete", reqBody) 
}

// API-Call
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
