package nameocean

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const defaultBaseURL = "https://nameocean.net/api/v1"

// apiRecord is a record as NameOcean's API v1 reads and writes it
// (GET/POST /api/v1/dns/{zone}/records). Which fields are set depends on the type.
type apiRecord struct {
	ID         int64  `json:"id,omitempty"`
	Type       string `json:"type"`
	Hostname   string `json:"hostname"`
	TTL        string `json:"ttl,omitempty"`
	IP         string `json:"ip,omitempty"`
	Target     string `json:"target,omitempty"`
	Text       string `json:"text,omitempty"`
	Priority   *int   `json:"priority,omitempty"`
	Weight     *int   `json:"weight,omitempty"`
	Port       *int   `json:"port,omitempty"`
	Flags      *int   `json:"flags,omitempty"`
	Tag        string `json:"tag,omitempty"`
	Value      string `json:"value,omitempty"`
	Params     string `json:"params,omitempty"`
	KeyTag     *int   `json:"key_tag,omitempty"`
	Algorithm  *int   `json:"algorithm,omitempty"`
	DigestType *int   `json:"digest_type,omitempty"`
	Digest     string `json:"digest,omitempty"`
}

type apiError struct {
	Status int
	// {"error": "<message>", "code": "<identifier>", "field": "<input at fault>"}
	Body struct {
		Message string `json:"error"`
		Code    string `json:"code"`
		Field   string `json:"field"`
	}
	Raw string
}

func (e *apiError) Error() string {
	m := e.Body
	if m.Message == "" {
		return fmt.Sprintf("nameocean: HTTP %d: %s", e.Status, strings.TrimSpace(e.Raw))
	}
	s := fmt.Sprintf("nameocean: HTTP %d: %s", e.Status, m.Message)
	if m.Field != "" {
		s += " (field " + m.Field + ")"
	}
	return s
}

func (p *Provider) apiKey() string {
	if p.APIKey != "" {
		return p.APIKey
	}
	return os.Getenv("NAMEOCEAN_API_KEY")
}

func (p *Provider) baseURL() string {
	if p.BaseURL != "" {
		return strings.TrimSuffix(p.BaseURL, "/")
	}
	return defaultBaseURL
}

func (p *Provider) httpClient() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// apiZone turns a libdns zone ("example.com.") into the name the API uses ("example.com").
func apiZone(zone string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
}

// do sends one request, retrying connection errors, 429 and 5xx a couple of times
// (GET and DELETE only: a retried POST could add a record twice).
func (p *Provider) do(ctx context.Context, method, path string, in, out any) error {
	key := p.apiKey()
	if key == "" {
		return errors.New("nameocean: no API key (set Provider.APIKey or NAMEOCEAN_API_KEY)")
	}
	var payload []byte
	if in != nil {
		var err error
		if payload, err = json.Marshal(in); err != nil {
			return err
		}
	}
	retries := 0
	if method == http.MethodGet || method == http.MethodDelete {
		retries = 2
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, p.baseURL()+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "libdns-nameocean")
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := p.httpClient().Do(req)
		if err != nil {
			if attempt < retries && ctx.Err() == nil {
				if werr := wait(ctx, attempt); werr != nil {
					return werr
				}
				continue
			}
			return fmt.Errorf("nameocean: %s %s: %w", method, path, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && attempt < retries {
			if werr := wait(ctx, attempt); werr != nil {
				return werr
			}
			continue
		}
		if resp.StatusCode/100 != 2 {
			e := &apiError{Status: resp.StatusCode, Raw: string(body)}
			_ = json.Unmarshal(body, &e.Body)
			return e
		}
		if out != nil && len(body) > 0 {
			if err := json.Unmarshal(body, out); err != nil {
				return fmt.Errorf("nameocean: %s %s: decoding response: %w", method, path, err)
			}
		}
		return nil
	}
}

func wait(ctx context.Context, attempt int) error {
	t := time.NewTimer(time.Duration(attempt+1) * 500 * time.Millisecond)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (p *Provider) listRecords(ctx context.Context, zone string) ([]apiRecord, error) {
	var out struct {
		Records []apiRecord `json:"records"`
	}
	err := p.do(ctx, http.MethodGet, "/dns/"+url.PathEscape(apiZone(zone))+"/records", nil, &out)
	return out.Records, err
}

func (p *Provider) createRecord(ctx context.Context, zone string, r apiRecord) (apiRecord, error) {
	var out apiRecord
	err := p.do(ctx, http.MethodPost, "/dns/"+url.PathEscape(apiZone(zone))+"/records", r, &out)
	return out, err
}

// updateRecord changes an existing record in place to the data and TTL of r.
func (p *Provider) updateRecord(ctx context.Context, zone string, existing, r apiRecord) (apiRecord, error) {
	path := "/dns/" + url.PathEscape(apiZone(zone)) + "/records/" + existing.Type + "/" + strconv.FormatInt(existing.ID, 10)
	r.ID = 0
	var out apiRecord
	err := p.do(ctx, http.MethodPatch, path, r, &out)
	return out, err
}

func (p *Provider) deleteRecord(ctx context.Context, zone string, r apiRecord) error {
	path := "/dns/" + url.PathEscape(apiZone(zone)) + "/records/" + r.Type + "/" + strconv.FormatInt(r.ID, 10)
	err := p.do(ctx, http.MethodDelete, path, nil, nil)
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
		return nil // already gone
	}
	return err
}

func (p *Provider) listZones(ctx context.Context) ([]string, error) {
	var out struct {
		Zones []struct {
			Name string `json:"name"`
		} `json:"zones"`
	}
	if err := p.do(ctx, http.MethodGet, "/dns", nil, &out); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(out.Zones))
	for _, z := range out.Zones {
		names = append(names, z.Name)
	}
	return names, nil
}
