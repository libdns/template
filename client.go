package enum

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const defaultBaseURL = "https://api.enum.co"

type zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type recordSet struct {
	Name    string        `json:"name"`
	Type    string        `json:"type"`
	TTL     int           `json:"ttl"`
	Records []recordValue `json:"records"`
}

type recordValue struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled,omitempty"`
}

type recordSetRequest struct {
	ProjectID string `json:"projectId"`
	ZoneID    string `json:"zoneId"`
	recordSet
}

type recordSetResponse struct {
	RecordSet recordSet `json:"recordSet"`
}

type apiError struct {
	status  int
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *apiError) Error() string {
	return fmt.Sprintf("HTTP %d: %s: %s", e.status, e.Code, e.Message)
}

func isNotFound(err error) bool {
	var apiErr *apiError
	return errors.As(err, &apiErr) && apiErr.status == http.StatusNotFound
}

func (p *Provider) getZoneByName(ctx context.Context, name string) (zone, error) {
	var resp struct {
		Zone zone `json:"zone"`
	}

	err := p.call(ctx, "GetZoneByName", map[string]string{"projectId": p.ProjectID, "name": name}, &resp)

	return resp.Zone, err
}

func (p *Provider) listZones(ctx context.Context) ([]zone, error) {
	var resp struct {
		Zones []zone `json:"zones"`
	}

	err := p.call(ctx, "ListZones", map[string]string{"projectId": p.ProjectID}, &resp)

	return resp.Zones, err
}

func (p *Provider) listRecordSets(ctx context.Context, zoneID string) ([]recordSet, error) {
	var resp struct {
		RecordSets []recordSet `json:"recordSets"`
	}

	err := p.call(ctx, "ListRecordSets", map[string]string{"projectId": p.ProjectID, "zoneId": zoneID}, &resp)

	return resp.RecordSets, err
}

func (p *Provider) createRecordSet(ctx context.Context, zoneID string, set recordSet) (recordSet, error) {
	var resp recordSetResponse

	err := p.call(ctx, "CreateRecordSet", recordSetRequest{ProjectID: p.ProjectID, ZoneID: zoneID, recordSet: set}, &resp)

	return resp.RecordSet, err
}

func (p *Provider) updateRecordSet(ctx context.Context, zoneID string, set recordSet) (recordSet, error) {
	var resp recordSetResponse

	err := p.call(ctx, "UpdateRecordSet", recordSetRequest{ProjectID: p.ProjectID, ZoneID: zoneID, recordSet: set}, &resp)

	return resp.RecordSet, err
}

func (p *Provider) addRecordSetValue(ctx context.Context, zoneID, name, typ string, ttl int, content string) (recordSet, error) {
	req := map[string]any{
		"projectId": p.ProjectID,
		"zoneId":    zoneID,
		"name":      name,
		"type":      typ,
		"ttl":       ttl,
		"value":     recordValue{Content: content},
	}

	var resp recordSetResponse

	err := p.call(ctx, "AddRecordSetValue", req, &resp)

	return resp.RecordSet, err
}

func (p *Provider) removeRecordSetValue(ctx context.Context, zoneID, name, typ, content string) error {
	req := map[string]string{
		"projectId": p.ProjectID,
		"zoneId":    zoneID,
		"name":      name,
		"type":      typ,
		"content":   content,
	}

	return p.call(ctx, "RemoveRecordSetValue", req, &struct{}{})
}

func (p *Provider) call(ctx context.Context, method string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}

	for attempt := 1; ; attempt++ {
		err = p.do(ctx, method, body, out)

		var apiErr *apiError
		retry := !errors.As(err, &apiErr) || apiErr.status == http.StatusTooManyRequests || apiErr.status >= 500
		if err == nil || !retry || attempt == 3 || ctx.Err() != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt) * time.Second):
		}
	}
}

func (p *Provider) do(ctx context.Context, method string, body []byte, out any) error {
	baseURL := defaultBaseURL
	if p.baseURL != "" {
		baseURL = p.baseURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/enum.api.v1.DnsService/"+method, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		apiErr := &apiError{status: resp.StatusCode}
		if json.Unmarshal(data, apiErr) != nil || apiErr.Message == "" {
			apiErr.Message = strings.TrimSpace(string(data))
		}

		return apiErr
	}

	return json.Unmarshal(data, out)
}

func quoteTXT(text string) string {
	var b strings.Builder

	b.WriteByte('"')
	for i := 0; i < len(text); i++ {
		c := text[i]

		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < ' ' || c > '~':
			fmt.Fprintf(&b, "\\%03d", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')

	return b.String()
}

func unquoteTXT(content string) string {
	var b strings.Builder

	quoted := false
	for i := 0; i < len(content); i++ {
		c := content[i]

		switch {
		case c == '"':
			quoted = !quoted
		case c == ' ' && !quoted:
		case c == '\\' && i+3 < len(content) && isDigits(content[i+1:i+4]):
			n, _ := strconv.Atoi(content[i+1 : i+4])
			b.WriteByte(byte(n))
			i += 3
		case c == '\\' && i+1 < len(content):
			b.WriteByte(content[i+1])
			i++
		default:
			b.WriteByte(c)
		}
	}

	return b.String()
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return true
}
