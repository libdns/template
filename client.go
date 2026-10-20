package hosterby

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

const (
	defaultBaseURL = "https://serviceapi.hoster.by"
	userAgent      = "libdns-hosterby"
	maxAttempts    = 3

	// tokenLeeway is how long before its expiry an access token is renewed.
	tokenLeeway = time.Minute

	// ordersTTL is how long the list of DNS orders is cached.
	ordersTTL = 5 * time.Minute
)

// apiError is returned when the hoster.by API responds with an error.
type apiError struct {
	statusCode int
	codes      []string          // e.g. "access_token_expired"
	messages   map[string]string // descriptions of the codes
}

func (e *apiError) Error() string {
	var details []string
	for _, code := range e.codes {
		if msg, ok := e.messages[code]; ok {
			code = fmt.Sprintf("%s (%s)", code, msg)
		}
		details = append(details, code)
	}
	msg := fmt.Sprintf("hoster.by API: HTTP %d", e.statusCode)
	if len(details) > 0 {
		msg += ": " + strings.Join(details, "; ")
	}
	return msg
}

// envelope is the common wrapper of all API responses.
type envelope struct {
	StatusCode string `json:"statusCode"`
	CodeList   struct {
		Error []string `json:"error"`
	} `json:"codeList"`
	MessageList struct {
		Error map[string]string `json:"error"`
	} `json:"messageList"`
	Payload json.RawMessage `json:"payload"`
}

// apiOrder is a DNS service order. Each order holds one zone.
type apiOrder struct {
	ID         string `json:"id"`
	DomainName string `json:"domainName"`
}

// dnsOrder is the resolved DNS service order of a zone.
type dnsOrder struct {
	id      string
	unicode bool // the API uses Unicode names for the zone (IDN zones)
}

// apiName converts an ASCII name into the form the API uses for the order.
func (o dnsOrder) apiName(name string) string {
	if !o.unicode {
		return name
	}
	if u, err := idna.Punycode.ToUnicode(name); err == nil {
		return u
	}
	return name
}

// call performs an authenticated API request, retrying requests that fail
// with transient errors.
func (p *Provider) call(ctx context.Context, method, path string, in, out any) error {
	var (
		body []byte
		err  error
	)
	if in != nil {
		if body, err = json.Marshal(in); err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
	}

	for attempt := range maxAttempts {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			case <-ctx.Done():
				return errors.Join(err, ctx.Err())
			}
		}
		err = p.callOnce(ctx, method, path, body, out)
		if !retryable(method, err) {
			return err
		}
	}
	return err
}

// callOnce performs an authenticated API request. If the API rejects the
// access token, it creates a new one and repeats the request.
func (p *Provider) callOnce(ctx context.Context, method, path string, body []byte, out any) error {
	token, err := p.accessToken(ctx)
	if err != nil {
		return err
	}
	err = p.send(ctx, method, path, http.Header{"Access-Token": {token}}, body, out)

	var apiErr *apiError
	if !errors.As(err, &apiErr) || apiErr.statusCode != http.StatusUnauthorized {
		return err
	}
	p.invalidateToken(token)
	if token, err = p.accessToken(ctx); err != nil {
		return err
	}
	return p.send(ctx, method, path, http.Header{"Access-Token": {token}}, body, out)
}

// retryable reports whether a request that failed with err may be repeated.
// Requests that may have been processed by the server are retried only if
// they are idempotent.
func retryable(method string, err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		// transport error
		return method != http.MethodPost
	}
	switch apiErr.statusCode {
	case http.StatusTooManyRequests:
		return true
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return method != http.MethodPost
	}
	return false
}

// send performs a single API request and decodes the response payload into
// out, if out is not nil.
func (p *Provider) send(ctx context.Context, method, path string, header http.Header, body []byte, out any) error {
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.baseURL()+path, reqBody)
	if err != nil {
		return err
	}
	maps.Copy(req.Header, header)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	var env envelope
	if err := json.Unmarshal(respBody, &env); err != nil {
		if resp.StatusCode >= 400 {
			return &apiError{statusCode: resp.StatusCode}
		}
		return fmt.Errorf("decoding response: %w", err)
	}
	if resp.StatusCode >= 400 || env.StatusCode == "error" {
		return &apiError{
			statusCode: resp.StatusCode,
			codes:      env.CodeList.Error,
			messages:   env.MessageList.Error,
		}
	}
	if out != nil {
		if err := json.Unmarshal(env.Payload, out); err != nil {
			return fmt.Errorf("decoding response payload: %w", err)
		}
	}
	return nil
}

// accessToken returns a valid access token, creating a new one from the
// access and secret keys if necessary.
func (p *Provider) accessToken(ctx context.Context) (string, error) {
	p.authMu.Lock()
	defer p.authMu.Unlock()

	if p.token != "" && time.Until(p.tokenExpiry) > tokenLeeway {
		return p.token, nil
	}
	if p.AccessKey == "" || p.SecretKey == "" {
		return "", errors.New("hosterby: access key and secret key are required")
	}

	var tokens struct {
		AccessToken string `json:"accessToken"`
		DateExpires int64  `json:"dateExpires"`
	}
	header := http.Header{"Access-Key": {p.AccessKey}, "Secret-Key": {p.SecretKey}}
	if err := p.send(ctx, http.MethodPost, "/service/account/create/token", header, nil, &tokens); err != nil {
		return "", fmt.Errorf("hosterby: creating access token: %w", err)
	}

	p.token = tokens.AccessToken
	p.tokenExpiry = time.Unix(tokens.DateExpires, 0)
	return p.token, nil
}

// invalidateToken discards token, unless it has already been replaced.
func (p *Provider) invalidateToken(token string) {
	p.authMu.Lock()
	defer p.authMu.Unlock()
	if p.token == token {
		p.token = ""
	}
}

func (p *Provider) listOrders(ctx context.Context) ([]apiOrder, error) {
	var payload struct {
		Orders []apiOrder `json:"orders"`
	}
	if err := p.call(ctx, http.MethodGet, "/dns/orders", nil, &payload); err != nil {
		return nil, err
	}
	return payload.Orders, nil
}

// lookupOrder returns the order of the normalized zone.
func (p *Provider) lookupOrder(ctx context.Context, zone string) (dnsOrder, error) {
	p.ordersMu.Lock()
	defer p.ordersMu.Unlock()

	if o, ok := p.orders[zone]; ok && time.Now().Before(p.ordersExpiry) {
		return o, nil
	}

	orders, err := p.listOrders(ctx)
	if err != nil {
		return dnsOrder{}, err
	}
	p.ordersExpiry = time.Now().Add(ordersTTL)
	p.orders = make(map[string]dnsOrder, len(orders))
	for _, o := range orders {
		p.orders[normalizeZone(o.DomainName)] = dnsOrder{
			id:      o.ID,
			unicode: toASCII(o.DomainName) != o.DomainName,
		}
	}

	o, ok := p.orders[zone]
	if !ok {
		return dnsOrder{}, fmt.Errorf("zone %q not found in hoster.by DNS orders", zone)
	}
	return o, nil
}

// listRRsets returns the record sets of the order, with names in lower-case
// ASCII.
func (p *Provider) listRRsets(ctx context.Context, o dnsOrder) ([]rrset, error) {
	var payload struct {
		Records []rrset `json:"records"`
	}
	if err := p.call(ctx, http.MethodGet, recordsPath(o), nil, &payload); err != nil {
		return nil, err
	}
	for i := range payload.Records {
		payload.Records[i].Name = toASCII(strings.ToLower(payload.Records[i].Name))
	}
	return payload.Records, nil
}

func (p *Provider) createRRset(ctx context.Context, o dnsOrder, set rrset) error {
	set.Name = o.apiName(set.Name)
	return p.call(ctx, http.MethodPost, recordsPath(o)+"/"+strings.ToLower(set.Type), set, nil)
}

// updateRRset replaces the TTL and records of an existing record set.
func (p *Provider) updateRRset(ctx context.Context, o dnsOrder, set rrset) error {
	body := struct {
		TTL     int      `json:"ttl"`
		Records []record `json:"records"`
	}{set.TTL, set.Records}
	return p.call(ctx, http.MethodPatch, rrsetPath(o, set), body, nil)
}

func (p *Provider) deleteRRset(ctx context.Context, o dnsOrder, set rrset) error {
	return p.call(ctx, http.MethodDelete, rrsetPath(o, set), nil, nil)
}

func recordsPath(o dnsOrder) string {
	return "/dns/orders/" + o.id + "/records"
}

func rrsetPath(o dnsOrder, set rrset) string {
	return recordsPath(o) + "/" + strings.ToLower(set.Type) + "/" + url.PathEscape(o.apiName(set.Name))
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
	return defaultHTTPClient
}

var defaultHTTPClient = &http.Client{Timeout: 30 * time.Second}
