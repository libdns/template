package mittwald

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
	"sync"
	"time"

	"github.com/mittwald/api-client-go/mittwaldv2"
	generatedv2 "github.com/mittwald/api-client-go/mittwaldv2/generated/clients"
	"github.com/mittwald/api-client-go/mittwaldv2/generated/clients/domainclientv2"
	"github.com/mittwald/api-client-go/mittwaldv2/generated/clients/projectclientv2"
	"github.com/mittwald/api-client-go/mittwaldv2/generated/schemas/dnsv2"
	"golang.org/x/net/idna"
)

// requestTimeout bounds one attempt of a request; waiting between attempts is
// bounded by the caller's context only.
const requestTimeout = 60 * time.Second

// projectPageSize is the number of projects requested per page.
const projectPageSize = 100

// defaultAPIURL is the API's address.
const defaultAPIURL = "https://api.mittwald.de/v2"

func newClient(token, apiURL string) (generatedv2.Client, error) {
	return mittwaldv2.New(context.Background(),
		mittwaldv2.WithHTTPClient(newAPIRunner(&http.Client{Timeout: requestTimeout})), // must come first
		mittwaldv2.WithAccessToken(token),
		mittwaldv2.WithBaseURL(apiURL),
	)
}

// listProjectZones returns every DNS zone of a project, named in ASCII. The
// API names zones in Unicode.
func listProjectZones(ctx context.Context, c generatedv2.Client, projectID string) ([]dnsv2.Zone, error) {
	zones, resp, err := c.Domain().ListDNSZones(ctx, domainclientv2.ListDNSZonesRequest{ProjectID: projectID})
	closeBody(resp)
	if err != nil {
		return nil, fmt.Errorf("listing DNS zones of project %s: %w", projectID, err)
	}
	for i := range *zones {
		z := &(*zones)[i]
		if z.Domain, err = idna.ToASCII(z.Domain); err != nil {
			return nil, fmt.Errorf("zone %s: %w", z.Id, err)
		}
	}
	return *zones, nil
}

// listProjectIDs returns the IDs of all projects the token can access.
func listProjectIDs(ctx context.Context, c generatedv2.Client) ([]string, error) {
	var ids []string
	limit := int64(projectPageSize)
	for skip := int64(0); ; skip += limit {
		page, resp, err := c.Project().ListProjects(ctx, projectclientv2.ListProjectsRequest{Limit: &limit, Skip: &skip})
		closeBody(resp)
		if err != nil {
			return nil, fmt.Errorf("listing projects: %w", err)
		}
		for _, p := range *page {
			ids = append(ids, p.Id)
		}
		if int64(len(*page)) < limit {
			return ids, nil
		}
	}
}

// createZone creates the zone for label (relative to the root zone) and returns its ID.
func createZone(ctx context.Context, c generatedv2.Client, rootID, label string) (string, error) {
	created, resp, err := c.Domain().CreateDNSZone(ctx, domainclientv2.CreateDNSZoneRequest{
		Body: domainclientv2.CreateDNSZoneRequestBody{Name: label, ParentZoneId: rootID},
	})
	closeBody(resp)
	if err != nil {
		return "", fmt.Errorf("creating zone %q: %w", label, err)
	}
	return created.Id, nil
}

// setRecordSet replaces one record set of a zone.
func setRecordSet(ctx context.Context, c generatedv2.Client, zoneID string, set domainclientv2.UpdateRecordSetRequestPathRecordSet, body domainclientv2.UpdateRecordSetRequestBody) error {
	resp, err := c.Domain().UpdateRecordSet(ctx, domainclientv2.UpdateRecordSetRequest{DNSZoneID: zoneID, RecordSet: set, Body: body})
	closeBody(resp)
	if err != nil {
		return fmt.Errorf("setting %s records of zone %s: %w", set, zoneID, err)
	}
	return nil
}

// closeBody releases the connection of a response; the client leaves that to the caller.
func closeBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

// The API allows a user a number of requests per window and reports what is
// left on every successful response (X-Ratelimit-Remaining, and
// X-Ratelimit-Reset in seconds). libdns expects retries not to add more than a
// couple of seconds, so once nothing is left a request waits for the reset
// only if it comes within maxResetWait, and fails otherwise.
//
// A request is repeated up to maxRetries times with a short, growing pause
// after a 429, and, if it cannot create anything twice (not a POST), after a
// 500, 502, 503 or 504.
//
// The API is eventually consistent: a write answers with the ID of its event
// (ETag), and a request that sends it as If-Event-Reached waits until the
// event is processed, or answers 412 of type FailedPrecondition without doing
// anything. (Other 412s, such as a CNAME on a name with records, are final.)
// Every request after a write waits for it this way, so that a read sees it
// and a write to a zone just created finds the zone, and is repeated after a
// 412. The permissions of a zone just created can still lag behind, so a
// request that is not a POST is also repeated after a 403 or 404, as
// mittwald's own client does.
//
// All waiting ends with the request's context.
const (
	firstRetryPause = 500 * time.Millisecond
	maxRetries      = 4
	maxResetWait    = 5 * time.Second
)

// errRateLimited is returned when the rate limit resets too late to wait for it.
var errRateLimited = errors.New("mittwald: API rate limit used up")

type apiRunner struct {
	inner interface {
		Do(*http.Request) (*http.Response, error)
	}
	now func() time.Time

	mu           sync.Mutex
	blockedUntil time.Time // no request before this time; the limit is used up
	lastEvent    string    // ETag of the last write
}

func newAPIRunner(inner *http.Client) *apiRunner {
	return &apiRunner{inner: inner, now: time.Now}
}

func (r *apiRunner) Do(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	if r.lastEvent != "" {
		req.Header.Set("If-Event-Reached", r.lastEvent)
	}
	wait := r.blockedUntil.Sub(r.now())
	r.mu.Unlock()

	pause := firstRetryPause
	for attempt := 0; ; attempt++ {
		if wait > maxResetWait {
			return nil, fmt.Errorf("%w, it resets in %s", errRateLimited, wait.Round(time.Second))
		}
		if err := sleep(req.Context(), wait); err != nil {
			return nil, err
		}

		resp, err := r.inner.Do(req)
		if err != nil {
			return resp, err
		}
		if !retryable(req, resp) || attempt == maxRetries {
			r.observe(req, resp)
			return resp, nil
		}
		closeBody(resp)
		if req.Body != nil {
			if req.GetBody == nil {
				return nil, errors.New("cannot repeat the request: its body cannot be sent again")
			}
			if req.Body, err = req.GetBody(); err != nil {
				return nil, err
			}
		}
		wait, pause = pause, 2*pause
	}
}

func retryable(req *http.Request, resp *http.Response) bool {
	barrier := req.Header.Get("If-Event-Reached") != ""
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		return true
	case http.StatusPreconditionFailed:
		return barrier && eventNotReached(resp)
	case http.StatusForbidden, http.StatusNotFound:
		return barrier && req.Method != http.MethodPost
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return req.Method != http.MethodPost
	}
	return false
}

// eventNotReached reports whether a 412 says that the event of
// If-Event-Reached is not processed yet. It reads the body and puts it back.
func eventNotReached(resp *http.Response) bool {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	var e struct {
		Type string `json:"type"`
	}
	return err == nil && json.Unmarshal(body, &e) == nil && e.Type == "FailedPrecondition"
}

// observe remembers the event of a write, and when the limit resets once a
// response says nothing is left.
func (r *apiRunner) observe(req *http.Request, resp *http.Response) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if etag := resp.Header.Get("ETag"); etag != "" && req.Method != http.MethodGet && resp.StatusCode < http.StatusBadRequest {
		r.lastEvent = etag
	}
	remaining, err1 := strconv.Atoi(resp.Header.Get("X-Ratelimit-Remaining"))
	reset, err2 := strconv.Atoi(resp.Header.Get("X-Ratelimit-Reset"))
	if err1 == nil && err2 == nil && remaining <= 0 && reset >= 0 {
		r.blockedUntil = r.now().Add(time.Duration(reset) * time.Second)
	}
}

// sleep waits for d or until ctx ends.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// fqdnNoDot returns a name the way the zones are named here: lower case,
// ASCII (Punycode) and without the trailing dot.
func fqdnNoDot(name string) string {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if a, err := idna.ToASCII(n); err == nil {
		return a
	}
	return n
}

// normalZone returns a zone as fqdnNoDot does, with the trailing dot.
func normalZone(zone string) string {
	return fqdnNoDot(zone) + "."
}
