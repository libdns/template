package provider

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"os"
	"time"
)

type OutputLevel uint8

// DebugTransport is an HTTP transport wrapper that logs outgoing requests
// and incoming responses for debugging purposes.
//
// It implements the http.RoundTripper interface and can be used to wrap
// an existing transport (such as http.DefaultTransport) to add debug output.
//
// Example:
//
//	 client := &http.Client{
//		 Transport: &DebugTransport{
//			 RoundTripper: http.DefaultTransport,
//			 config: ...
//		 },
//	 }
type DebugTransport struct {
	http.RoundTripper
	Config DebugConfig
}

type DebugConfig interface {
	DebugOutputLevel() OutputLevel
	DebugOutput() io.Writer
}

// DebugAware is an interface implemented by types that support
// configurable debug logging of client communication.
//
// Implementations typically allow controlling the debug output level
// and destination writer used for HTTP or API requests.
//
// Example:
//
//	type Provider struct {
//		DebugLevel  OutputLevel
//		DebugOutput io.Writer
//		client      *http.Client
//	}
//
//	func (p *Provider) DebugOutputLevel() OutputLevel {
//		return p.DebugLevel
//	}
//
//	func (p *Provider) DebugOutput() io.Writer {
//		return p.DebugOutput
//	}
//
//	func (p *Provider) SetDebug(level OutputLevel, writer io.Writer) {
//		p.DebugLevel = level
//		p.DebugOutput = writer
//	}
//
//	func (p *Provider) getClient() *http.Client {
//		if p.client == nil {
//			p.client = &http.Client{
//				Transport: &DebugTransport{
//					RoundTripper: http.DefaultTransport,
//					config:       p,
//				},
//			}
//		}
//		return p.client
//	}
type DebugAware interface {
	SetDebug(level OutputLevel, writer io.Writer)
}

const (
	OutputNone        OutputLevel = 0x00
	OutputVerbose                 = 0x01
	OutputVeryVerbose             = 0x02
	OutputDebug                   = 0x03
)

func (t *DebugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var now time.Time
	var out io.Writer

	if t.Config.DebugOutputLevel() >= OutputVerbose {
		out = t.Config.DebugOutput()

		if nil == out {
			out = os.Stdout
		}
	}
	if t.Config.DebugOutputLevel() == OutputVerbose {
		now = time.Now()
	}

	if nil != out && t.Config.DebugOutputLevel() >= OutputVeryVerbose {
		dumpWire(req, httputil.DumpRequest, "c", out, t.Config.DebugOutputLevel() == OutputDebug)
	}

	response, err := t.RoundTripper.RoundTrip(req)

	if out != nil && nil != response {

		if t.Config.DebugOutputLevel() >= OutputVeryVerbose {
			dumpWire(response, httputil.DumpResponse, "s", out, t.Config.DebugOutputLevel() == OutputDebug)
		} else {
			dumpLine(response, out, now)
		}
	}

	return response, err
}

func dumpLine(response *http.Response, write io.Writer, start time.Time) {
	var req = response.Request
	var uri string

	if uri = req.RequestURI; "" == uri {
		uri = req.URL.RequestURI()
	}

	_, _ = fmt.Fprintf(
		write,
		"[%d] %s \"%s HTTP/%d.%d\" %d (%s)\r\n",
		start.UnixMilli(),
		req.Method,
		uri,
		req.ProtoMajor,
		req.ProtoMinor,
		response.StatusCode,
		time.Now().Sub(start).Round(time.Millisecond),
	)
}

func dumpWire[T *http.Request | *http.Response](x T, d func(T, bool) ([]byte, error), p string, o io.Writer, z bool) {
	if out, err := d(x, z); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			_, _ = fmt.Fprintf(o, "[%s] %s\n", p, scanner.Text())
		}
	}
}
