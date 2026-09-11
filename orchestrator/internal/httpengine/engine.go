// Package httpengine is the single guarded HTTP client every active phase uses.
//
// Each request is checked against the project scope AND the SSRF guard, and the
// SSRF check runs again at dial time on the actual connection IP so a
// DNS-rebind cannot slip a private address past the pre-flight check. A shared
// token-bucket rate limiter and a response-size cap apply to every call.
package httpengine

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/argus-platform/orchestrator/internal/scope"
	"github.com/argus-platform/orchestrator/internal/ssrf"
	"golang.org/x/time/rate"
)

type Engine struct {
	scope    *scope.Engine
	guard    *ssrf.Guard
	limiter  *rate.Limiter
	maxBytes int64
	client   *http.Client
	ua       string
}

type Options struct {
	RequestsPerSecond int
	MaxResponseBytes  int64
	TimeoutSeconds    int
	UserAgent         string
}

// Response is the trimmed result of a request.
type Response struct {
	URL         string
	StatusCode  int
	Header      http.Header
	Body        []byte
	Truncated   bool
	RemoteIP    string
	TLSSubjects []string
	Elapsed     time.Duration
}

// ScopeError / SSRFError distinguish policy rejections from transport failures
// so callers can treat "blocked" as a non-fatal, expected outcome.
type ScopeError struct{ Reason string }

func (e *ScopeError) Error() string { return "out of scope: " + e.Reason }

type SSRFError struct{ Reason string }

func (e *SSRFError) Error() string { return "blocked by SSRF policy: " + e.Reason }

func New(sc *scope.Engine, guard *ssrf.Guard, o Options) *Engine {
	rps := o.RequestsPerSecond
	if rps <= 0 {
		rps = 5
	}
	maxBytes := o.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = 2 << 20
	}
	timeout := time.Duration(o.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	ua := o.UserAgent
	if ua == "" {
		ua = "Argus/0.1 (+authorized-assessment)"
	}

	e := &Engine{
		scope:    sc,
		guard:    guard,
		limiter:  rate.NewLimiter(rate.Limit(rps), rps),
		maxBytes: maxBytes,
		ua:       ua,
	}

	dialer := &net.Dialer{Timeout: 8 * time.Second}
	resolver := &net.Resolver{}
	transport := &http.Transport{
		DisableKeepAlives:   false,
		MaxIdleConns:        50,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 8 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // recon inspects broken/self-signed TLS
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			// addr may carry a hostname (Go resolves inside the default dialer);
			// resolve here so the SSRF check runs on the real connection IP and
			// a DNS-rebind cannot slip a private address through.
			if ip := net.ParseIP(host); ip != nil {
				if err := e.guard.CheckAddr(host); err != nil {
					return nil, &SSRFError{Reason: err.Error()}
				}
				return dialer.DialContext(ctx, network, addr)
			}
			ips, err := resolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ipa := range ips {
				if e.guard.CheckAddr(ipa.IP.String()) == nil {
					return dialer.DialContext(ctx, network, net.JoinHostPort(ipa.IP.String(), port))
				}
			}
			return nil, &SSRFError{Reason: "all resolved addresses for " + host + " are blocked"}
		},
	}
	e.client = &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 4 {
				return http.ErrUseLastResponse
			}
			if err := e.check(req.URL, req.Host); err != nil {
				return err
			}
			return nil
		},
	}
	return e
}

func (e *Engine) check(u *url.URL, hostHeader string) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return &SSRFError{Reason: "scheme " + u.Scheme}
	}
	name := hostHeader
	if name == "" {
		name = u.Hostname()
	}
	name = strings.Split(name, ":")[0]
	// Literal IP → scope-check the IP; hostname → scope-check the host.
	var d scope.Decision
	if ip := net.ParseIP(name); ip != nil {
		d = e.scope.Evaluate(scope.Target{IP: name, Path: u.Path})
	} else {
		d = e.scope.Evaluate(scope.Target{Host: name, Path: u.Path})
	}
	if !d.Allowed {
		return &ScopeError{Reason: d.Reason}
	}
	if err := e.guard.CheckURL(u.String()); err != nil {
		return &SSRFError{Reason: err.Error()}
	}
	return nil
}

// Do performs a scope- and SSRF-checked request. hostHeader overrides the Host
// header (used for virtual-host probing); pass "" to use the URL's host.
func (e *Engine) Do(ctx context.Context, method, rawurl, hostHeader string) (*Response, error) {
	return e.DoRequest(ctx, Request{Method: method, URL: rawurl, Host: hostHeader})
}

// Request is the extended form DoRequest accepts — a body and extra headers,
// for the injection engine's form/JSON/header/cookie test cases.
type Request struct {
	Method  string
	URL     string
	Host    string // overrides the Host header; "" = use the URL's host
	Body    []byte
	Headers map[string]string // merged over the defaults; case as given
}

// DoRequest is Do with an optional body and extra headers.
func (e *Engine) DoRequest(ctx context.Context, r Request) (*Response, error) {
	method, rawurl, hostHeader := r.Method, r.URL, r.Host
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, fmt.Errorf("bad url: %w", err)
	}
	if err := e.check(u, hostHeader); err != nil {
		return nil, err
	}
	if err := e.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	var bodyReader io.Reader
	if len(r.Body) > 0 {
		bodyReader = bytes.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawurl, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", e.ua)
	req.Header.Set("Accept", "*/*")
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	if hostHeader != "" {
		req.Host = hostHeader
	}

	start := time.Now()
	resp, err := e.client.Do(req)
	if err != nil {
		// Unwrap our policy errors from url.Error.
		if se, ok := err.(*url.Error); ok {
			if _, is := se.Err.(*SSRFError); is {
				return nil, se.Err
			}
			if _, is := se.Err.(*ScopeError); is {
				return nil, se.Err
			}
		}
		return nil, err
	}
	defer resp.Body.Close()

	body, trunc := readCapped(resp.Body, e.maxBytes)
	out := &Response{
		URL:        resp.Request.URL.String(),
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       body,
		Truncated:  trunc,
		Elapsed:    time.Since(start),
	}
	if resp.TLS != nil {
		for _, c := range resp.TLS.PeerCertificates {
			out.TLSSubjects = append(out.TLSSubjects, c.DNSNames...)
			break
		}
	}
	return out, nil
}

func (e *Engine) Get(ctx context.Context, rawurl string) (*Response, error) {
	return e.Do(ctx, http.MethodGet, rawurl, "")
}

func readCapped(r io.Reader, max int64) ([]byte, bool) {
	buf := make([]byte, 0, 16<<10)
	lr := io.LimitReader(r, max+1)
	tmp := make([]byte, 32<<10)
	for {
		n, err := lr.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if int64(len(buf)) > max {
			return buf[:max], true
		}
		if err != nil {
			return buf, false
		}
	}
}

// IsBlocked reports whether an error is a policy rejection (expected, non-fatal).
func IsBlocked(err error) bool {
	if err == nil {
		return false
	}
	_, s1 := err.(*ScopeError)
	_, s2 := err.(*SSRFError)
	return s1 || s2
}
