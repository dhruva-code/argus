// Package ssrf is the dedicated SSRF-protection layer. Because Argus makes
// outbound requests on an operator's behalf, every HTTP fetch, crawl,
// screenshot, callback, and integration call must pass Guard.CheckURL /
// Guard.CheckAddr before a connection is made.
//
// Blocked by default: loopback, RFC1918, link-local, CGNAT (100.64/10),
// unique-local IPv6, and cloud metadata endpoints. An operator may re-allow
// specific CIDRs for an authorized internal engagement.
package ssrf

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// MetadataIPs are well-known cloud instance-metadata endpoints that must never
// be reachable through the platform unless metadata blocking is disabled.
var MetadataIPs = []string{
	"169.254.169.254", // AWS / GCP / Azure / OpenStack / DigitalOcean
	"100.100.100.200", // Alibaba Cloud
	"fd00:ec2::254",   // AWS IMDSv2 over IPv6
}

type Guard struct {
	allow         []netip.Prefix
	blockMetadata bool
}

func NewGuard(allowCIDRs []string, blockMetadata bool) (*Guard, error) {
	g := &Guard{blockMetadata: blockMetadata}
	for _, c := range allowCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("SSRF_ALLOW_CIDRS: %q: %w", c, err)
		}
		g.allow = append(g.allow, p.Masked())
	}
	return g, nil
}

// CheckURL validates the scheme and host of a URL. Hostnames are resolved and
// every returned address is checked, defeating DNS-rebinding to a private IP.
func (g *Guard) CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q not allowed", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("url has no host")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return g.checkAddr(addr)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("resolve %q: no addresses", host)
	}
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return fmt.Errorf("bad address for %q", host)
		}
		if err := g.checkAddr(addr.Unmap()); err != nil {
			return err
		}
	}
	return nil
}

// CheckAddr validates a literal IP string.
func (g *Guard) CheckAddr(ip string) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("invalid ip: %w", err)
	}
	return g.checkAddr(addr.Unmap())
}

func (g *Guard) checkAddr(addr netip.Addr) error {
	for _, p := range g.allow {
		if p.Contains(addr) {
			return nil
		}
	}
	if g.blockMetadata {
		for _, m := range MetadataIPs {
			if ma, err := netip.ParseAddr(m); err == nil && ma == addr {
				return fmt.Errorf("blocked: cloud metadata endpoint %s", addr)
			}
		}
	}
	switch {
	case addr.IsLoopback():
		return fmt.Errorf("blocked: loopback %s", addr)
	case addr.IsPrivate():
		return fmt.Errorf("blocked: private address %s", addr)
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return fmt.Errorf("blocked: link-local %s", addr)
	case addr.IsUnspecified():
		return fmt.Errorf("blocked: unspecified address %s", addr)
	case addr.IsMulticast():
		return fmt.Errorf("blocked: multicast %s", addr)
	case isCGNAT(addr):
		return fmt.Errorf("blocked: carrier-grade NAT %s", addr)
	case addr.Is6() && isULA(addr):
		return fmt.Errorf("blocked: unique-local %s", addr)
	}
	return nil
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func isCGNAT(a netip.Addr) bool { return a.Is4() && cgnat.Contains(a) }

func isULA(a netip.Addr) bool {
	b := a.As16()
	return b[0]&0xfe == 0xfc // fc00::/7
}
