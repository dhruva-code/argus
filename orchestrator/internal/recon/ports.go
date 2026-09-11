package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/argus-platform/orchestrator/internal/httpengine"
	"github.com/argus-platform/orchestrator/internal/plugin"
	"github.com/argus-platform/orchestrator/internal/scope"
	"github.com/argus-platform/orchestrator/internal/ssrf"
)

// newProbeEngine builds a guarded HTTP client for the M5 phases.
func newProbeEngine(eng *scope.Engine, guard *ssrf.Guard, opts Options) *httpengine.Engine {
	return httpengine.New(eng, guard, httpengine.Options{
		RequestsPerSecond: opts.RequestsPerSecond, TimeoutSeconds: 8,
		MaxResponseBytes: 256 << 10,
	})
}

var reHTMLTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// probeWebPort does one guarded GET against a discovered web port and fills in
// the HTTP fields.
func probeWebPort(ctx context.Context, he *httpengine.Engine, ip string, port int, hostnames []string, p *Port) {
	schemes := []string{"http", "https"}
	if port == 443 || port == 8443 || port == 4443 || p.TLS {
		schemes = []string{"https", "http"}
	}
	// Probe over an in-scope hostname (as the Host header) when we have one, so
	// the guarded client's scope check passes for an IP-addressed request.
	host := ""
	if len(hostnames) > 0 {
		host = hostnames[0]
	}
	authority := ip + ":" + strconv.Itoa(port)
	for _, sch := range schemes {
		resp, err := he.Do(ctx, "GET", sch+"://"+authority+"/", host)
		if err != nil {
			continue
		}
		p.HTTPStatus = resp.StatusCode
		p.TLS = p.TLS || sch == "https"
		if p.Service == "" || p.Service == "unknown" {
			p.Service = sch
		}
		if srv := resp.Header.Get("Server"); srv != "" && p.Product == "" {
			p.Product = trim(srv, 200)
		}
		if m := reHTMLTitle.FindStringSubmatch(string(resp.Body)); m != nil {
			p.HTTPTitle = trim(strings.TrimSpace(m[1]), 300)
		}
		return
	}
}

// PhasePortScan is the Phase 11 key.
const PhasePortScan = "port_service_fingerprint"

// Port is a discovered open port emitted as a "port" event.
type Port struct {
	IP         string   `json:"ip"`
	Port       int      `json:"port"`
	Protocol   string   `json:"protocol"`
	State      string   `json:"state"`
	Service    string   `json:"service,omitempty"`
	Product    string   `json:"product,omitempty"`
	Version    string   `json:"version,omitempty"`
	Banner     string   `json:"banner,omitempty"`
	TLS        bool     `json:"tls,omitempty"`
	HTTPTitle  string   `json:"http_title,omitempty"`
	HTTPStatus int      `json:"http_status,omitempty"`
	Hostnames  []string `json:"hostnames,omitempty"`
	Source     string   `json:"source"`
	InScope    bool     `json:"in_scope"`
}

// wellKnownPorts maps a port number to a coarse service name. Used when service
// detection is disabled or returns nothing.
var wellKnownPorts = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 69: "tftp",
	110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
	161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
	587: "smtp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
	1521: "oracle", 1723: "pptp", 2049: "nfs", 2375: "docker", 2376: "docker-tls",
	3000: "http-dev", 3306: "mysql", 3389: "rdp", 4443: "https-alt", 5000: "http-dev",
	5432: "postgres", 5601: "kibana", 5672: "amqp", 5900: "vnc", 5985: "winrm",
	6379: "redis", 7001: "weblogic", 8000: "http-alt", 8008: "http-alt",
	8080: "http-alt", 8081: "http-alt", 8088: "http-alt", 8443: "https-alt",
	8888: "http-alt", 9000: "http-alt", 9092: "kafka", 9200: "elasticsearch",
	9300: "elasticsearch", 11211: "memcached", 15672: "rabbitmq-mgmt",
	27017: "mongodb", 5984: "couchdb",
}

func webPort(p int, svc string) bool {
	if strings.Contains(svc, "http") {
		return true
	}
	switch p {
	case 80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 4443:
		return true
	}
	return false
}

// runPortScan is Phase 11: naabu connect-scan of every in-scope IP that also
// passes the SSRF guard, an optional nmap -sV service-detection pass, and a
// lightweight HTTP probe of web ports. Every IP is re-checked against scope and
// the SSRF guard before it is touched.
func runPortScan(
	ctx context.Context, r plugin.Runner, guard *ssrf.Guard, eng *scope.Engine,
	dir string, ips []string, ipHosts map[string][]string, opts Options, cb Callbacks,
) int {
	var targets []string
	for _, ip := range ips {
		// `ips` are addresses that an in-scope hostname resolves to, so they are
		// in scope for probing. Only an *explicit* IP/ASN deny rule (RuleID set)
		// takes one back out; a bare default-deny does not.
		if d := eng.Evaluate(scope.Target{IP: ip}); !d.Allowed && d.RuleID != "" {
			cb.log("WARNING", "port scan skipping "+ip+" — "+d.Reason)
			continue
		}
		if guard.CheckAddr(ip) != nil {
			cb.log("WARNING", "port scan skipping "+ip+" — blocked by SSRF policy")
			continue
		}
		targets = append(targets, ip)
	}
	sort.Strings(targets)
	if len(targets) == 0 {
		cb.log("INFO", "port scan — no in-scope IPs to scan")
		return 0
	}
	if len(targets) > 25 {
		cb.log("WARNING", fmt.Sprintf("port scan — capping at 25 of %d IPs", len(targets)))
		targets = targets[:25]
	}

	portSpec := strings.TrimSpace(opts.PortSpec)
	rows, err := naabuScan(ctx, r, dir, targets, portSpec, opts.RequestsPerSecond)
	if err != nil {
		cb.log("WARNING", "naabu: "+err.Error())
		return 0
	}

	// dedup ip:port (naabu retries emit duplicates)
	seen := map[string]bool{}
	byIP := map[string][]int{}
	for _, row := range rows {
		key := row.IP + ":" + strconv.Itoa(row.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		byIP[row.IP] = append(byIP[row.IP], row.Port)
	}

	// optional nmap -sV service/version detection — one invocation for every
	// host (nmap parallelizes across targets; per-host serial calls are far
	// too slow for a 25-IP sweep).
	svcInfo := map[string]nmapService{}
	if opts.ServiceDetection && len(byIP) > 0 && !cb.cancelled() {
		for k, s := range nmapServiceScan(ctx, r, dir, byIP) {
			svcInfo[k] = s
		}
	}

	he := newProbeEngine(eng, guard, opts)
	total := 0
	for _, ip := range targets {
		ports := byIP[ip]
		sort.Ints(ports)
		hostnames := uniqSorted(ipHosts[ip])
		for _, pnum := range ports {
			if cb.cancelled() {
				break
			}
			p := Port{
				IP: ip, Port: pnum, Protocol: "tcp", State: "open",
				Service: wellKnownPorts[pnum], Hostnames: hostnames,
				Source: "naabu", InScope: true,
			}
			if s, ok := svcInfo[ip+":"+strconv.Itoa(pnum)]; ok {
				if s.Name != "" {
					p.Service = s.Name
				}
				p.Product = s.Product
				p.Version = s.Version
				p.Banner = trim(s.Extra, 500)
				p.TLS = s.TLS
			}
			if webPort(pnum, p.Service) {
				probeWebPort(ctx, he, ip, pnum, hostnames, &p)
			}
			cb.emitPort(p)
			total++
			if p.Service == "" {
				p.Service = "unknown"
			}
			cb.log("INFO", fmt.Sprintf("open %s:%d %s %s", ip, pnum, p.Service, strings.TrimSpace(p.Product+" "+p.Version)))
		}
	}
	cb.log("INFO", fmt.Sprintf("port scan — %d open port(s) across %d host(s)", total, len(targets)))
	return total
}

// ── naabu adapter ─────────────────────────────────────────────────────────

type naabuRow struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	TLS      bool   `json:"tls"`
}

func naabuScan(ctx context.Context, r plugin.Runner, dir string, ips []string, portSpec string, rps int) ([]naabuRow, error) {
	bin, err := r.Look("naabu")
	if err != nil {
		return nil, err
	}
	lf, err := writeList(dir, "naabu-hosts.txt", ips)
	if err != nil {
		return nil, err
	}
	rate := rps * 10
	if rate < 100 {
		rate = 100
	}
	if rate > 1000 {
		rate = 1000
	}
	// "-s c" is an unprivileged TCP connect scan (no CAP_NET_RAW needed).
	argv := []string{
		bin, "-list", lf, "-s", "c", "-json", "-silent", "-no-color",
		"-rate", itoa(rate), "-c", "25", "-timeout", "1500", "-retries", "1",
		"-warm-up-time", "0",
	}
	if portSpec == "" {
		argv = append(argv, "-top-ports", "100")
	} else if strings.HasPrefix(portSpec, "top-") {
		argv = append(argv, "-top-ports", strings.TrimPrefix(portSpec, "top-"))
	} else {
		argv = append(argv, "-p", portSpec)
	}
	out, _, err := r.Exec(ctx, argv)
	if err != nil {
		return nil, err
	}
	var rows []naabuRow
	for _, ln := range jsonLines(out) {
		var row naabuRow
		if json.Unmarshal(ln, &row) == nil && row.Port > 0 {
			if row.IP == "" {
				row.IP = row.Host
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

// ── nmap -sV adapter (greppable output) ───────────────────────────────────

type nmapService struct {
	Port    int
	Name    string
	Product string
	Version string
	Extra   string
	TLS     bool
}

var (
	reNmapPorts = regexp.MustCompile(`Ports:\s*(.+)`)
	reNmapHost  = regexp.MustCompile(`Host:\s*(\S+)`)
)

// nmapServiceScan runs one `nmap -sV` over every discovered host and returns a
// map keyed "ip:port" -> service detail.
func nmapServiceScan(ctx context.Context, r plugin.Runner, dir string, byIP map[string][]int) map[string]nmapService {
	bin, err := r.Look("nmap")
	if err != nil {
		return nil
	}
	portSet := map[int]bool{}
	ips := make([]string, 0, len(byIP))
	for ip, ports := range byIP {
		ips = append(ips, ip)
		for _, p := range ports {
			portSet[p] = true
		}
	}
	if len(ips) == 0 || len(portSet) == 0 {
		return nil
	}
	sort.Strings(ips)
	ps := make([]string, 0, len(portSet))
	for p := range portSet {
		ps = append(ps, strconv.Itoa(p))
	}
	sort.Strings(ps)

	lf, err := writeList(dir, "nmap-hosts.txt", ips)
	if err != nil {
		return nil
	}
	argv := []string{
		bin, "-sV", "-Pn", "-T4", "--version-light",
		"--host-timeout", "90s", "--max-retries", "2",
		"-p", strings.Join(ps, ","), "-oG", "-", "-iL", lf,
	}
	out, _, err := r.Exec(ctx, argv)
	if err != nil {
		return nil
	}
	res := map[string]nmapService{}
	for _, ln := range strings.Split(out, "\n") {
		hm := reNmapHost.FindStringSubmatch(ln)
		pm := reNmapPorts.FindStringSubmatch(ln)
		if hm == nil || pm == nil {
			continue
		}
		ip := hm[1]
		// "22/open/tcp//ssh//OpenSSH 6.6.1p1 Ubuntu.../, 80/open/tcp//http//Apache..."
		for _, entry := range strings.Split(pm[1], ",") {
			f := strings.Split(strings.TrimSpace(entry), "/")
			if len(f) < 7 || f[1] != "open" {
				continue
			}
			pn, _ := strconv.Atoi(f[0])
			prodVer := strings.TrimSpace(strings.ReplaceAll(f[6], "|", " "))
			s := nmapService{Port: pn, Name: f[4], Extra: prodVer}
			if prodVer != "" {
				parts := strings.SplitN(prodVer, " ", 2)
				s.Product = parts[0]
				if len(parts) > 1 {
					s.Version = strings.TrimSpace(parts[1])
				}
			}
			s.TLS = strings.Contains(f[4], "ssl") || strings.Contains(prodVer, "SSL")
			res[ip+":"+strconv.Itoa(pn)] = s
		}
	}
	return res
}
