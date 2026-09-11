package recon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/argus-platform/orchestrator/internal/plugin"
)

// writeList writes one item per line to a temp file and returns its path.
func writeList(dir, name string, items []string) (string, error) {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(strings.Join(items, "\n")+"\n"), 0o600); err != nil {
		return "", err
	}
	return p, nil
}

func jsonLines(out string) [][]byte {
	var lines [][]byte
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "{") {
			lines = append(lines, []byte(ln))
		}
	}
	return lines
}

// ── subfinder ──────────────────────────────────────────────────────────────

type subfinderRow struct {
	Host   string `json:"host"`
	Source string `json:"source"`
	Input  string `json:"input"`
}

// subfinderEnum returns host -> set of passive sources.
func subfinderEnum(ctx context.Context, r plugin.Runner, dir string, roots []string) (map[string]map[string]bool, error) {
	path, err := r.Look("subfinder")
	if err != nil {
		return nil, err
	}
	dl, err := writeList(dir, "roots.txt", roots)
	if err != nil {
		return nil, err
	}
	// The default curated source set only — "-all" pulls in noisy sources that
	// return tens of thousands of junk entries for common names.
	out, _, err := r.Exec(ctx, []string{path, "-dL", dl, "-silent", "-json", "-timeout", "15"})
	if err != nil {
		return nil, err
	}
	found := map[string]map[string]bool{}
	for _, ln := range jsonLines(out) {
		var row subfinderRow
		if json.Unmarshal(ln, &row) != nil || row.Host == "" {
			continue
		}
		h := normHost(row.Host)
		if found[h] == nil {
			found[h] = map[string]bool{}
		}
		src := row.Source
		if src == "" {
			src = "subfinder"
		}
		found[h]["subfinder:"+src] = true
	}
	return found, nil
}

// ── assetfinder ────────────────────────────────────────────────────────────

func assetfinderEnum(ctx context.Context, r plugin.Runner, roots []string) (map[string]bool, error) {
	path, err := r.Look("assetfinder")
	if err != nil {
		return nil, err
	}
	found := map[string]bool{}
	for _, root := range roots {
		out, _, err := r.Exec(ctx, []string{path, "--subs-only", root})
		if err != nil {
			return found, err
		}
		for _, ln := range strings.Split(out, "\n") {
			if h := normHost(ln); h != "" && strings.Contains(h, ".") {
				found[h] = true
			}
		}
	}
	return found, nil
}

// ── dnsx ───────────────────────────────────────────────────────────────────

type dnsxRow struct {
	Host       string   `json:"host"`
	A          []string `json:"a"`
	AAAA       []string `json:"aaaa"`
	CNAME      []string `json:"cname"`
	StatusCode string   `json:"status_code"`
}

func dnsxResolve(ctx context.Context, r plugin.Runner, dir string, hosts []string, rps int) ([]dnsxRow, error) {
	path, err := r.Look("dnsx")
	if err != nil {
		return nil, err
	}
	lf, err := writeList(dir, "resolve.txt", hosts)
	if err != nil {
		return nil, err
	}
	argv := []string{path, "-l", lf, "-json", "-a", "-aaaa", "-cname", "-resp", "-silent", "-retry", "2"}
	if rps > 0 {
		argv = append(argv, "-rate-limit", strconv.Itoa(rps))
	}
	out, _, err := r.Exec(ctx, argv)
	if err != nil {
		return nil, err
	}
	var rows []dnsxRow
	for _, ln := range jsonLines(out) {
		var row dnsxRow
		if json.Unmarshal(ln, &row) == nil && row.Host != "" {
			row.Host = normHost(row.Host)
			rows = append(rows, row)
		}
	}
	return rows, nil
}

// ── httpx ──────────────────────────────────────────────────────────────────

type httpxRow struct {
	URL         string   `json:"url"`
	Input       string   `json:"input"`
	StatusCode  int      `json:"status_code"`
	Title       string   `json:"title"`
	Webserver   string   `json:"webserver"`
	Tech        []string `json:"tech"`
	Scheme      string   `json:"scheme"`
	Port        string   `json:"port"`
	CDN         string   `json:"cdn_name"`
	ContentType string   `json:"content_type"`
	Location    string   `json:"location"`
	Host        string   `json:"host"` // resolved IP
	A           []string `json:"a"`
	TLS         *struct {
		SubjectAN []string `json:"subject_an"`
		SubjectCN string   `json:"subject_cn"`
	} `json:"tls"`
}

func httpxProbe(ctx context.Context, r plugin.Runner, dir string, hosts []string, rps int) ([]httpxRow, error) {
	path, err := r.Look("httpx")
	if err != nil {
		return nil, err
	}
	lf, err := writeList(dir, "probe.txt", hosts)
	if err != nil {
		return nil, err
	}
	argv := []string{
		path, "-l", lf, "-json", "-silent", "-no-color",
		"-status-code", "-title", "-web-server", "-tech-detect", "-content-type",
		"-tls-grab", "-cdn", "-location", "-follow-redirects", "-max-redirects", "3",
		"-timeout", "10", "-retries", "1",
	}
	if rps > 0 {
		argv = append(argv, "-rate-limit", strconv.Itoa(rps))
	}
	out, _, err := r.Exec(ctx, argv)
	if err != nil {
		return nil, err
	}
	var rows []httpxRow
	for _, ln := range jsonLines(out) {
		var row httpxRow
		if json.Unmarshal(ln, &row) == nil && (row.URL != "" || row.Input != "") {
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func normHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	h = strings.TrimPrefix(h, "*.")
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimPrefix(h, "http://")
	h = strings.TrimPrefix(h, "https://")
	if i := strings.IndexAny(h, "/:"); i >= 0 {
		h = h[:i]
	}
	return h
}
