package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/argus-platform/orchestrator/internal/plugin"
	"github.com/argus-platform/orchestrator/internal/scope"
)

// PhaseSourceIntel is the Phase 10 key.
const PhaseSourceIntel = "source_code_intel"

// Repository is a discovered source repository emitted as a "repository" event.
type Repository struct {
	Provider      string    `json:"provider"`
	FullName      string    `json:"full_name"`
	URL           string    `json:"url"`
	Description   string    `json:"description"`
	DefaultBranch string    `json:"default_branch"`
	IsFork        bool      `json:"is_fork"`
	IsArchived    bool      `json:"is_archived"`
	Stars         int       `json:"stars"`
	PushedAt      time.Time `json:"pushed_at"`
	DiscoveredVia string    `json:"discovered_via"`
	MatchedTerms  []string  `json:"matched_terms"`
	IaCFiles      []string  `json:"iac_files"`
	InScope       bool      `json:"in_scope"`
}

type ghRepo struct {
	FullName      string    `json:"full_name"`
	HTMLURL       string    `json:"html_url"`
	Description   string    `json:"description"`
	Fork          bool      `json:"fork"`
	Archived      bool      `json:"archived"`
	Stargazers    int       `json:"stargazers_count"`
	DefaultBranch string    `json:"default_branch"`
	PushedAt      time.Time `json:"pushed_at"`
}

// ghClient is a minimal GitHub REST client. api.github.com is a third-party
// service (not the target) so it is not scope-checked; it is still resolved to
// a public IP.
type ghClient struct {
	token string
	http  *http.Client
}

func newGHClient(token string) *ghClient {
	return &ghClient{token: token, http: &http.Client{Timeout: 20 * time.Second}}
}

func (g *ghClient) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Argus/0.1")
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 403 && resp.Header.Get("X-RateLimit-Remaining") == "0" {
		return fmt.Errorf("github rate limit exhausted (set GITHUB_TOKEN for higher limits)")
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("github %s: %d", path, resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	return json.Unmarshal(body, v)
}

var iacNames = map[string]string{
	"dockerfile": "docker", "docker-compose.yml": "docker", "docker-compose.yaml": "docker",
	".gitlab-ci.yml": "ci", ".github": "ci", "jenkinsfile": "ci",
	"terraform": "terraform", "main.tf": "terraform", "variables.tf": "terraform",
	"kustomization.yaml": "kubernetes", "chart.yaml": "helm", "playbook.yml": "ansible",
	"serverless.yml": "serverless", "cloudformation": "cloudformation",
}

// runSourceIntel enumerates repos for the discovered GitHub orgs (derived from
// the root domains, plus any explicitly configured), records them, flags IaC,
// and runs trufflehog's github scanner over the non-fork ones.
func runSourceIntel(
	ctx context.Context, r plugin.Runner, eng *scope.Engine,
	roots []string, opts Options, cb Callbacks,
) (int, int) {
	orgs := map[string]bool{}
	for _, o := range opts.GitHubOrgs {
		orgs[strings.ToLower(o)] = true
	}
	for _, root := range roots {
		// "example.com" -> candidate org "example"
		label := strings.SplitN(root, ".", 2)[0]
		if len(label) > 1 {
			orgs[strings.ToLower(label)] = true
		}
	}

	gh := newGHClient(opts.GitHubToken)
	repoN, secretN := 0, 0
	terms := append([]string{}, roots...)

	for org := range orgs {
		if cb.cancelled() {
			break
		}
		var repos []ghRepo
		if err := gh.get(ctx, "/orgs/"+org+"/repos?per_page=100&sort=pushed", &repos); err != nil {
			// try it as a user account
			if err2 := gh.get(ctx, "/users/"+org+"/repos?per_page=100&sort=pushed", &repos); err2 != nil {
				cb.log("WARNING", fmt.Sprintf("github %s: %v", org, err))
				continue
			}
		}
		if len(repos) == 0 {
			continue
		}
		cb.log("INFO", fmt.Sprintf("github %s: %d repo(s)", org, len(repos)))

		for _, repo := range repos {
			if cb.cancelled() {
				break
			}
			matched := matchTerms(repo.Description+" "+repo.FullName, terms)
			iac := detectIaC(ctx, gh, repo)
			rp := Repository{
				Provider: "github", FullName: repo.FullName, URL: repo.HTMLURL,
				Description: trim(repo.Description, 500), DefaultBranch: repo.DefaultBranch,
				IsFork: repo.Fork, IsArchived: repo.Archived, Stars: repo.Stargazers,
				PushedAt: repo.PushedAt, DiscoveredVia: "org:" + org,
				MatchedTerms: matched, IaCFiles: iac,
				InScope: len(matched) > 0,
			}
			cb.emitRepo(rp)
			repoN++

			// Scan non-fork, recently-pushed repos for secrets.
			if repo.Fork || repo.Archived || time.Since(repo.PushedAt) > 3*365*24*time.Hour {
				continue
			}
			for _, s := range trufflehogGitHubRepo(ctx, r, repo.HTMLURL, opts.GitHubToken) {
				s.SourceKind = "repo"
				s.Source = repo.HTMLURL
				cb.emitSecret(s)
				secretN++
				cb.log("WARNING", fmt.Sprintf("secret candidate in %s: %s (%s)", repo.FullName, s.DetectorType, s.Location))
			}
		}
	}
	_ = eng
	cb.log("INFO", fmt.Sprintf("source-code intelligence — %d repo(s), %d secret candidate(s)", repoN, secretN))
	return repoN, secretN
}

func matchTerms(text string, terms []string) []string {
	lt := strings.ToLower(text)
	var out []string
	for _, t := range terms {
		if t != "" && strings.Contains(lt, strings.ToLower(t)) {
			out = append(out, t)
		}
	}
	return out
}

func detectIaC(ctx context.Context, gh *ghClient, repo ghRepo) []string {
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
		} `json:"tree"`
	}
	branch := repo.DefaultBranch
	if branch == "" {
		branch = "main"
	}
	if gh.get(ctx, "/repos/"+repo.FullName+"/git/trees/"+branch+"?recursive=1", &tree) != nil {
		return nil
	}
	kinds := map[string]bool{}
	for _, e := range tree.Tree {
		lp := strings.ToLower(e.Path)
		base := lp
		if i := strings.LastIndex(lp, "/"); i >= 0 {
			base = lp[i+1:]
		}
		for name, kind := range iacNames {
			if base == name || strings.Contains(lp, name) {
				kinds[kind] = true
			}
		}
	}
	var out []string
	for k := range kinds {
		out = append(out, k)
	}
	return out
}

func trufflehogGitHubRepo(ctx context.Context, r plugin.Runner, repoURL, token string) []Secret {
	bin, err := r.Look("trufflehog")
	if err != nil {
		return nil
	}
	argv := []string{bin, "github", "--repo", repoURL, "--json", "--no-update", "--no-verification"}
	if token != "" {
		argv = append(argv, "--token", token)
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	out, _, err := r.Exec(cctx, argv)
	if err != nil {
		return nil
	}
	var found []Secret
	for _, ln := range jsonLines(out) {
		var t thResult
		if json.Unmarshal(ln, &t) != nil || t.Raw == "" {
			continue
		}
		loc := repoURL
		if t.SourceMetadata.Data.Filesystem.File != "" {
			loc = t.SourceMetadata.Data.Filesystem.File
		}
		found = append(found, newSecret(t.DetectorName, "trufflehog", loc, t.Raw, t.Verified))
	}
	return dedupeSecrets(found)
}
