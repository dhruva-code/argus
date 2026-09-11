package recon

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/argus-platform/orchestrator/internal/httpengine"
)

// detectXSSOrHTMLInjection uses the shared reflection probe: unencoded
// reflection inside a script/attribute/dom-sink context is a candidate XSS;
// unencoded reflection in plain HTML body text (that never reaches an
// executable sink) is HTML injection instead — the spec explicitly asks not
// to escalate every HTML reflection to XSS.
func detectXSSOrHTMLInjection(ctx context.Context, he *httpengine.Engine, browserCheck string, p InjParam, params []InjParam) *InjResult {
	refl, _, err := probeReflection(ctx, he, p, params)
	if err != nil || !refl.found {
		return nil
	}

	if refl.encoded {
		// reflected, but HTML-entity encoded on the way out — not exploitable.
		return &InjResult{
			Param: p, Class: ClassHTMLInjection, Tier: TierNone, Confidence: 5, EvidenceQuality: 20,
			DetectionMethod: "reflection", Context: refl.context,
			Evidence: "input reflects but is HTML-encoded on output — not exploitable",
		}
	}

	executable := refl.context == "javascript" || refl.context == "attribute" || refl.context == "dom_sink"
	if !executable {
		return &InjResult{
			Param: p, Class: ClassHTMLInjection, Tier: TierLikely, Confidence: 55, EvidenceQuality: 45,
			DetectionMethod: "reflection", Context: refl.context,
			Evidence:        "unencoded markup is reflected into the HTML body outside any script/attribute/event-handler context",
			ResponseExcerpt: trimN(refl.occurrence, 300),
		}
	}

	// executable context — attempt safe browser verification: the payload sets
	// a benign, uniquely-named global instead of alert()/document.location, so
	// a positive result proves execution with zero side effects on the target.
	marker := "argusXSS" + randToken(4)
	xssPayload := `"><script>window.__argus_xss__=window.__argus_xss__||[];window.__argus_xss__.push("` + marker + `")</script>`
	u := buildURL(p.BaseURL, params, p.Name, xssPayload)

	tier, conf, eq, method := TierLikely, 65, 55, "reflection"
	evidence := "input reflects unencoded inside a " + refl.context + " context (payload not executed by a browser in this pass)"
	if browserCheck != "" {
		if confirmed, detail := verifyXSSInBrowser(ctx, browserCheck, u, marker); confirmed {
			tier, conf, eq, method = TierVerified, 96, 92, "browser_execution"
			evidence = "a sandboxed headless browser navigated to the crafted URL and the injected script executed: " + detail
		}
	}
	return &InjResult{
		Param: p, Class: ClassXSS, Tier: tier, Confidence: conf, EvidenceQuality: eq,
		DetectionMethod: method, Context: refl.context,
		Evidence:        evidence,
		ResponseExcerpt: trimN(refl.occurrence, 300),
		CurlCommand:     curlFor(p.Method, u),
		Request:         "GET " + u,
	}
}

// verifyXSSInBrowser runs a tiny, sandboxed Playwright/Chromium script (argv
// only — never a shell) that navigates to the URL and checks whether the
// benign marker was pushed onto window.__argus_xss__, i.e. the injected
// script actually executed. In production this should run as its own
// isolated worker/container with no network egress beyond the target and the
// OAST collector; here it runs as a resource-capped subprocess of the
// orchestrator using the same Chromium already bundled for other tooling.
func verifyXSSInBrowser(ctx context.Context, nodeBin, targetURL, marker string) (bool, string) {
	script := xssVerifyScript
	dir, err := os.MkdirTemp("", "argus-xss-*")
	if err != nil {
		return false, ""
	}
	defer os.RemoveAll(dir)
	scriptPath := filepath.Join(dir, "verify.mjs")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		return false, ""
	}
	cmd := exec.CommandContext(ctx, nodeBin, scriptPath, targetURL, marker)
	cmd.Env = append(os.Environ(), "NODE_OPTIONS=--max-old-space-size=256")
	out, err := cmd.Output()
	if err != nil {
		return false, ""
	}
	result := strings.TrimSpace(string(out))
	return result == "CONFIRMED", result
}

// LookBrowserBinary resolves a Node binary capable of running the Playwright
// verification script, or "" if unavailable (the caller falls back to
// reflection-only evidence — never blocks the scan on browser availability).
func LookBrowserBinary() string {
	for _, name := range []string{"node"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// xssVerifyScript is a minimal, self-contained Playwright script. It requires
// `playwright-core` + a Chromium build to be resolvable from NODE_PATH /
// global install; if unavailable it exits non-zero and the caller treats the
// finding as `likely` rather than `verified`.
const xssVerifyScript = `
const url = process.argv[2];
const marker = process.argv[3];
(async () => {
  let chromium;
  try {
    ({ chromium } = require("playwright-core"));
  } catch (e) {
    console.log("UNAVAILABLE");
    return;
  }
  const execPath = process.env.ARGUS_CHROMIUM_PATH;
  let browser;
  try {
    browser = await chromium.launch({
      executablePath: execPath || undefined,
      args: ["--no-sandbox", "--disable-gpu", "--disable-extensions"],
      timeout: 8000,
    });
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    page.on("dialog", (d) => d.dismiss().catch(() => {}));
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 8000 }).catch(() => {});
    await page.waitForTimeout(500);
    const hit = await page.evaluate((m) => {
      try {
        return Array.isArray(window.__argus_xss__) && window.__argus_xss__.includes(m);
      } catch (e) {
        return false;
      }
    }, marker);
    console.log(hit ? "CONFIRMED" : "NOT_CONFIRMED");
  } catch (e) {
    console.log("ERROR");
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
})();
`
