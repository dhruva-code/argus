package recon

import (
	"context"
	"regexp"
	"time"

	"github.com/argus-platform/orchestrator/internal/httpengine"
)

// dbErrorSignatures are error-based SQLi indicators. Matching one is treated
// as `likely` on its own (a real DB error leaking to the response is already
// meaningful); matching plus the baseline being clean raises it further.
var dbErrorSignatures = []struct {
	dbms string
	re   *regexp.Regexp
}{
	{"MySQL", regexp.MustCompile(`(?i)you have an error in your sql syntax|warning: mysqli?_|mysql_fetch_|check the manual that corresponds to your (mysql|mariadb) server`)},
	{"PostgreSQL", regexp.MustCompile(`(?i)pg_query\(\)|unterminated quoted string|PostgreSQL.*?ERROR|syntax error at or near`)},
	{"MSSQL", regexp.MustCompile(`(?i)unclosed quotation mark after the character string|microsoft ole db provider for sql server|System\.Data\.SqlClient|SqlException`)},
	{"Oracle", regexp.MustCompile(`(?i)ORA-\d{5}|oracle error|oci_(parse|execute)`)},
	{"SQLite", regexp.MustCompile(`(?i)sqlite3?\.OperationalError|SQLite3::SQLException|unrecognized token`)},
	{"Generic", regexp.MustCompile(`(?i)SQLSTATE\[|SQL syntax.*?error|ODBC (SQL Server|Driver)|JDBC (Driver|Exception)`)},
}

// time-based payload pairs, keyed by a rough DBMS guess (we don't know which
// backend it is up front, so a couple of conservative, side-effect-free
// candidates are tried and the first that shows a consistent delay wins).
var sqliTimePayloads = []struct {
	dbms, suffix string
}{
	{"MySQL/Postgres", `' AND (SELECT 4200 FROM (SELECT(SLEEP(%d)))x)-- -`},
	{"MSSQL", `';WAITFOR DELAY '0:0:%d'--`},
	{"Oracle", `' AND (SELECT CASE WHEN (1=1) THEN dbms_pipe.receive_message(('a'),%d) ELSE 1 END FROM dual)-- -`},
	{"Generic-numeric", ` AND SLEEP(%d)`}, // for unquoted numeric params
}

const sqliDelaySeconds = 4

// detectSQLi runs error-based, boolean-based and (last, most expensive)
// time-based checks. It stops as soon as a tier=verified result is reached.
func detectSQLi(ctx context.Context, he *httpengine.Engine, p InjParam, params []InjParam, base injBaseline) *InjResult {
	// ── error-based ─────────────────────────────────────────────────────
	probe := p.Value + `'"\`
	u := buildURL(p.BaseURL, params, p.Name, probe)
	resp, err := he.Get(ctx, u)
	if err == nil {
		body := string(resp.Body)
		for _, sig := range dbErrorSignatures {
			if sig.re.MatchString(body) && !sig.re.MatchString(base.body) {
				tier := TierLikely
				conf, eq := 70, 65
				// confirm: baseline (unmodified) must NOT error, and a second,
				// differently-shaped probe should also error, for `verified`.
				u2 := buildURL(p.BaseURL, params, p.Name, p.Value+`)) OR (1=1`)
				if resp2, err2 := he.Get(ctx, u2); err2 == nil && sig.re.MatchString(string(resp2.Body)) {
					tier, conf, eq = TierVerified, 92, 88
				}
				return &InjResult{
					Param: p, Class: ClassSQLi, Tier: tier, Confidence: conf, EvidenceQuality: eq,
					DetectionMethod: "error_based", DBMS: sig.dbms,
					Evidence:        "database error signature (" + sig.dbms + ") appeared only when the parameter was modified",
					ResponseExcerpt: trimN(excerptAround(body, sig.re.FindString(body)), 300),
					CurlCommand:     curlFor(p.Method, u),
					Request:         "GET " + u,
				}
			}
		}
	}

	// ── boolean-based (differential response) ──────────────────────────
	uTrue := buildURL(p.BaseURL, params, p.Name, p.Value+`' AND '1'='1`)
	uFalse := buildURL(p.BaseURL, params, p.Name, p.Value+`' AND '1'='2`)
	respTrue, errT := he.Get(ctx, uTrue)
	respFalse, errF := he.Get(ctx, uFalse)
	if errT == nil && errF == nil {
		simTrueBase := bodySimilarity(base.body, string(respTrue.Body))
		simTrueFalse := bodySimilarity(string(respTrue.Body), string(respFalse.Body))
		statusDiff := respTrue.StatusCode != respFalse.StatusCode
		if (simTrueBase > 0.92 && simTrueFalse < 0.75) || (statusDiff && simTrueFalse < 0.85) {
			return &InjResult{
				Param: p, Class: ClassSQLi, Tier: TierLikely, Confidence: 62, EvidenceQuality: 55,
				DetectionMethod: "boolean_based",
				Evidence: "the 1=1 response matches the baseline while the 1=2 response differs materially " +
					"(similarity true/false: " + pct(simTrueFalse) + ")",
				CurlCommand: curlFor(p.Method, uTrue),
				Request:     "GET " + uTrue + "\n(compared against)\nGET " + uFalse,
			}
		}
	}

	// ── time-based (last resort — one request per candidate payload) ────
	for _, tp := range sqliTimePayloads {
		if tp.dbms == "Generic-numeric" && p.ParamType != "numeric" {
			continue
		}
		payload := p.Value
		if tp.dbms == "Generic-numeric" {
			payload = p.Value + sprintfDelay(tp.suffix, sqliDelaySeconds)
		} else {
			payload = p.Value + sprintfDelay(tp.suffix, sqliDelaySeconds)
		}
		u := buildURL(p.BaseURL, params, p.Name, payload)
		start := time.Now()
		resp, err := he.Get(ctx, u)
		elapsed := time.Since(start)
		if err != nil || resp == nil {
			continue
		}
		if elapsed >= time.Duration(sqliDelaySeconds-1)*time.Second+500*time.Millisecond && elapsed > base.elapsed*3 {
			// confirm once more to rule out network jitter
			start2 := time.Now()
			_, err2 := he.Get(ctx, buildURL(p.BaseURL, params, p.Name, p.Value))
			fastAgain := time.Since(start2) < base.elapsed*2+time.Second
			tier, conf, eq := TierLikely, 68, 60
			if err2 == nil && fastAgain {
				tier, conf, eq = TierVerified, 90, 85
			}
			return &InjResult{
				Param: p, Class: ClassSQLi, Tier: tier, Confidence: conf, EvidenceQuality: eq,
				DetectionMethod: "time_based", DBMS: tp.dbms,
				Evidence: "injected a " + itoa(sqliDelaySeconds) + "s conditional delay (" + tp.dbms +
					" syntax); observed " + elapsed.Round(time.Millisecond).String() +
					" vs baseline " + base.elapsed.Round(time.Millisecond).String(),
				CurlCommand: curlFor(p.Method, u),
				Request:     "GET " + u,
			}
		}
	}
	return nil
}

func sprintfDelay(tmpl string, secs int) string {
	out := make([]byte, 0, len(tmpl))
	for i := 0; i < len(tmpl); i++ {
		if tmpl[i] == '%' && i+1 < len(tmpl) && tmpl[i+1] == 'd' {
			out = append(out, []byte(itoa(secs))...)
			i++
			continue
		}
		out = append(out, tmpl[i])
	}
	return string(out)
}

func pct(f float64) string {
	return itoa(int(f*100)) + "%"
}
