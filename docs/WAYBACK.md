# Wayback URL discovery

## What it does

`url_endpoint_discovery` (phase 7 of the recon pipeline) queries the
[Internet Archive's CDX API](https://web.archive.org/cdx/search/cdx) for
every in-scope root domain, alongside the existing `gau` (historical URLs)
and `katana` (live crawl) sources. Implementation: `waybackFetch()` in
`orchestrator/internal/recon/endpoints.go`.

```
domain → CDX API query → URL + capture timestamp per row
       → scope.Evaluate() (same check every other source's output goes through)
       → makeEndpoint() (normalize, route-template, extract query params)
       → dedup against gau/katana/well-known-probe results already found
       → Endpoint upsert (source="wayback", wayback_first_seen/last_seen)
```

## Why it's a direct HTTP call, not a CLI tool

Every other historical-URL/crawl source in this codebase shells out to a
binary via `plugin.Runner` (`gau`, `katana`). The Wayback CDX API has no
CLI wrapper in this build, so `waybackFetch` makes a plain `net/http`
request instead of going through `httpengine.Engine` — that engine
scope-checks the *destination* of every request, and `web.archive.org` is
never part of a project's scope. The URLs the CDX API *returns* still go
through the normal scope check in `makeEndpoint()` before ever being
trusted or emitted — nothing bypasses scope enforcement, only the request
*to the archive itself* does (the same way a `gau`/`katana` binary's own
outbound requests to third-party archive/index services aren't scope-checked
either).

## Deduplication

The orchestrator's endpoint-discovery function keeps one in-memory `seen`
set per scan run, keyed by `(method, normalized_url)`, shared across every
source. If `gau` or `katana` already found a URL in the same scan,
Wayback's rediscovery of it is dropped before ever reaching the gateway —
this is the existing convention for every source in this phase, not
something special-cased for Wayback. Across *separate* scan runs, the
gateway's `upsert_endpoint` merges the `sources` array and updates
`wayback_first_seen`/`wayback_last_seen` to the min/max capture time seen
so far.

In practice, for a well-covered domain, `gau` and Wayback's CDX results
overlap heavily (both ultimately draw on archive data) — seeing `wayback: N
URL(s) → 0 new distinct endpoint(s)` in a job's event log is expected and
correct when `gau` already ran first in the same phase, not a bug.

## Capture timestamp

The CDX query uses `collapse=urlkey`, which returns one representative
capture per unique URL rather than every capture ever made (unbounded for
a popular domain). That single timestamp is used for both
`wayback_first_seen` and `wayback_last_seen` on first discovery; a true
min/max across a URL's full capture history would need a second,
uncollapsed query, which wasn't judged worth doubling the request volume
against a shared public service for this feature.

## Failure handling

A CDX API failure (network error, non-200, malformed JSON) is reported as
`WARNING wayback: <error>` in the job's event log — never as a silent zero
result. `limit=3000` per root bounds worst-case response size; a 20MB
response cap and a 20s HTTP timeout bound worst-case resource use.

## UI

**Project → Wayback URLs** tab: total/new(Wayback-only)/parameterized/
interesting counts, and a filterable table (URL text, domain, extension,
status code, parameterized-only, interesting/sensitive-only) backed by
`GET /api/projects/{id}/endpoints?source=wayback`.

## Known limitation

A domain with no real crawl/archive history (e.g. a freshly-registered or
purely-internal hostname) will correctly return zero Wayback results —
this is accurate, not a defect.
