# Real frontier matrix

Multi-scenario live matrix for REPI real-platform capability. This sits above `frontier-gate/`: instead of scoring only the latest artifact per family, it runs or selects distinct positive and negative cases and checks that the harness does not inflate generic 2xx or blocked states into target-note success.

## Usage

Score latest evidence plus the aggregate frontier strict gate:

```bash
node bench/recon-remote/frontier-matrix/run.mjs
```

Run the live matrix:

```bash
node bench/recon-remote/frontier-matrix/run.mjs --live
```

Release-blocking mode:

```bash
node bench/recon-remote/frontier-matrix/run.mjs --live --strict
```

Strict latest-evidence mode also enforces freshness by default, so old passing
artifacts cannot keep the matrix green indefinitely:

```bash
node bench/recon-remote/frontier-matrix/run.mjs --strict --fresh
```

Limit live cases while developing:

```bash
RECON_MATRIX_CASES=xhs_auto_discovery,xhs_search_negative \
  node bench/recon-remote/frontier-matrix/run.mjs --live
```

## Scenarios

| Scenario | Purpose |
|---|---|
| `bilibili_wbi_runtime` | Positive Bilibili runtime WBI signer/bundle/signed-request evidence. |
| `bilibili_media_cdn_boundary` | Derived positive Bilibili signed media/CDN boundary: WBI signed playurl, reachable DASH media, backup media, reachable HTTP status, and multiple host classes. |
| `bilibili_multipage_wbi_container` | Positive Bilibili multi-page container case: default `?p=2` target, multi-page pagelist, WBI signed DASH playurl, WBI media candidates, reachable media, and host-class diversity. |
| `bilibili_per_page_cid_boundary` | Derived hard Bilibili per-page boundary: requested `?p=2`, selected page/CID, pagelist row CID, result CID, WBI signed playurl, and media probes must all bind to the same non-first page. |
| `xhs_auto_discovery` | Positive Xiaohongshu seed-page discovery: extract tokenized note URL, chain into XHS, replay target note/feed signed 2xx. |
| `xhs_discovery_hit_rate` | Derived positive Xiaohongshu discovery quality gate: tokenized candidate provenance, attempted candidates, signed-header evidence, and configurable hit rate (`RECON_MATRIX_XHS_DISCOVERY_MIN_HIT_RATE`, default `1`). |
| `xhs_search_negative` | Negative-control Xiaohongshu search case: `search/notes` permission/login boundaries must not count as target note/feed success. |
| `douyin_structured_api` | Positive Douyin runtime observed + independently replayed structured aweme API. |
| `douyin_cookie_boundary` | Derived negative-control Douyin replay boundary: no-cookie replay may return HTTP 200 but must stay structurally empty/divergent, while exact-cookie replay carries structured aweme data. |
| `frontier_strict` | Aggregate `frontier-gate --strict` binding over latest evidence. |

Derived scenarios reuse their source live run (`bilibili_wbi_runtime`,
`xhs_auto_discovery`, or `douyin_structured_api`) so the matrix gets stricter
without adding duplicate browser sessions. The multi-page Bilibili case is a
separate live target because it must prove a `?p=2` container rather than reusing
the single-page seed.

## Freshness gate

`--fresh` / `RECON_MATRIX_FRESHNESS=1` requires every scenario artifact path and
nested `frontier-gate` dependency artifact to be newer than
`RECON_MATRIX_MAX_ARTIFACT_AGE_HOURS` (default `24`). `--strict` turns this on
unless freshness is disabled. This is intentionally a verification-quality gate:
if latest evidence is stale, rerun `--live --strict` instead of claiming a stale
pass.

## Output

```text
.repi-harness/evidence/remote/frontier-matrix/<timestamp>/
artifact.md
result.json
<scenario>.stdout.txt
<scenario>.stderr.txt
```
