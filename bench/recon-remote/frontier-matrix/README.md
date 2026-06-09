# Real frontier matrix

Multi-scenario live matrix for Pi-RECON real-platform capability. This sits above `frontier-gate/`: instead of scoring only the latest artifact per family, it runs or selects distinct positive and negative cases and checks that the harness does not inflate generic 2xx or blocked states into target-note success.

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

Limit live cases while developing:

```bash
RECON_MATRIX_CASES=xhs_auto_discovery,xhs_search_negative \
  node bench/recon-remote/frontier-matrix/run.mjs --live
```

## Scenarios

| Scenario | Purpose |
|---|---|
| `bilibili_wbi_runtime` | Positive Bilibili runtime WBI signer/bundle/signed-request evidence. |
| `xhs_auto_discovery` | Positive Xiaohongshu seed-page discovery: extract tokenized note URL, chain into XHS, replay target note/feed signed 2xx. |
| `xhs_search_negative` | Negative-control Xiaohongshu search case: `search/notes` permission/login boundaries must not count as target note/feed success. |
| `douyin_structured_api` | Positive Douyin runtime observed + independently replayed structured aweme API. |
| `frontier_strict` | Aggregate `frontier-gate --strict` binding over latest evidence. |

## Output

```text
.pi/evidence/remote/frontier-matrix/<timestamp>/
artifact.md
result.json
<scenario>.stdout.txt
<scenario>.stderr.txt
```
