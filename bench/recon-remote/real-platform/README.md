# Real platform hard benchmark

High-difficulty public-network reverse benchmark for real platforms. It focuses on runtime truth: public page state, API replay, signed/ephemeral media URLs, CDN probes, anti-bot/header surfaces, and browser/CDP evidence.

## Usage

```bash
node bench/recon-remote/real-platform/run.mjs https://www.bilibili.com/video/BV1odL76QE6B bilibili-video
node bench/recon-remote/real-platform/run.mjs 'https://www.xiaohongshu.com/explore/66237c6e000000001c00893f' xiaohongshu-note
RECON_XHS_AUTO_DISCOVER=1 node bench/recon-remote/real-platform/run.mjs https://www.xhs-download.org/zh xiaohongshu-note
node bench/recon-remote/real-platform/run.mjs --self-test
```

Profiles:

| Profile | Chain |
|---|---|
| `bilibili-video` | Extract BV, parse `?p=` page selection, call view/pagelist/playurl, bind selected page/CID back to `pagelist.rows`, rebuild WBI `w_rid` from `nav.wbi_img`, call signed `x/player/wbi/playurl`, classify DASH/durl candidates, probe CDN media URLs with HEAD/range, emit media probe matrix and deterministic WBI signer self-test. With `RECON_BROWSER=1` or `RECON_BILI_CDP=1`, also captures Chrome/CDP runtime, browser-emitted WBI signed requests, signer stack events, external JS bundle hints, and buvid/media URL runtime drift. |
| `xiaohongshu-note` | Chrome/CDP runtime capture, extract note IDs, `/api/sns/web/*` hints, xsec/signature/anti-bot signals, rendered state/response bodies, signer bundle snippets, signed request timeline, runtime signer events, trigger bounded runtime probes for note/feed/search modules, replay a ranked ladder of captured signed GET/POST API requests with no-cookie and exact-cookie variants, classify generic signed 2xx web replay separately from eligible target note/feed/search-notes 2xx vs 461 verification/risk challenges, and emit first-divergence evidence. With `RECON_XHS_AUTO_DISCOVER=1`, it can start from a public seed page, extract tokenized `xiaohongshu.com/explore/<note>` candidates from HTML/JSON/headers/POST bodies, then chain into XHS and replay the discovered target. |
| `generic-cdp` | Chrome/CDP request/response/body/storage baseline and generic signature/header bundle trace for unknown platforms. |

`--self-test` validates the embedded Bilibili WBI mixin table, signing normalizer, query ordering and deterministic `w_rid` hash without network access.

Bilibili browser trace example:

```bash
RECON_BROWSER=1 RECON_PROBE_LIMIT=4 \
  node bench/recon-remote/real-platform/run.mjs https://www.bilibili.com/video/BV1odL76QE6B bilibili-video
```

Media probes use `HEAD` plus a bounded `Range: bytes=0-N` GET for media-like
responses. `RECON_PROBE_BODY_BYTES` controls the byte cap (default `4096`) and
the artifact records `bodySha256`/`bodyBytes` without downloading full media.

## Output

```text
.pi/evidence/remote/real-platform/<profile>/<host>/<timestamp>/
artifact.md
result.json
browser.json       # CDP profiles
browser.html       # when rendered HTML is available
```


## Bilibili runtime frontier evidence

The Bilibili profile does not stop at offline `w_rid` reconstruction. In browser mode it injects fetch/XHR/header/storage/cookie/crypto hooks, observes real player WBI requests such as `x/player/wbi/playurl`, records signer stack anchors from loaded player bundles, and fetches referenced JS bundles for signer-term snippets. This is the evidence consumed by `frontier-gate` for `bilibili_runtime_wbi_bundle_trace`.

For multi-page videos, the profile now records `requestedPage`, `selectedPage`,
`selectedCid`, `pagelist.rows[]`, and `pageBoundary`. A `?p=2` run must prove
that the selected CID equals the page-2 pagelist row and differs from the first
page/view CID before the frontier matrix accepts the per-page CID boundary.


## Xiaohongshu replay ladder

The Xiaohongshu profile ranks captured `/api/sns/web/*`, `/api/sns/h5/*`, and `/web_api/sns/*` GET/POST requests by endpoint class, method/body hash, signed header coverage, observed status, and response shape. POST seeds keep distinct body variants in the replay ladder instead of deduping by URL alone. For each selected seed it replays both `no-cookie` and `exact-cookie` variants, using CDP `Network.getAllCookies` internally while redacting cookie values in artifacts.

The output separates:

- `best2xxSignedReplay`: any structured signed 2xx replay, including generic endpoints such as `user/me`; this is not enough to pass the Xiaohongshu frontier.
- `bestTargetNote2xxSignedReplay`: strict target note/feed/search-notes structured 2xx replay from eligible endpoint classes (`h5-note-info`, `web-feed`, `web-api-note`, `web-note-or-feed`, or `web-search-notes`); this is the only Xiaohongshu frontier-pass replay signal.
- `challengeMatrix` / `targetEndpointCoverage`: status/body/header taxonomy for `verify302`, `riskPolicy400`, login-missing, permission, unavailable, empty-data, and structured 2xx boundaries.
- `seedInventory` / `dedupeCollisions`: selected and dropped seeds with method, body hash, endpoint class, and rank evidence.

Search recommendation endpoints are treated as generic structured replay and cannot satisfy the note/feed frontier by themselves.

## Xiaohongshu auto discovery

Set `RECON_XHS_AUTO_DISCOVER=1` when the input is a landing/search/documentation page rather than a final note URL. The profile scans captured runtime state for tokenized `xiaohongshu.com/explore/<note_id>?xsec_token=...&xsec_source=...` candidates, ranks tokenized candidates above bare note IDs, and launches bounded child captures under:

```text
<artifact_dir>/discovery/<rank>-<note_id>/
```

The parent `result.json` records `xhsDiscovery.candidates`, `xhsDiscovery.attempts`, `effectiveTarget`, and `discoveredArtifact`. A successful chain returns `xhs-auto-discovery-target-note-replay-confirmed` while keeping raw `xsec_token`, cookies, and signed headers redacted in written artifacts.
