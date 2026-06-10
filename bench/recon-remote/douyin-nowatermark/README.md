# Douyin no-watermark live benchmark

A live REPI benchmark for short-video media URL reverse analysis. Given a Douyin share/video URL, the harness records redirect behavior, captures browser/CDP runtime traffic when static extraction is weak, extracts `aweme_id` / media IDs / state JSON hints, inventories `a_bogus` / `msToken` / webid / `X-Bogus` style anti-bot parameters, records signer-bundle hints, ranks media URL candidates, builds `playwm -> play` style no-watermark hypotheses, verifies candidates with `HEAD` plus bounded `Range` body-hash probes, and attempts exact replay of browser-observed signed aweme APIs.

It writes evidence only under `.repi-harness/evidence/remote/douyin-nowatermark/`; those runtime artifacts are git-ignored.

## Usage

```bash
export DOUYIN_SHARE_URL='https://v.douyin.com/xxxxx/'
node bench/recon-remote/douyin-nowatermark/run.mjs
```

or:

```bash
node bench/recon-remote/douyin-nowatermark/run.mjs 'https://v.douyin.com/xxxxx/'
```

Force browser/CDP capture through local Chrome:

```bash
RECON_BROWSER=1 RECON_PROBE_LIMIT=12 \
  node bench/recon-remote/douyin-nowatermark/run.mjs 'https://v.douyin.com/xxxxx/'
```

Probe generated aweme detail endpoint hypotheses after an `aweme_id` is found:

```bash
RECON_API_PROBE=1 RECON_BROWSER=1 \
  node bench/recon-remote/douyin-nowatermark/run.mjs 'https://v.douyin.com/xxxxx/'
```

Capture and replay runtime signed aweme APIs observed in browser traffic:

```bash
RECON_BROWSER=1 RECON_API_PROBE=1 RECON_DOUYIN_RUNTIME_API_LIMIT=4 \
  node bench/recon-remote/douyin-nowatermark/run.mjs 'https://www.douyin.com/video/<aweme_id>'
```

## Environment

| Variable | Default | Purpose |
|---|---:|---|
| `RECON_BROWSER` | `auto` | `auto`, `1`, or `0`; uses local Chrome CDP capture when static extraction is weak or when forced. |
| `RECON_BROWSER_TIMEOUT_MS` | `45000` | Max browser capture time. |
| `RECON_BROWSER_QUIET_MS` | `2500` | Network quiet window before ending capture. |
| `RECON_PROBE_LIMIT` | `28` | Number of ranked media candidates / transform hypotheses to probe. |
| `RECON_PROBE_BODY_BYTES` | `4096` | Bounded media prefix bytes to read and hash for byte-proof probes. |
| `RECON_API_PROBE` | unset | Set `1` to request generated aweme detail endpoint hypotheses. |
| `RECON_DOUYIN_RUNTIME_API_LIMIT` | `4` | Max browser-observed signed aweme API seeds to replay with no-cookie and exact-cookie variants. |
| `RECON_MAX_REDIRECTS` | `10` | Share URL redirect limit. |
| `RECON_MAX_PROBE_REDIRECTS` | `5` | Media probe redirect limit. |
| `RECON_MAX_BODY_BYTES` | `5000000` | Max stored text/HTML body bytes per source. |
| `RECON_USER_AGENT` | mobile Chrome UA | Browser/fetch user-agent. |
| `RECON_COOKIE` | unset | Optional runtime cookie for browser/fetch; redacted in artifacts by default. |
| `RECON_EXTRA_HEADERS_JSON` | `{}` | Additional headers as JSON. |
| `RECON_REDACT_HEADERS` | `1` | Set `0` to keep sensitive headers in local evidence. |
| `RECON_CHROME_BIN` | auto | Chrome/Chromium binary path. |

## Output

Artifacts are written to:

```text
.repi-harness/evidence/remote/douyin-nowatermark/<timestamp>/
```

Files:

```text
artifact.md    Human-readable evidence summary
result.json    Structured redirect/candidate/probe data
body.html      Static final response body
browser.json   Chrome/CDP request/response/body/storage artifact when browser capture runs
browser.html   Rendered document HTML when browser capture runs
```

`result.json` includes `runtimeApiReplay` when browser capture runs:

- `observedStructuredApi`: browser-observed 2xx structured aweme JSON; this proves runtime signer/browser flow reached the API.
- `bestReplayedStructuredApi`: Node replay of the captured signed URL/headers/cookies that returns structured 2xx JSON; this is the frontier-pass signal.
- `firstDivergence`: first observed-vs-replay status/body mismatch, useful for finding the anti-bot boundary.

Captured cookies and raw replay headers stay in memory for replay and are redacted or omitted from written artifacts.

## Verdicts

| Verdict | Meaning |
|---|---|
| `strong-candidate` | A reachable video candidate was probed and has no common watermark markers in the URL/redirect path. |
| `video-candidate` | A video resource was found, but no-watermark confidence is weaker. |
| `needs-manual-replay` | Browser/CDP found relevant candidates, but replay or endpoint parameters need manual verification. |
| `needs-browser-capture` | Static fetch found candidate URLs, but browser/CDP capture is needed. |
| `no-candidate` | No usable media candidates were extracted. |

Runtime-observed structured aweme JSON is partial evidence. The hard frontier only passes when `bestReplayedStructuredApi` exists and is a structured 2xx response.

## REPI follow-up

Use the generated `artifact.md` as input to:

```text
/re-map <share-url> 2
/re-live-browser run <share-url>
/re-replayer plan <candidate-url>
/re-verifier matrix <artifact-dir>
```
