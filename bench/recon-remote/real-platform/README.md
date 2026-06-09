# Real platform hard benchmark

High-difficulty public-network reverse benchmark for real platforms. It focuses on runtime truth: public page state, API replay, signed/ephemeral media URLs, CDN probes, anti-bot/header surfaces, and browser/CDP evidence.

## Usage

```bash
node bench/recon-remote/real-platform/run.mjs https://www.bilibili.com/video/BV1odL76QE6B bilibili-video
node bench/recon-remote/real-platform/run.mjs 'https://www.xiaohongshu.com/explore/66237c6e000000001c00893f' xiaohongshu-note
```

Profiles:

| Profile | Chain |
|---|---|
| `bilibili-video` | Extract BV/cid, call public view/pagelist/playurl APIs, classify DASH/durl candidates, probe CDN media URLs with HEAD/range. |
| `xiaohongshu-note` | Chrome/CDP runtime capture, extract note IDs, `/api/sns/web/*` hints, xsec/signature/anti-bot signals, rendered state and response bodies. |
| `generic-cdp` | Chrome/CDP request/response/body/storage baseline for unknown platforms. |

## Output

```text
.pi/evidence/remote/real-platform/<profile>/<host>/<timestamp>/
artifact.md
result.json
browser.json       # CDP profiles
browser.html       # when rendered HTML is available
```
