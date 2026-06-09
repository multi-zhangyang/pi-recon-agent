# Same-window live frontier gate

Runs or binds Bilibili, Xiaohongshu, and Douyin evidence inside one freshness window and separates proven runtime facts from unsolved frontier claims.

```bash
node bench/recon-remote/same-window-live/run.mjs
node bench/recon-remote/same-window-live/run.mjs --strict
node bench/recon-remote/same-window-live/run.mjs --use-latest
```

The gate is intentionally harder than `hard-score`:

- Bilibili must prove WBI + requested page CID and, for frontier pass, CDN Range/body evidence.
- Xiaohongshu must capture `x-s`/`x-t` signer evidence and, for frontier pass, eligible target note/feed/search-notes structured 2xx. The default XHS target is a live discovery landing with `RECON_XHS_AUTO_DISCOVER=1`; set `RECON_SAME_WINDOW_XHS_URL` for a fixed note.
- Douyin must replay a browser-captured signed structured API and, for frontier pass, produce no-watermark media byte/hash proof.
- Artifacts must be generated inside one window (`RECON_SAME_WINDOW_MAX_SPAN_MS`, default 15 minutes) and be fresh (`RECON_SAME_WINDOW_MAX_AGE_MS`, default 30 minutes).

Outputs:

```text
.pi/evidence/remote/same-window-live/<timestamp>/
artifact.md
result.json
bilibili.stdout.txt / bilibili.stderr.txt
xiaohongshu.stdout.txt / xiaohongshu.stderr.txt
douyin.stdout.txt / douyin.stderr.txt
hard-score.stdout.txt / hard-score.stderr.txt
```

Useful knobs:

| Variable | Default | Purpose |
|---|---:|---|
| `RECON_SAME_WINDOW_XHS_URL` | `https://www.xhs-download.org/zh` | XHS landing or fixed note URL. |
| `RECON_SAME_WINDOW_XHS_AUTO_DISCOVER` | `1` | Let the XHS runner promote a discovered tokenized note when the landing page exposes one. |
| `RECON_SAME_WINDOW_XHS_DISCOVERY_LIMIT` | `1` | Number of discovered note candidates to replay. |
| `RECON_SAME_WINDOW_DOUYIN_PROBE_LIMIT` | `12` | Number of Douyin media candidates/hypotheses to probe. |
| `RECON_PROBE_BODY_BYTES` | `4096` | Bounded media prefix bytes hashed by body-proof probes. |

Verdicts:

| Verdict | Meaning |
|---|---|
| `same-window-live-passed` | All required same-window frontier gates passed. |
| `same-window-live-frontier-gaps` | Some runtime proof exists but one or more frontier gates failed; inspect `frontierGaps`. |
| `same-window-live-failed` | No useful required gate passed. |
