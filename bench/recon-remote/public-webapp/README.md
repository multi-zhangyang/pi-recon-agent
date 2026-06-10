# Public webapp live benchmark

A REPI live benchmark for public web application surface mapping and replay-safe vulnerability confirmation. It records a small probe matrix, response hashes/body heads, route hints, and profile-specific findings under `.repi-harness/evidence/remote/public-webapp/`.

## Usage

```bash
node bench/recon-remote/public-webapp/run.mjs https://preview.owasp-juice.shop juice-shop
node bench/recon-remote/public-webapp/run.mjs https://preview.owasp-juice.shop juice-shop-hard
node bench/recon-remote/public-webapp/run.mjs https://demo.testfire.net testfire
```

Profiles:

| Profile | Checks |
|---|---|
| `juice-shop` | SPA/API reachability, product search API, challenge metadata, exposed FTP/confidential document. |
| `juice-shop-hard` | Multi-stage SQLi login bypass, JWT role verification, authenticated admin API/user/config/basket read probes. |
| `testfire` | Route baseline, reflected search XSS probe, SQLi login-bypass probe. |
| `generic` | Home/robots/sitemap/security.txt and security header baseline. |

## Output

```text
.repi-harness/evidence/remote/public-webapp/<host>/<timestamp>/
artifact.md
result.json
*.head.txt
```
