# GrokX — protocol register → CPA `xai-<email>.json`

HTTP-only xAI signup + local Chrome only for Turnstile. Writes CLIProxyAPI files to `cpa_auths/xai-*.json`.

## Share package defaults

- Browser: `local` (system Chrome/Chromium)
- Concurrency: `register_threads = 7`
- Count: `register_count = 7`
- Local proxy fallback: `http://127.0.0.1:7890`
- **No** accounts, CPA tokens, residential proxies, Roxy token, or mail API keys

## Quick start

1. Install Python 3.11+
2. Run `setup.bat`
3. Edit `config.json`:
   - `cloudflare_api_base` / `cloudflare_api_key` / `default_domains`
   - put proxies in `proxies.txt` if needed
4. Run `start.bat`

## Optional

- Roxy: set `browser_backend=roxy` + `roxy_api_token`; set env `GROKX_BROWSER_BACKEND_DIR` to a folder containing `browser_backend.py`
- Proxies that only work via local hop: `proxy_via_local=auto` chains `127.0.0.1:7890 → residential`

## Outputs

- `cpa_auths/xai-<email>.json` — main product
- `accounts.json` — email/password/sso ledger
