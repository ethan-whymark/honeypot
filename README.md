# Honeypot Endpoint

A Cloudflare Workers honeypot that imitates commonly-scanned web paths (fake WordPress logins, `.env` files, exposed git configs) and logs detailed metadata about every visitor to a private dashboard. Built as a learning project to observe real automated scanning traffic on the public internet.

> Because no legitimate user has any reason to visit these paths, every request the honeypot receives is — by definition — suspicious. The whole point of the project is the data this property produces.

**Live:** `https://api-gateway-prod.ethanwhymark.workers.dev/wp-login.php` (paths are deliberately undocumented; the dashboard is token-protected)

---

## How it works

A single Cloudflare Worker listens on a set of trap paths (`/wp-login.php`, `/.env`, `/.git/config`, `/admin`, and others). Every hit is recorded to Workers KV with detailed metadata, then a convincing-but-inert fake response is returned so the scanner registers a "hit" and moves on.

```
   Internet  ─────▶  Cloudflare Worker  ─┬─▶  /dashboard ─▶  token? ─▶  render hits from KV
   (scanners)                            ├─▶  trap path  ─▶  log hit  ─▶  KV.put(ttl: 30d)
                                         │                  └▶  return fake response
                                         └─▶  everything else ─▶  404
```

Each logged record contains:

- Timestamp, source IP, HTTP method, requested path
- The full request headers and any POST body (which is where bots send the credential pairs they're trying)
- Cloudflare edge enrichment: country, city, ASN, AS organisation, timezone — populated from `request.cf` at no cost

## Features

- 15+ trap paths spanning common scanner targets: CMS admin panels, exposed config files, leaked credential paths, Spring Boot actuator endpoints, router/IoT exploit paths
- Edge geo/ASN enrichment via Cloudflare's `request.cf` object
- Token-protected dashboard at `/dashboard?token=...` — returns a generic 404 without a valid token, so the admin interface isn't discoverable by the same scanners it's meant to log
- HTML-escaped output on the dashboard to prevent XSS via attacker-controlled fields (user-agents and POST bodies are rendered, so they need to be treated as untrusted)
- 30-day TTL on stored hits for data minimisation
- Single-file Worker (~300 lines), no build step, free-tier compatible

## Tech stack

Cloudflare Workers (ES module syntax) · Workers KV for storage · Vanilla JavaScript · Wrangler for local dev and deployment

## Security & ethics

A honeypot done carelessly becomes a liability. This project is deliberately scoped:

- **Passive only.** Observes and records. Never identifies, retaliates against, or "hacks back" at visitors.
- **Generic disguise.** Bait pages look like a plausible no-name server, never a clone of a real organisation's site — impersonation drifts into territory that could be misused for actual phishing.
- **Inert bait.** Fake credentials are non-functional and point nowhere (`127.0.0.1`, placeholder strings). The honeypot baits; it does not booby-trap.
- **GDPR-aware.** IP addresses are personal data under UK GDPR. A fixed 30-day TTL on stored records means old data expires automatically; the dashboard is private; collection is limited to what the project's purpose requires.

## Known limitations

A honeypot only sees what reaches it. This setup reliably catches **broad, opportunistic, automated scanning** — which is most of what's out there, and genuinely interesting. It does **not** catch targeted human adversaries, and the `*.workers.dev` hostname is a tell that would be skipped by anything sophisticated. These limits are stated openly rather than overclaimed.

## Future work

- Migrate storage from KV to D1 to enable proper querying ("show me all hits from this ASN in the last week")
- Dashboard summary view: hits per day, top probed paths, top source ASNs
- Pattern detection: flag when one IP probes 5+ trap paths in a short window (the signature of a scanner working through a list, versus a one-off opportunistic hit)
- Migration to a custom domain with wildcard subdomain routing — the real volume unlock; `*.workers.dev` discovery is patchier than indexed `.com`/`.co.uk` hostnames

## Project documents

- [PRD](./honeypot-prd.md) — full product requirements document, including scope, build plan, risks, and the security/ethics reasoning in more detail

## Setup

Brief — full instructions in the PRD's appendix.

```bash
npm install
npx wrangler kv namespace create HONEYPOT_LOGS
# Paste the printed namespace id into wrangler.jsonc under "kv_namespaces"
npx wrangler secret put DASHBOARD_TOKEN
npx wrangler deploy
```

For local development, put `DASHBOARD_TOKEN=<your-token>` in a `.dev.vars` file (gitignored) and run `npx wrangler dev`.

---

*Built by [Ethan Whymark](https://github.com/ethan-whymark) as a personal security-engineering learning project.*
