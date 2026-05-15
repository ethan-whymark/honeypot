/**
 * Honeypot Endpoint — Cloudflare Worker
 * =====================================
 *
 * A deliberately-deployed fake target. It imitates commonly-scanned paths,
 * logs detailed metadata about every visitor to Workers KV, and exposes a
 * token-protected dashboard to review collected hits.
 *
 * Because no legitimate user has any reason to visit these paths, every
 * request logged here is suspicious by definition — pure signal.
 *
 * SETUP (see honeypot-prd.md, Appendix):
 *   1. Create a KV namespace:   npx wrangler kv namespace create HONEYPOT_LOGS
 *   2. Bind it in wrangler.toml under [[kv_namespaces]] (binding = "HONEYPOT_LOGS")
 *   3. Set the dashboard token: npx wrangler secret put DASHBOARD_TOKEN
 *   4. Deploy:                  npx wrangler deploy
 *
 * SCOPE: passive observation only. This never responds to, identifies, or
 * retaliates against visitors. See the PRD's "Security, ethics & legal" section.
 */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------


// Trap paths the honeypot "listens" on, each mapped to a fake-response type.
// Add more here as your logs show you what's actually being probed.
const TRAP_PATHS = {
  // Basic web app patterns — these are the most common scanner targets, and the ones most likely to yield interesting metadata in the request body (username/password pairs).
  '/wp-login.php': 'wordpress',
  '/wp-admin': 'wordpress',
  '/.env': 'envfile',
  '/.git/config': 'gitconfig',
  '/admin': 'adminpanel',
  '/administrator': 'adminpanel',
  '/phpmyadmin': 'adminpanel',
  '/api/v1/login': 'apilogin',
  '/config.php': 'envfile',
  '/.git/HEAD': 'gitconfig',
  '/wp-config.php': 'envfile',
  '/login': 'adminpanel',
  '/api/login': 'apilogin',
  '/.ssh/id_rsa': 'envfile',
  '/backup.sql': 'envfile',
  '/server-status': 'adminpanel',
  '/.vscode/sftp.json': 'envfile',

  // Spring Boot Actuator (very actively probed right now)
  '/actuator/health': 'apilogin',
  '/actuator/env': 'envfile',
  '/actuator/heapdump': 'envfile',

  // API patterns
  '/api/v2/login': 'apilogin',
  '/api/health': 'apilogin',
  '/api/.env': 'envfile',

  // Cloud / container credentials
  '/.aws/credentials': 'envfile',
  '/.docker/config.json': 'envfile',

  // Common admin panels

  '/manager/html': 'adminpanel',

  // Router / IoT (botnet favourites)
  '/HNAP1/': 'adminpanel',
  '/cgi-bin/luci': 'adminpanel',

  // CVE-driven scans (very common scanner targets)
  '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php': 'apilogin',
  '/_ignition/execute-solution': 'apilogin',
};

const DASHBOARD_PATH = '/dashboard';

// How long to keep each logged hit. IP addresses are personal data under UK
// GDPR — a fixed TTL means old data expires automatically (data minimisation).
const LOG_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days

// ---------------------------------------------------------------------------
// Worker entry point
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // --- Dashboard route (token-protected) ---------------------------------
    // Without a valid token this returns a generic 404, so the dashboard
    // isn't discoverable by the same scanners we're trying to log.
    if (path === DASHBOARD_PATH) {
      const token = url.searchParams.get('token');
      if (!env.DASHBOARD_TOKEN || token !== env.DASHBOARD_TOKEN) {
        return new Response('Not found', { status: 404 });
      }
      return renderDashboard(env);
    }

    // --- Trap routes -------------------------------------------------------
    const trapType = TRAP_PATHS[path];
    if (trapType) {
      // Log the hit BEFORE responding. We await rather than using
      // ctx.waitUntil() because logHit() reads the request body — simpler
      // and guaranteed correct. Latency doesn't matter for a honeypot.
      await logHit(request, env, trapType);
      return fakeResponse(trapType);
    }

    // --- Generic catch-all -------------------------------------------------
    return new Response('Not found', { status: 404 });
  },
};

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

/**
 * Build a detailed record of a single hit and write it to KV.
 */
async function logHit(request, env, trapType) {
  const url = new URL(request.url);
  const cf = request.cf || {}; // Cloudflare edge data — geo, ASN, etc.

  // Collect all request headers into a plain object.
  const headers = {};
  for (const [key, value] of request.headers.entries()) {
    headers[key] = value;
  }

  // Capture the request body for POST/PUT — this is where bots send the
  // username/password pairs they're trying. The whole point of the project.
  let body = null;
  if (request.method === 'POST' || request.method === 'PUT') {
    try {
      body = await request.text();
    } catch (e) {
      body = '<unreadable>';
    }
  }

  const hit = {
    timestamp: new Date().toISOString(),
    ip: request.headers.get('CF-Connecting-IP') || 'unknown',
    method: request.method,
    path: url.pathname,
    query: url.search,
    trapType,
    userAgent: request.headers.get('User-Agent') || 'unknown',
    geo: {
      country: cf.country || 'unknown',
      city: cf.city || 'unknown',
      asn: cf.asn || 'unknown',
      asOrganization: cf.asOrganization || 'unknown',
      timezone: cf.timezone || 'unknown',
    },
    headers,
    body,
  };

  // Key format: hit:<timestamp>:<short-random>
  // The ISO timestamp makes keys sort chronologically; the random suffix
  // avoids collisions if two hits land in the same millisecond.
  const key = `hit:${hit.timestamp}:${crypto.randomUUID().slice(0, 8)}`;

  await env.HONEYPOT_LOGS.put(key, JSON.stringify(hit), {
    expirationTtl: LOG_TTL_SECONDS,
  });
}

// ---------------------------------------------------------------------------
// Fake responses
// ---------------------------------------------------------------------------

/**
 * Return a plausible-looking response so a scanner registers a "hit".
 * Everything here is generic and inert — no real branding, no working
 * credentials. We bait; we don't impersonate and we don't booby-trap.
 */
function fakeResponse(trapType) {
  switch (trapType) {
    case 'wordpress':
      return new Response(GENERIC_LOGIN_HTML, {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });

    case 'envfile':
      // Fake config. DB_HOST points at localhost; the key is nonsense.
      return new Response(FAKE_ENV, {
        status: 200,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      });

    case 'gitconfig':
      return new Response(FAKE_GIT_CONFIG, {
        status: 200,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      });

    case 'apilogin':
      // Imitate a JSON API rejecting credentials.
      return new Response(JSON.stringify({ error: 'invalid_credentials' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });

    case 'adminpanel':
    default:
      return new Response(GENERIC_LOGIN_HTML, {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
  }
}

// A deliberately generic login page — looks like a no-name server, not a
// clone of any real company's site.
const GENERIC_LOGIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Admin Login</title></head>
<body style="font-family:sans-serif;max-width:320px;margin:80px auto">
  <h2>Admin Login</h2>
  <form method="POST">
    <p><input name="username" placeholder="Username" style="width:100%"></p>
    <p><input name="password" type="password" placeholder="Password" style="width:100%"></p>
    <p><button type="submit" style="width:100%">Sign in</button></p>
  </form>
</body>
</html>`;

// Fake .env — every value is inert. DB_HOST is localhost; the app key is
// not a real key; the password is a placeholder. Nothing here points anywhere.
const FAKE_ENV = `APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:bm90YXJlYWxrZXlub3RhcmVhbGtleW5vdGFyZWFs
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=app_production
DB_USERNAME=app_user
DB_PASSWORD=placeholder_not_a_real_password
`;

const FAKE_GIT_CONFIG = `[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[remote "origin"]
\turl = https://example.invalid/placeholder/repo.git
`;

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

/**
 * Read recent hits from KV and render them as a simple HTML table,
 * newest first.
 */
async function renderDashboard(env) {
  // List keys under the "hit:" prefix. Keys sort ascending by timestamp,
  // so reverse for newest-first. Limit keeps the dashboard fast.
  const list = await env.HONEYPOT_LOGS.list({ prefix: 'hit:', limit: 100 });
  const keys = list.keys.map((k) => k.name).reverse();

  // Fetch each record. Fine at this scale; for larger volumes you'd move
  // to D1 (see PRD §12, future work).
  const hits = [];
  for (const key of keys) {
    const value = await env.HONEYPOT_LOGS.get(key);
    if (value) hits.push(JSON.parse(value));
  }

  const rows = hits
    .map(
      (h) => `<tr>
      <td>${escapeHtml(h.timestamp)}</td>
      <td>${escapeHtml(h.ip)}</td>
      <td>${escapeHtml(h.geo.country)} / ${escapeHtml(String(h.geo.asOrganization))}</td>
      <td>${escapeHtml(h.method)}</td>
      <td>${escapeHtml(h.path)}</td>
      <td><code>${escapeHtml(h.body || '')}</code></td>
      <td>${escapeHtml(h.userAgent)}</td>
    </tr>`
    )
    .join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Honeypot — collected hits</title>
  <style>
    body { font-family: sans-serif; margin: 24px; }
    table { border-collapse: collapse; width: 100%; font-size: 13px; }
    th, td { border: 1px solid #ccc; padding: 6px 8px; text-align: left; vertical-align: top; }
    th { background: #f4f4f4; }
    code { word-break: break-all; }
  </style>
</head>
<body>
  <h1>Collected hits (${hits.length})</h1>
  <p>Newest first. Records auto-expire after 30 days.</p>
  <table>
    <thead>
      <tr><th>Timestamp</th><th>IP</th><th>Geo / Network</th><th>Method</th>
          <th>Path</th><th>Body</th><th>User-Agent</th></tr>
    </thead>
    <tbody>${rows || '<tr><td colspan="7">No hits yet.</td></tr>'}</tbody>
  </table>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

/**
 * Escape user-controlled strings before putting them in the dashboard HTML.
 * Attacker-supplied data (user-agents, POST bodies) could contain markup or
 * script — we are NOT going to introduce an XSS hole in our own security tool.
 */
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}