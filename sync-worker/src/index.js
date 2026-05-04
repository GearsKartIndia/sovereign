/**
 * Sovereign Sync Worker — Cloudflare Worker + KV
 *
 * Routes:
 *   GET  /sync/:channelId   — fetch latest blob (requires Bearer token)
 *   PUT  /sync/:channelId   — store blob with rollback protection (requires Bearer token)
 *   OPTIONS  *              — CORS preflight
 *
 * KV value: { ts, data, tokenHash }
 *   tokenHash = SHA-256(token) — never stored in plaintext
 *   data      = AES-256-GCM encrypted entries blob (opaque to this worker)
 */

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return corsResp(new Response(null, { status: 204 }));
    }

    const url   = new URL(request.url);
    const parts = url.pathname.split('/').filter(Boolean);

    if (parts[0] !== 'sync' || !parts[1]) {
      return corsResp(new Response('Not found', { status: 404 }));
    }

    const channelId = parts[1];

    const auth = request.headers.get('Authorization') || '';
    if (!auth.startsWith('Bearer ')) {
      return corsResp(new Response('Unauthorized', { status: 401 }));
    }
    const token     = auth.slice(7);
    const tokenHash = await sha256b64(token);
    const kvKey     = `sync:${channelId}`;

    if (request.method === 'GET') {
      const stored = await env.KV.get(kvKey, 'json');
      if (!stored) return corsResp(new Response('Not found', { status: 404 }));
      if (stored.tokenHash !== tokenHash) {
        return corsResp(new Response('Unauthorized', { status: 401 }));
      }
      return corsResp(Response.json({ ts: stored.ts, data: stored.data }));
    }

    if (request.method === 'PUT') {
      let body;
      try { body = await request.json(); } catch {
        return corsResp(new Response('Bad request', { status: 400 }));
      }
      const { ts, data } = body;
      if (!ts || !data || typeof ts !== 'number' || typeof data !== 'string') {
        return corsResp(new Response('Bad request', { status: 400 }));
      }

      const existing = await env.KV.get(kvKey, 'json');
      if (existing) {
        if (existing.tokenHash !== tokenHash) {
          return corsResp(new Response('Unauthorized', { status: 401 }));
        }
        if (ts <= existing.ts) {
          return corsResp(Response.json({ ok: false, error: 'stale' }));
        }
      }

      await env.KV.put(kvKey, JSON.stringify({ ts, data, tokenHash }), {
        expirationTtl: 30 * 24 * 3600,
      });
      return corsResp(Response.json({ ok: true }));
    }

    return corsResp(new Response('Method not allowed', { status: 405 }));
  },
};

async function sha256b64(str) {
  const buf  = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  let   s    = '';
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s);
}

function corsResp(resp) {
  const r = new Response(resp.body, resp);
  r.headers.set('Access-Control-Allow-Origin', '*');
  r.headers.set('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS');
  r.headers.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  return r;
}
