// Cloudflare Pages Function — handles all /api/* routes
// Uses Cloudflare D1 (SQLite) for relational storage.
//
// D1 schema (see migrations/0001_init.sql):
//   contacts(slug, salt, iv, data, verifier, notify_topic, created_at, updated_at)
//   rate_limits(key, count, window_start)

const RESERVED_SLUGS = new Set([
  'api', 'admin', 'www', 'mail', 'ftp', 'static', 'assets',
  'index', 'create', 'new', 'help', 'about', 'contact',
  'login', 'logout', 'signup', 'register', 'dashboard',
  'privacy', 'terms',
]);

const SLUG_RE = /^[a-z0-9][a-z0-9\-_]{1,48}[a-z0-9]$/;

// ── Helpers ───────────────────────────────────────────────────────────────────

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function err(message, status = 400) {
  return json({ error: message }, status);
}

// ── Rate limiting via D1 ──────────────────────────────────────────────────────
// Each (type, ip, time-window) tuple gets a row. We increment atomically with
// INSERT OR REPLACE … SELECT to stay race-safe within a single D1 write.

async function checkRateLimit(db, type, ip, env) {
  const createLimit = parseInt(env.RATE_LIMIT_CREATE_PER_HOUR ?? '5');
  const readLimit   = parseInt(env.RATE_LIMIT_READ_PER_MINUTE ?? '30');

  const windowSecs  = type === 'create' ? 3600 : 60;
  const limit       = type === 'create' ? createLimit : readLimit;
  const now         = Math.floor(Date.now() / 1000);
  const bucket      = Math.floor(now / windowSecs);
  const key         = `${type}:${ip}:${bucket}`;

  // Upsert: if row exists and is within window, increment; else start fresh.
  await db.prepare(`
    INSERT INTO rate_limits (key, count, window_start)
    VALUES (?, 1, ?)
    ON CONFLICT(key) DO UPDATE SET count = count + 1
  `).bind(key, now).run();

  const row = await db.prepare(
    'SELECT count FROM rate_limits WHERE key = ?'
  ).bind(key).first();

  // Opportunistic cleanup of old rows (best-effort, non-blocking)
  db.prepare(
    'DELETE FROM rate_limits WHERE window_start < ?'
  ).bind(now - windowSecs * 2).run().catch(() => {});

  return (row?.count ?? 1) <= limit;
}

// ── Notification (fire-and-forget) ────────────────────────────────────────────

async function notify(topic, slug, action) {
  if (!topic) return;
  const messages = {
    created: `Your CallHome page /${slug} is live. Share it with people who may need to reach you.`,
    updated: `Your CallHome page /${slug} was just updated.`,
  };
  fetch(`https://ntfy.sh/${encodeURIComponent(topic)}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain',
      'Title': action === 'created' ? 'CallHome page created' : 'CallHome page updated',
      'Priority': '3',
      'Tags': 'phone',
    },
    body: messages[action] ?? `CallHome page /${slug} was modified.`,
  }).catch(() => {});
}

// ── Constant-time string comparison ──────────────────────────────────────────

function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ── Route handlers ────────────────────────────────────────────────────────────

async function handleCheckSlug(db, slug) {
  if (!slug) return err('slug param required');
  const normalized = slug.toLowerCase().trim();
  if (!SLUG_RE.test(normalized) || RESERVED_SLUGS.has(normalized)) {
    return json({ available: false, reason: 'invalid' });
  }
  const row = await db.prepare(
    'SELECT slug FROM contacts WHERE slug = ?'
  ).bind(normalized).first();
  return json({ available: !row });
}

async function handleCreate(request, db, ip, env) {
  if (!await checkRateLimit(db, 'create', ip, env)) {
    return err('Too many pages created from your IP. Try again in an hour.', 429);
  }

  let body;
  try { body = await request.json(); }
  catch { return err('Invalid JSON'); }

  const { slug, salt, iv, data, verifier, notifyTopic } = body;

  if (!slug || typeof slug !== 'string') return err('slug is required');
  const normalized = slug.toLowerCase().trim();
  if (!SLUG_RE.test(normalized)) {
    return err('Slug must be 3–50 characters: letters, numbers, hyphens, underscores only.');
  }
  if (RESERVED_SLUGS.has(normalized)) return err('That slug is reserved. Choose another.');
  if (!salt || !iv || !data || !verifier)  return err('Missing encrypted payload fields.');

  // Check availability
  const existing = await db.prepare(
    'SELECT slug FROM contacts WHERE slug = ?'
  ).bind(normalized).first();
  if (existing) return err('That URL is already taken. Choose a different one.', 409);

  const now = new Date().toISOString();
  await db.prepare(`
    INSERT INTO contacts (slug, salt, iv, data, verifier, notify_topic, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(normalized, salt, iv, data, verifier, notifyTopic ?? null, now, now).run();

  notify(notifyTopic, normalized, 'created');

  return json({ slug: normalized }, 201);
}

async function handleRead(request, db, ip, env, slug) {
  if (!await checkRateLimit(db, 'read', ip, env)) {
    return err('Too many requests. Slow down and try again in a minute.', 429);
  }

  const row = await db.prepare(
    'SELECT salt, iv, data, updated_at FROM contacts WHERE slug = ?'
  ).bind(slug).first();

  if (!row) return err('Page not found.', 404);

  // Return only what's needed for decryption — never expose verifier or notify_topic
  return json({
    salt:      row.salt,
    iv:        row.iv,
    data:      row.data,
    updatedAt: row.updated_at,
  });
}

async function handleUpdate(request, db, ip, env, slug) {
  if (!await checkRateLimit(db, 'create', ip, env)) {
    return err('Too many requests from your IP. Try again in an hour.', 429);
  }

  const row = await db.prepare(
    'SELECT verifier, notify_topic FROM contacts WHERE slug = ?'
  ).bind(slug).first();
  if (!row) return err('Page not found.', 404);

  let body;
  try { body = await request.json(); }
  catch { return err('Invalid JSON'); }

  const { verifier, salt, iv, data, newVerifier, notifyTopic } = body;
  if (!verifier || !salt || !iv || !data) return err('Missing required fields.');

  if (!safeCompare(verifier, row.verifier)) {
    return err('Wrong password.', 403);
  }

  const updatedVerifier  = newVerifier   ?? row.verifier;
  const updatedTopic     = notifyTopic !== undefined ? (notifyTopic || null) : row.notify_topic;
  const now              = new Date().toISOString();

  await db.prepare(`
    UPDATE contacts
    SET salt = ?, iv = ?, data = ?, verifier = ?, notify_topic = ?, updated_at = ?
    WHERE slug = ?
  `).bind(salt, iv, data, updatedVerifier, updatedTopic, now, slug).run();

  notify(updatedTopic, slug, 'updated');

  return json({ ok: true });
}

async function handleDelete(request, db, ip, slug) {
  const row = await db.prepare(
    'SELECT verifier FROM contacts WHERE slug = ?'
  ).bind(slug).first();
  if (!row) return err('Page not found.', 404);

  let body;
  try { body = await request.json(); }
  catch { return err('Invalid JSON'); }

  const { verifier } = body;
  if (!verifier) return err('Missing verifier.');

  if (!safeCompare(verifier, row.verifier)) {
    return err('Wrong password.', 403);
  }

  await db.prepare('DELETE FROM contacts WHERE slug = ?').bind(slug).run();

  return json({ ok: true });
}

// ── Router ────────────────────────────────────────────────────────────────────

export async function onRequest(context) {
  const { request, env, params } = context;
  const method = request.method;
  const url    = new URL(request.url);
  const db     = env.DB;
  const ip     = request.headers.get('CF-Connecting-IP') ?? '0.0.0.0';

  const route = Array.isArray(params.route)
    ? params.route
    : (params.route ?? '').split('/').filter(Boolean);

  if (route[0] !== 'contacts') {
    return new Response('Not found', { status: 404 });
  }

  const slug = route[1]?.toLowerCase() ?? null;

  if (method === 'GET'    && slug === 'check') return handleCheckSlug(db, url.searchParams.get('slug'));
  if (method === 'POST'   && !slug)            return handleCreate(request, db, ip, env);
  if (method === 'GET'    && slug)             return handleRead(request, db, ip, env, slug);
  if (method === 'PUT'    && slug)             return handleUpdate(request, db, ip, env, slug);
  if (method === 'DELETE' && slug)             return handleDelete(request, db, ip, slug);

  return new Response('Method not allowed', { status: 405 });
}
