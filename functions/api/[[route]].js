// Cloudflare Pages Function — handles all /api/* routes
// KV schema per entry (key = slug):
// {
//   salt: string (base64),      -- PBKDF2 salt for encryption key
//   iv: string (base64),        -- AES-GCM IV
//   data: string (base64),      -- AES-GCM encrypted contact JSON
//   verifier: string (base64),  -- PBKDF2(password, "callhome:verify:{slug}") for auth
//   notifyTopic: string|null,   -- ntfy.sh topic for update notifications
//   createdAt: string,
//   updatedAt: string
// }

const RESERVED_SLUGS = new Set([
  'api', 'admin', 'www', 'mail', 'ftp', 'static', 'assets',
  'index', 'create', 'new', 'help', 'about', 'contact',
  'login', 'logout', 'signup', 'register', 'dashboard',
]);

const SLUG_RE = /^[a-z0-9][a-z0-9\-_]{1,48}[a-z0-9]$/;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function err(message, status = 400) {
  return json({ error: message }, status);
}

// ── Rate limiting via KV ──────────────────────────────────────────────────────
// Uses sliding window buckets; accepts minor race conditions (KV not atomic).

async function checkRateLimit(env, type, ip) {
  const createLimit = parseInt(env.RATE_LIMIT_CREATE_PER_HOUR || '5');
  const readLimit   = parseInt(env.RATE_LIMIT_READ_PER_MINUTE || '30');

  const windowSecs = type === 'create' ? 3600 : 60;
  const limit      = type === 'create' ? createLimit : readLimit;
  const bucket     = Math.floor(Date.now() / (windowSecs * 1000));
  const key        = `rl:${type}:${ip}:${bucket}`;

  const current = parseInt((await env.CONTACTS.get(key)) ?? '0');
  if (current >= limit) return false;

  // Write incremented count; TTL = 2 windows so we don't leak keys
  await env.CONTACTS.put(key, String(current + 1), {
    expirationTtl: windowSecs * 2,
  });
  return true;
}

// ── Notification helper ───────────────────────────────────────────────────────

async function notify(topic, slug, action) {
  if (!topic) return;
  const messages = {
    created: `Your CallHome page /${slug} is live. Share it with people who may need to reach you.`,
    updated: `Your CallHome page /${slug} was just updated.`,
  };
  try {
    await fetch(`https://ntfy.sh/${encodeURIComponent(topic)}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'Title': action === 'created' ? 'CallHome page created' : 'CallHome page updated',
        'Priority': '3',
        'Tags': 'phone',
      },
      body: messages[action] ?? `CallHome page /${slug} was modified.`,
    });
  } catch {
    // fire-and-forget; notification failure must not break the response
  }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async function handleCreate(request, env, ip) {
  const allowed = await checkRateLimit(env, 'create', ip);
  if (!allowed) {
    return err('Too many pages created from your IP. Try again in an hour.', 429);
  }

  let body;
  try { body = await request.json(); }
  catch { return err('Invalid JSON'); }

  const { slug, salt, iv, data, verifier, notifyTopic } = body;

  // Validate slug
  if (!slug || typeof slug !== 'string') return err('slug is required');
  const normalized = slug.toLowerCase().trim();
  if (!SLUG_RE.test(normalized)) {
    return err('Slug must be 3–50 characters: letters, numbers, hyphens, underscores only.');
  }
  if (RESERVED_SLUGS.has(normalized)) return err('That slug is reserved. Choose another.');

  // Validate encrypted payload fields
  if (!salt || !iv || !data || !verifier) return err('Missing encrypted payload fields.');

  // Check availability
  const existing = await env.CONTACTS.get(normalized);
  if (existing) return err('That URL is already taken. Choose a different one.', 409);

  const now = new Date().toISOString();
  const entry = {
    salt,
    iv,
    data,
    verifier,
    notifyTopic: notifyTopic || null,
    createdAt: now,
    updatedAt: now,
  };

  await env.CONTACTS.put(normalized, JSON.stringify(entry));

  // Non-blocking notification to owner
  notify(notifyTopic, normalized, 'created');

  return json({ slug: normalized }, 201);
}

async function handleRead(request, env, ip, slug) {
  const allowed = await checkRateLimit(env, 'read', ip);
  if (!allowed) {
    return err('Too many requests. Slow down and try again in a minute.', 429);
  }

  const raw = await env.CONTACTS.get(slug);
  if (!raw) return err('Page not found.', 404);

  const entry = JSON.parse(raw);

  // Only return what the client needs to decrypt — never expose verifier or notifyTopic
  return json({
    salt: entry.salt,
    iv: entry.iv,
    data: entry.data,
    updatedAt: entry.updatedAt,
  });
}

async function handleUpdate(request, env, ip, slug) {
  // Updates count against the create rate limit (heavier operation)
  const allowed = await checkRateLimit(env, 'create', ip);
  if (!allowed) {
    return err('Too many requests from your IP. Try again in an hour.', 429);
  }

  const raw = await env.CONTACTS.get(slug);
  if (!raw) return err('Page not found.', 404);

  let body;
  try { body = await request.json(); }
  catch { return err('Invalid JSON'); }

  const { verifier, salt, iv, data, newVerifier, notifyTopic } = body;
  if (!verifier || !salt || !iv || !data) return err('Missing required fields.');

  const entry = JSON.parse(raw);

  // Constant-time comparison to prevent timing attacks
  if (!safeCompare(verifier, entry.verifier)) {
    return err('Wrong password.', 403);
  }

  const updated = {
    ...entry,
    salt,
    iv,
    data,
    verifier: newVerifier || entry.verifier,
    notifyTopic: notifyTopic !== undefined ? (notifyTopic || null) : entry.notifyTopic,
    updatedAt: new Date().toISOString(),
  };

  await env.CONTACTS.put(slug, JSON.stringify(updated));

  notify(updated.notifyTopic, slug, 'updated');

  return json({ ok: true });
}

async function handleDelete(request, env, ip, slug) {
  const raw = await env.CONTACTS.get(slug);
  if (!raw) return err('Page not found.', 404);

  let body;
  try { body = await request.json(); }
  catch { return err('Invalid JSON'); }

  const { verifier } = body;
  if (!verifier) return err('Missing verifier.');

  const entry = JSON.parse(raw);
  if (!safeCompare(verifier, entry.verifier)) {
    return err('Wrong password.', 403);
  }

  await env.CONTACTS.delete(slug);
  return json({ ok: true });
}

async function handleCheckSlug(env, slug) {
  if (!slug) return err('slug param required');
  const normalized = slug.toLowerCase().trim();
  if (!SLUG_RE.test(normalized) || RESERVED_SLUGS.has(normalized)) {
    return json({ available: false, reason: 'invalid' });
  }
  const existing = await env.CONTACTS.get(normalized);
  return json({ available: !existing });
}

// ── Constant-time string comparison ──────────────────────────────────────────

function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ── Router ────────────────────────────────────────────────────────────────────

export async function onRequest(context) {
  const { request, env, params } = context;
  const method = request.method;
  const url = new URL(request.url);

  // Normalise catch-all param to array of path segments
  const route = Array.isArray(params.route)
    ? params.route
    : (params.route || '').split('/').filter(Boolean);

  const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';

  // Only handle /api/contacts/...
  if (route[0] !== 'contacts') {
    return new Response('Not found', { status: 404 });
  }

  const slug = route[1]?.toLowerCase() ?? null;

  // GET /api/contacts/check?slug=foo
  if (method === 'GET' && slug === 'check') {
    return handleCheckSlug(env, url.searchParams.get('slug'));
  }

  // POST /api/contacts  — create
  if (method === 'POST' && !slug) {
    return handleCreate(request, env, ip);
  }

  // GET /api/contacts/:slug  — read encrypted blob
  if (method === 'GET' && slug) {
    return handleRead(request, env, ip, slug);
  }

  // PUT /api/contacts/:slug  — update
  if (method === 'PUT' && slug) {
    return handleUpdate(request, env, ip, slug);
  }

  // DELETE /api/contacts/:slug  — delete
  if (method === 'DELETE' && slug) {
    return handleDelete(request, env, ip, slug);
  }

  return new Response('Method not allowed', { status: 405 });
}
