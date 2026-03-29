'use strict';
// ═══════════════════════════════════════════════════════════════════════════════
// CallHome — client-side logic
// All encryption/decryption happens here; the server only ever sees ciphertext.
// ═══════════════════════════════════════════════════════════════════════════════

// ── Utilities ─────────────────────────────────────────────────────────────────

function toBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function fromBase64(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

function escHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function el(id) { return document.getElementById(id); }

function setHTML(id, html) {
  const node = el(id);
  if (node) node.innerHTML = html;
}

function formatDate(iso) {
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: 'medium', timeStyle: 'short',
    });
  } catch { return iso; }
}

// ── E2E Crypto ────────────────────────────────────────────────────────────────
// Encryption key  : PBKDF2(password, random_salt, 200_000 iters, SHA-256) → AES-GCM-256
// Write verifier  : PBKDF2(password, "callhome:verify:{slug}", 200_000 iters, SHA-256)
//                   Stored on server; used to authenticate writes without revealing password.

const PBKDF2_ITERATIONS = 200_000;
const enc = new TextEncoder();
const dec = new TextDecoder();

async function importPassword(password) {
  return crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey', 'deriveBits'],
  );
}

async function deriveEncryptionKey(password, salt) {
  const km = await importPassword(password);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: typeof salt === 'string' ? fromBase64(salt) : salt,
      iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    km,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function deriveVerifier(password, slug) {
  const km = await importPassword(password);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(`callhome:verify:${slug}`),
      iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    km, 256,
  );
  return toBase64(bits);
}

async function encryptContact(password, contactData) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveEncryptionKey(password, salt);
  const ct   = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(JSON.stringify(contactData)),
  );
  return { salt: toBase64(salt), iv: toBase64(iv), data: toBase64(ct) };
}

async function decryptContact(password, { salt, iv, data }) {
  const key = await deriveEncryptionKey(password, salt);
  const pt  = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(iv) },
    key,
    fromBase64(data),
  );
  return JSON.parse(dec.decode(pt));
}

// ── API helpers ───────────────────────────────────────────────────────────────

async function apiFetch(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  const json = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data: json };
}

async function checkSlugAvailability(slug) {
  const { ok, data } = await apiFetch('GET', `/api/contacts/check?slug=${encodeURIComponent(slug)}`);
  return ok ? data : null;
}

async function apiCreate(payload) {
  return apiFetch('POST', '/api/contacts', payload);
}

async function apiRead(slug) {
  return apiFetch('GET', `/api/contacts/${encodeURIComponent(slug)}`);
}

async function apiUpdate(slug, payload) {
  return apiFetch('PUT', `/api/contacts/${encodeURIComponent(slug)}`, payload);
}

async function apiDelete(slug, verifier) {
  return apiFetch('DELETE', `/api/contacts/${encodeURIComponent(slug)}`, { verifier });
}

// ── Slug validation ───────────────────────────────────────────────────────────

const SLUG_RE = /^[a-z0-9][a-z0-9\-_]{1,48}[a-z0-9]$/;

function validateSlug(slug) {
  if (!slug) return 'Choose a custom URL.';
  if (!SLUG_RE.test(slug.toLowerCase())) {
    return 'Only letters, numbers, hyphens, underscores. Min 3 chars.';
  }
  return null;
}

// ── SPA Router ────────────────────────────────────────────────────────────────

const STATIC_ROUTES = new Set(['about', 'privacy', 'terms']);

function getRoute() {
  const p = window.location.pathname.replace(/^\/|\/$/g, '');
  if (!p || p === 'index.html') return { page: 'home' };
  if (STATIC_ROUTES.has(p))     return { page: p };
  return { page: 'view', slug: p };
}

function navigate(path) {
  window.history.pushState(null, '', path);
  route();
}

function route() {
  const { page, slug } = getRoute();
  const app = document.getElementById('app');
  app.className = '';
  switch (page) {
    case 'home':    renderCreatePage(); break;
    case 'about':   app.className = 'wide'; renderAboutPage();   break;
    case 'privacy': app.className = 'wide'; renderPrivacyPage(); break;
    case 'terms':   app.className = 'wide'; renderTermsPage();   break;
    case 'view':    renderViewPage(slug);  break;
  }
  window.scrollTo(0, 0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CREATE PAGE
// ═══════════════════════════════════════════════════════════════════════════════

function renderCreatePage() {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="create-hero">
      <h1>Create your emergency contact page</h1>
      <p>
        Set up a password-protected URL to share with family and friends.
        If you lose your phone, they can find your contact details here.
        Everything is encrypted in your browser — we never see your data.
      </p>
    </div>

    <div class="card">
      <div id="form-alert"></div>

      <p class="section-label">Your page URL</p>
      <div class="field">
        <label for="slug">Custom URL</label>
        <div class="slug-row">
          <span class="slug-prefix" id="slug-prefix">callhome.app/</span>
          <input type="text" id="slug" placeholder="your-name" maxlength="50"
            autocomplete="off" spellcheck="false" autocapitalize="none" />
          <span class="slug-status" id="slug-status"></span>
        </div>
        <p class="hint">Letters, numbers, hyphens and underscores. Min 3 characters.</p>
      </div>

      <hr class="divider" />
      <p class="section-label">Password protection</p>

      <div class="field">
        <label for="password">Password</label>
        <input type="password" id="password" placeholder="Choose a strong password"
          autocomplete="new-password" />
        <p class="hint">Anyone with the URL <em>and</em> this password can view or update the page.</p>
      </div>
      <div class="field">
        <label for="password2">Confirm password</label>
        <input type="password" id="password2" placeholder="Repeat password"
          autocomplete="new-password" />
      </div>

      <hr class="divider" />
      <p class="section-label">Contact details</p>

      <div class="field">
        <label for="contact-name">Full name <span class="optional">(shown on the page)</span></label>
        <input type="text" id="contact-name" placeholder="Alex Smith" />
      </div>

      <div class="field">
        <label>Phone numbers</label>
        <div class="multi-field" id="phones-list">
          <div class="input-row">
            <input type="tel" placeholder="+1 555 000 0000" />
          </div>
        </div>
        <button type="button" class="add-btn" id="add-phone">+ Add phone</button>
      </div>

      <div class="field">
        <label>Email addresses</label>
        <div class="multi-field" id="emails-list">
          <div class="input-row">
            <input type="email" placeholder="you@example.com" />
          </div>
        </div>
        <button type="button" class="add-btn" id="add-email">+ Add email</button>
      </div>

      <div class="field">
        <label for="address">Address <span class="optional">(optional)</span></label>
        <textarea id="address" rows="2" placeholder="123 Main St, City, Country"></textarea>
      </div>

      <div class="field">
        <label for="notes">
          Message to the finder <span class="optional">(optional, max 256 chars)</span>
        </label>
        <textarea id="notes" rows="3" maxlength="256"
          placeholder="e.g. I've lost my phone. Please call me on any of the numbers above."></textarea>
        <p class="char-count" id="notes-count">0 / 256</p>
      </div>

      <hr class="divider" />
      <p class="section-label">Notifications</p>

      <div class="field">
        <label for="notify-topic">
          ntfy.sh topic <span class="optional">(optional)</span>
        </label>
        <input type="text" id="notify-topic" placeholder="my-callhome-alerts"
          autocomplete="off" autocapitalize="none" spellcheck="false" />
        <p class="hint">
          Get a push notification when your page is updated.
          Install <a href="https://ntfy.sh" target="_blank" rel="noopener">ntfy</a>
          and subscribe to your chosen topic name.
        </p>
      </div>

      <div class="btn-row">
        <button type="button" class="btn btn-primary" id="create-btn">
          🔒 Encrypt &amp; create page
        </button>
      </div>
    </div>
  `;

  // Update slug prefix with actual hostname
  const prefix = el('slug-prefix');
  if (prefix) prefix.textContent = `${window.location.hostname}/`;

  wireCreatePage();
}

function wireCreatePage() {
  // Slug availability check (debounced)
  let slugTimer = null;
  const slugInput  = el('slug');
  const slugStatus = el('slug-status');

  slugInput.addEventListener('input', () => {
    const val = slugInput.value.trim().toLowerCase();
    slugStatus.textContent = '';
    slugStatus.className   = 'slug-status';
    clearTimeout(slugTimer);
    if (!val) return;
    const err = validateSlug(val);
    if (err) {
      slugStatus.textContent = '✗ ' + err;
      slugStatus.className   = 'slug-status taken';
      return;
    }
    slugStatus.textContent = 'checking…';
    slugStatus.className   = 'slug-status checking';
    slugTimer = setTimeout(async () => {
      const res = await checkSlugAvailability(val).catch(() => null);
      if (!res) return;
      if (res.available) {
        slugStatus.textContent = '✓ available';
        slugStatus.className   = 'slug-status ok';
      } else {
        slugStatus.textContent = res.reason === 'invalid' ? '✗ invalid' : '✗ taken';
        slugStatus.className   = 'slug-status taken';
      }
    }, 450);
  });

  // Dynamic multi-input rows
  addMultiInputWiring('phones-list', 'add-phone', 'tel',   '+1 555 000 0000', 5);
  addMultiInputWiring('emails-list', 'add-email', 'email', 'you@example.com', 3);

  // Notes character counter
  const notesTA    = el('notes');
  const notesCount = el('notes-count');
  notesTA.addEventListener('input', () => {
    const n = notesTA.value.length;
    notesCount.textContent = `${n} / 256`;
    notesCount.className = n > 240 ? 'char-count warn' : n >= 256 ? 'char-count over' : 'char-count';
  });

  // Submit
  el('create-btn').addEventListener('click', handleCreateSubmit);
}

function addMultiInputWiring(listId, addBtnId, type, placeholder, max) {
  const list   = el(listId);
  const addBtn = el(addBtnId);

  function makeRemoveBtn(row) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'remove-btn';
    btn.setAttribute('aria-label', 'Remove');
    btn.textContent = '×';
    btn.addEventListener('click', () => {
      row.remove();
      updateRemoveBtns();
    });
    return btn;
  }

  function updateRemoveBtns() {
    const rows = list.querySelectorAll('.input-row');
    rows.forEach((row, i) => {
      const existing = row.querySelector('.remove-btn');
      if (rows.length > 1 && !existing) {
        row.appendChild(makeRemoveBtn(row));
      } else if (rows.length === 1 && existing) {
        existing.remove();
      }
    });
    addBtn.style.display = list.querySelectorAll('.input-row').length >= max ? 'none' : '';
  }

  addBtn.addEventListener('click', () => {
    if (list.querySelectorAll('.input-row').length >= max) return;
    const row   = document.createElement('div');
    row.className = 'input-row';
    const inp = document.createElement('input');
    inp.type = type;
    inp.placeholder = placeholder;
    row.appendChild(inp);
    list.appendChild(row);
    updateRemoveBtns();
    inp.focus();
  });

  updateRemoveBtns();
}

function getMultiValues(listId) {
  return [...document.querySelectorAll(`#${listId} .input-row input`)]
    .map(i => i.value.trim())
    .filter(Boolean);
}

function showFormAlert(msg, type = 'error') {
  const icons = { error: '⚠️', success: '✅', info: 'ℹ️' };
  el('form-alert').innerHTML = msg
    ? `<div class="alert alert-${type}"><span class="alert-icon">${icons[type]}</span><span>${escHtml(msg)}</span></div>`
    : '';
}

async function handleCreateSubmit() {
  const btn = el('create-btn');
  btn.disabled = true;
  btn.textContent = 'Encrypting…';
  showFormAlert('');

  try {
    const slug     = el('slug').value.trim().toLowerCase();
    const password = el('password').value;
    const pass2    = el('password2').value;
    const name     = el('contact-name').value.trim();
    const address  = el('address').value.trim();
    const notes    = el('notes').value.trim().slice(0, 256);
    const phones   = getMultiValues('phones-list');
    const emails   = getMultiValues('emails-list');
    const notifyTopic = el('notify-topic').value.trim();

    // Client validation
    const slugErr = validateSlug(slug);
    if (slugErr) { showFormAlert(slugErr); return; }
    if (!password) { showFormAlert('Password is required.'); return; }
    if (password !== pass2) { showFormAlert('Passwords do not match.'); return; }
    if (password.length < 8) { showFormAlert('Password must be at least 8 characters.'); return; }
    if (!name && !phones.length && !emails.length) {
      showFormAlert('Add at least a name, phone number, or email address.'); return;
    }

    const contactData = { name, phones, emails, address, notes };

    // Encrypt and derive verifier
    const encrypted = await encryptContact(password, contactData);
    const verifier  = await deriveVerifier(password, slug);

    btn.textContent = 'Creating page…';
    const { ok, status, data } = await apiCreate({
      slug, ...encrypted, verifier,
      notifyTopic: notifyTopic || undefined,
    });

    if (ok) {
      renderSuccessPage(slug);
    } else {
      showFormAlert(data.error || `Error ${status}. Please try again.`);
    }
  } catch (e) {
    console.error(e);
    showFormAlert('Something went wrong. Please try again.');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '🔒 Encrypt &amp; create page';
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUCCESS PAGE
// ═══════════════════════════════════════════════════════════════════════════════

function renderSuccessPage(slug) {
  const url = `${window.location.origin}/${slug}`;
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="card">
      <div class="success-hero">
        <span class="success-icon">✅</span>
        <h1>Your page is ready!</h1>
        <p>Share this URL with the people who might need to reach you.</p>
      </div>

      <div class="url-box">
        <span class="url-text" id="share-url">${escHtml(url)}</span>
        <button class="copy-btn" id="copy-url-btn">Copy</button>
      </div>

      <div class="alert alert-info">
        <span class="alert-icon">🔑</span>
        <span>
          <strong>Keep your password safe.</strong>
          Without it, the contact data cannot be recovered — not even by us.
        </span>
      </div>

      <div class="btn-row">
        <a href="/${escHtml(slug)}" class="btn btn-primary">View my page</a>
        <a href="/" class="btn btn-secondary">Create another</a>
      </div>
    </div>
  `;

  // Copy button
  el('copy-url-btn').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(url);
      el('copy-url-btn').textContent = 'Copied!';
      setTimeout(() => { el('copy-url-btn').textContent = 'Copy'; }, 2000);
    } catch {
      el('copy-url-btn').textContent = 'Copy failed';
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// VIEW PAGE
// ═══════════════════════════════════════════════════════════════════════════════

function renderViewPage(slug) {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="card" id="lock-card">
      <div class="lock-screen">
        <span class="lock-big">🔒</span>
        <h1>${escHtml(slug)}</h1>
        <p>This contact page is password-protected.<br>Enter the password to view it.</p>
      </div>

      <div id="view-alert"></div>

      <div class="field">
        <label for="view-password">Password</label>
        <input type="password" id="view-password" placeholder="Enter password"
          autocomplete="current-password" />
      </div>
      <div class="btn-row">
        <button type="button" class="btn btn-primary btn-full" id="view-btn">
          Unlock
        </button>
      </div>
    </div>

    <div class="card" style="margin-top:1rem">
      <span class="security-badge">🔒 End-to-end encrypted</span>
      <p style="font-size:.85rem;color:var(--gray-600)">
        Contact data is decrypted locally in your browser.
        The server only stores an encrypted blob and never sees the plaintext.
      </p>
    </div>
  `;

  const pwdInput = el('view-password');
  const viewBtn  = el('view-btn');

  async function tryUnlock() {
    const password = pwdInput.value;
    if (!password) return;
    viewBtn.disabled = true;
    viewBtn.textContent = 'Decrypting…';
    setViewAlert('');

    try {
      const { ok, status, data } = await apiRead(slug);
      if (!ok) {
        setViewAlert(status === 404 ? 'This page does not exist.' : (data.error || `Error ${status}`));
        return;
      }

      let contact;
      try {
        contact = await decryptContact(password, data);
      } catch {
        setViewAlert('Wrong password. Please try again.');
        pwdInput.select();
        return;
      }

      renderContactCard(slug, contact, password, data.updatedAt);
    } catch (e) {
      console.error(e);
      setViewAlert('Network error. Please check your connection and try again.');
    } finally {
      viewBtn.disabled = false;
      viewBtn.textContent = 'Unlock';
    }
  }

  viewBtn.addEventListener('click', tryUnlock);
  pwdInput.addEventListener('keydown', e => { if (e.key === 'Enter') tryUnlock(); });
  // Auto-focus password field
  setTimeout(() => pwdInput.focus(), 50);
}

function setViewAlert(msg) {
  const icons = { error: '⚠️' };
  el('view-alert').innerHTML = msg
    ? `<div class="alert alert-error"><span class="alert-icon">⚠️</span><span>${escHtml(msg)}</span></div>`
    : '';
}

// ── Contact card ──────────────────────────────────────────────────────────────

function renderContactCard(slug, contact, password, updatedAt) {
  const app = document.getElementById('app');

  const phonesHtml = (contact.phones || []).map(p =>
    `<li><span class="detail-icon">📞</span>
     <a class="detail-link" href="tel:${escHtml(p)}">${escHtml(p)}</a></li>`,
  ).join('');

  const emailsHtml = (contact.emails || []).map(e =>
    `<li><span class="detail-icon">✉️</span>
     <a class="detail-link" href="mailto:${escHtml(e)}">${escHtml(e)}</a></li>`,
  ).join('');

  const addressHtml = contact.address
    ? `<li><span class="detail-icon">📍</span>
       <span class="detail-text">${escHtml(contact.address)}</span></li>` : '';

  const notesHtml = contact.notes
    ? `<li><span class="detail-icon">📝</span>
       <span class="detail-text">${escHtml(contact.notes)}</span></li>` : '';

  const noDetails = !phonesHtml && !emailsHtml && !addressHtml && !notesHtml;

  app.innerHTML = `
    <div class="card">
      <span class="security-badge">🔒 Decrypted locally</span>
      ${contact.name ? `<div class="contact-name">${escHtml(contact.name)}</div>` : ''}

      ${noDetails ? '<p style="color:var(--gray-400);font-size:.9rem">No contact details on this page.</p>' : `
      <ul class="contact-detail-list">
        ${phonesHtml}${emailsHtml}${addressHtml}${notesHtml}
      </ul>`}

      ${updatedAt ? `<p class="updated-at">Last updated: ${escHtml(formatDate(updatedAt))}</p>` : ''}

      <div class="btn-row" style="margin-top:1.25rem">
        <button type="button" class="btn btn-secondary" id="update-btn">✏️ Update this page</button>
        <button type="button" class="btn btn-danger btn-sm"  id="delete-btn">Delete page</button>
      </div>
    </div>
  `;

  el('update-btn').addEventListener('click', () => renderUpdateForm(slug, password, contact));
  el('delete-btn').addEventListener('click', () => confirmDelete(slug, password));
}

// ═══════════════════════════════════════════════════════════════════════════════
// UPDATE FORM
// ═══════════════════════════════════════════════════════════════════════════════

function renderUpdateForm(slug, password, existing) {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="card">
      <div class="card-title">Update contact page</div>
      <div class="card-subtitle">/${escHtml(slug)}</div>

      <div id="update-alert"></div>

      <p class="section-label">Contact details</p>

      <div class="field">
        <label for="u-name">Full name</label>
        <input type="text" id="u-name" value="${escHtml(existing.name || '')}" placeholder="Alex Smith" />
      </div>

      <div class="field">
        <label>Phone numbers</label>
        <div class="multi-field" id="u-phones-list">
          ${(existing.phones?.length ? existing.phones : ['']).map(p =>
            `<div class="input-row"><input type="tel" value="${escHtml(p)}" placeholder="+1 555 000 0000" /></div>`
          ).join('')}
        </div>
        <button type="button" class="add-btn" id="u-add-phone">+ Add phone</button>
      </div>

      <div class="field">
        <label>Email addresses</label>
        <div class="multi-field" id="u-emails-list">
          ${(existing.emails?.length ? existing.emails : ['']).map(e =>
            `<div class="input-row"><input type="email" value="${escHtml(e)}" placeholder="you@example.com" /></div>`
          ).join('')}
        </div>
        <button type="button" class="add-btn" id="u-add-email">+ Add email</button>
      </div>

      <div class="field">
        <label for="u-address">Address <span class="optional">(optional)</span></label>
        <textarea id="u-address" rows="2">${escHtml(existing.address || '')}</textarea>
      </div>

      <div class="field">
        <label for="u-notes">Message to the finder <span class="optional">(optional, max 256 chars)</span></label>
        <textarea id="u-notes" rows="3" maxlength="256">${escHtml(existing.notes || '')}</textarea>
        <p class="char-count" id="u-notes-count">${(existing.notes || '').length} / 256</p>
      </div>

      <hr class="divider" />
      <p class="section-label">Change password <span class="optional">(leave blank to keep current)</span></p>

      <div class="field">
        <label for="u-newpass">New password</label>
        <input type="password" id="u-newpass" placeholder="Leave blank to keep current" autocomplete="new-password" />
      </div>
      <div class="field">
        <label for="u-newpass2">Confirm new password</label>
        <input type="password" id="u-newpass2" placeholder="Repeat new password" autocomplete="new-password" />
      </div>

      <div class="btn-row">
        <button type="button" class="btn btn-primary" id="save-btn">💾 Save changes</button>
        <button type="button" class="btn btn-secondary" id="cancel-update-btn">Cancel</button>
      </div>
    </div>
  `;

  addMultiInputWiring('u-phones-list', 'u-add-phone', 'tel',   '+1 555 000 0000', 5);
  addMultiInputWiring('u-emails-list', 'u-add-email', 'email', 'you@example.com', 3);

  const uNotes = el('u-notes'), uCount = el('u-notes-count');
  uNotes.addEventListener('input', () => {
    const n = uNotes.value.length;
    uCount.textContent = `${n} / 256`;
    uCount.className = n > 240 ? 'char-count warn' : n >= 256 ? 'char-count over' : 'char-count';
  });

  el('cancel-update-btn').addEventListener('click', () => {
    // Re-fetch and re-render the contact card
    renderViewPage(slug);
  });

  el('save-btn').addEventListener('click', () => handleSaveUpdate(slug, password));
}

async function handleSaveUpdate(slug, currentPassword) {
  const btn = el('save-btn');
  btn.disabled = true;
  btn.textContent = 'Saving…';
  setUpdateAlert('');

  try {
    const name    = el('u-name').value.trim();
    const address = el('u-address').value.trim();
    const notes   = el('u-notes').value.trim().slice(0, 256);
    const phones  = getMultiValues('u-phones-list');
    const emails  = getMultiValues('u-emails-list');
    const newPass = el('u-newpass').value;
    const newPass2= el('u-newpass2').value;

    if (newPass && newPass !== newPass2) {
      setUpdateAlert('New passwords do not match.'); return;
    }
    if (newPass && newPass.length < 8) {
      setUpdateAlert('New password must be at least 8 characters.'); return;
    }

    const contactData = { name, phones, emails, address, notes };
    const savePassword = newPass || currentPassword;

    const encrypted  = await encryptContact(savePassword, contactData);
    const verifier   = await deriveVerifier(currentPassword, slug);
    const newVerifier = newPass ? await deriveVerifier(newPass, slug) : undefined;

    const payload = { verifier, ...encrypted };
    if (newVerifier) payload.newVerifier = newVerifier;

    const { ok, status, data } = await apiUpdate(slug, payload);

    if (ok) {
      // Re-render contact card with updated data and new password
      renderContactCard(slug, contactData, savePassword, new Date().toISOString());
      // Show a brief success notice
      const notice = document.createElement('div');
      notice.className = 'alert alert-success';
      notice.style.marginBottom = '1rem';
      notice.innerHTML = '<span class="alert-icon">✅</span><span>Contact page updated successfully.</span>';
      document.getElementById('app').prepend(notice);
      setTimeout(() => notice.remove(), 4000);
    } else {
      setUpdateAlert(data.error || `Error ${status}. Please try again.`);
    }
  } catch (e) {
    console.error(e);
    setUpdateAlert('Something went wrong. Please try again.');
  } finally {
    btn.disabled = false;
    btn.textContent = '💾 Save changes';
  }
}

function setUpdateAlert(msg) {
  el('update-alert').innerHTML = msg
    ? `<div class="alert alert-error"><span class="alert-icon">⚠️</span><span>${escHtml(msg)}</span></div>`
    : '';
}

// ═══════════════════════════════════════════════════════════════════════════════
// DELETE
// ═══════════════════════════════════════════════════════════════════════════════

async function confirmDelete(slug, password) {
  if (!confirm(`Permanently delete the page "/${slug}"? This cannot be undone.`)) return;

  try {
    const verifier = await deriveVerifier(password, slug);
    const { ok, data } = await apiDelete(slug, verifier);
    if (ok) {
      const app = document.getElementById('app');
      app.innerHTML = `
        <div class="card" style="text-align:center;padding:2.5rem 1.5rem">
          <span style="font-size:2.5rem;display:block;margin-bottom:.75rem">🗑️</span>
          <h2 style="margin-bottom:.5rem">Page deleted</h2>
          <p style="color:var(--gray-600);margin-bottom:1.5rem">
            The contact page <strong>/${escHtml(slug)}</strong> has been permanently removed.
          </p>
          <a href="/" class="btn btn-primary">Create a new page</a>
        </div>
      `;
    } else {
      alert(data.error || 'Delete failed. Please try again.');
    }
  } catch (e) {
    console.error(e);
    alert('Network error. Please try again.');
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ABOUT PAGE
// ═══════════════════════════════════════════════════════════════════════════════

function renderAboutPage() {
  document.getElementById('app').innerHTML = `
    <div class="static-page">
      <div class="page-hero">
        <h1>About CallHome</h1>
        <p class="lead">
          A simple, free tool to create password-protected emergency contact pages.
          Built for the moment you lose your phone and someone needs to reach you.
        </p>
      </div>

      <div class="feature-grid">
        <div class="feature-card">
          <span class="feature-icon">🔒</span>
          <h3>End-to-end encrypted</h3>
          <p>Your contact data is encrypted in your browser before it ever leaves your device. The server stores only an unreadable blob.</p>
        </div>
        <div class="feature-card">
          <span class="feature-icon">🔑</span>
          <h3>Password protected</h3>
          <p>Only people who know the password can view or update the page. No accounts, no sign-ups.</p>
        </div>
        <div class="feature-card">
          <span class="feature-icon">🔔</span>
          <h3>Push notifications</h3>
          <p>Optionally get notified via <a href="https://ntfy.sh" target="_blank" rel="noopener">ntfy.sh</a> when your page is updated.</p>
        </div>
        <div class="feature-card">
          <span class="feature-icon">💚</span>
          <h3>Free &amp; open source</h3>
          <p>No ads, no tracking, no monetization. The <a href="https://github.com/jkk1/callhome" target="_blank" rel="noopener">source code</a> is public for anyone to inspect.</p>
        </div>
      </div>

      <h2>How it works</h2>
      <ol class="how-it-works">
        <li><div>
          <strong>Create your page</strong>
          Choose a custom URL, set a password, and enter your contact details (name, phone, email, address, a short message).
        </div></li>
        <li><div>
          <strong>Everything is encrypted in your browser</strong>
          Your password is used to derive an AES-256-GCM encryption key via PBKDF2 (200,000 iterations).
          The contact data is encrypted before being sent to the server.
          The server never sees the plaintext or your password.
        </div></li>
        <li><div>
          <strong>Share the URL</strong>
          Give the link and password to family, friends, or anyone who might need to reach you in an emergency.
        </div></li>
        <li><div>
          <strong>Someone visits your page</strong>
          They enter the password. The encrypted blob is fetched from the server and decrypted
          entirely in their browser. If the password is wrong, decryption fails and nothing is revealed.
        </div></li>
      </ol>

      <h2>Technical details</h2>
      <ul>
        <li><strong>Encryption:</strong> AES-256-GCM with a 12-byte IV and 16-byte random salt.</li>
        <li><strong>Key derivation:</strong> PBKDF2 with SHA-256, 200,000 iterations.</li>
        <li><strong>Write authentication:</strong> A separate PBKDF2-derived verifier (different salt) is stored server-side to authenticate updates without revealing the password.</li>
        <li><strong>Storage:</strong> Cloudflare Workers KV. The server stores only the encrypted blob, IV, salt, and verifier.</li>
        <li><strong>No JavaScript frameworks:</strong> Vanilla JS, no build step, no dependencies.</li>
      </ul>

      <div class="oss-banner">
        <h2>Open source, always</h2>
        <p>
          CallHome is free, has no ads, and will never monetize your data.
          The entire codebase is open for inspection, forking, and self-hosting.
        </p>
        <a href="https://github.com/jkk1/callhome" target="_blank" rel="noopener" class="btn">View on GitHub</a>
      </div>

      <h2>Who is this for?</h2>
      <p>
        Anyone who wants a backup way to be reached. Stick the URL on a label inside your
        phone case, save it as a bookmark, or share it with your emergency contacts.
        If your phone is lost or stolen, anyone who finds it (or anyone you've shared
        the password with) can look up how to reach you.
      </p>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PRIVACY PAGE
// ═══════════════════════════════════════════════════════════════════════════════

function renderPrivacyPage() {
  document.getElementById('app').innerHTML = `
    <div class="static-page">
      <div class="page-hero">
        <h1>Privacy Notice</h1>
        <p class="lead">
          CallHome is designed from the ground up to know as little about you as possible.
        </p>
      </div>

      <h2>What we store</h2>
      <ul>
        <li><strong>Encrypted contact data:</strong> An AES-256-GCM ciphertext blob, an IV, and a salt. We cannot read this data.</li>
        <li><strong>Password verifier:</strong> A PBKDF2-derived hash used to authenticate write requests. This is not your password and cannot be used to decrypt your data.</li>
        <li><strong>Notification topic:</strong> If you choose to receive push notifications, we store your ntfy.sh topic name so the server can send notifications when your page is updated.</li>
        <li><strong>Timestamps:</strong> When the page was created and last updated.</li>
      </ul>

      <h2>What we never see</h2>
      <ul>
        <li>Your contact details (name, phone, email, address, notes) in plaintext.</li>
        <li>Your password. It never leaves your browser.</li>
        <li>Who views your page (we do not log access).</li>
      </ul>

      <h2>Cookies &amp; tracking</h2>
      <p>
        CallHome does not use cookies, analytics, tracking pixels, fingerprinting, or any
        third-party scripts. There is no advertising. There is no monetization of any kind.
      </p>

      <h2>Third-party services</h2>
      <ul>
        <li><strong>Cloudflare:</strong> The app is hosted on Cloudflare Pages and Workers. Cloudflare may process standard HTTP metadata (IP addresses, headers) as part of their infrastructure. See <a href="https://www.cloudflare.com/privacypolicy/" target="_blank" rel="noopener">Cloudflare's privacy policy</a>.</li>
        <li><strong>ntfy.sh:</strong> If you opt in to notifications, update events are sent to ntfy.sh. See <a href="https://ntfy.sh/docs/privacy/" target="_blank" rel="noopener">ntfy.sh's privacy info</a>.</li>
      </ul>

      <h2>Data retention &amp; deletion</h2>
      <p>
        Your encrypted data is stored in Cloudflare KV until you delete it.
        You can delete your page at any time from the view screen (requires your password).
        Deletion is permanent and immediate.
      </p>

      <h2>Rate limiting</h2>
      <p>
        To prevent abuse, we enforce per-IP rate limits on page creation and reads.
        IP addresses used for rate limiting are stored temporarily (bucket counters in KV with short TTLs)
        and are not associated with any contact data.
      </p>

      <h2>Open source</h2>
      <p>
        The complete source code is available at
        <a href="https://github.com/jkk1/callhome" target="_blank" rel="noopener">github.com/jkk1/callhome</a>.
        You can verify every claim on this page by reading the code, or self-host your own instance.
      </p>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TERMS PAGE
// ═══════════════════════════════════════════════════════════════════════════════

function renderTermsPage() {
  document.getElementById('app').innerHTML = `
    <div class="static-page">
      <div class="page-hero">
        <h1>Terms of Service</h1>
        <p class="lead">Simple terms for a simple service.</p>
      </div>

      <h2>The service</h2>
      <p>
        CallHome lets you create password-protected, end-to-end encrypted contact pages
        hosted on our domain. The service is provided free of charge, as-is, with no warranty.
      </p>

      <h2>Your responsibilities</h2>
      <ul>
        <li><strong>Keep your password safe.</strong> We cannot recover your data without it. There is no password reset.</li>
        <li><strong>Do not abuse the service.</strong> Do not use CallHome to store illegal content, spam, or anything unrelated to emergency contact information.</li>
        <li><strong>Do not share others' contact details without their consent.</strong></li>
        <li><strong>Respect rate limits.</strong> Automated bulk creation or scraping is not allowed.</li>
      </ul>

      <h2>Our responsibilities</h2>
      <ul>
        <li>We will make reasonable efforts to keep the service available, but we do not guarantee uptime.</li>
        <li>We will not attempt to decrypt your data or access your password.</li>
        <li>We will not sell, share, or monetize any data stored on the platform.</li>
        <li>We will keep the source code open so you can verify our claims.</li>
      </ul>

      <h2>Content &amp; removal</h2>
      <p>
        Since all contact data is encrypted and we cannot read it, we generally cannot
        moderate content. However, we reserve the right to remove any page if we receive
        a valid legal request or if we determine the slug (URL) itself is being used for
        abuse (e.g., impersonation, harassment).
      </p>

      <h2>Limitation of liability</h2>
      <p>
        CallHome is provided "as is" without warranty of any kind. We are not liable for
        any data loss, inability to access your page, or any damages arising from use of
        the service. This is a free, community tool — please keep your own backups of
        important contact information.
      </p>

      <h2>Changes</h2>
      <p>
        We may update these terms from time to time. Continued use of the service after
        changes constitutes acceptance. Since the code is open source, all changes are
        publicly visible in the repository history.
      </p>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════════════════
// BOOTSTRAP — SPA router, link interception, mobile nav
// ═══════════════════════════════════════════════════════════════════════════════

(function init() {
  // Intercept all internal [data-route] links for SPA navigation
  document.addEventListener('click', (e) => {
    const link = e.target.closest('[data-route]');
    if (!link) return;
    e.preventDefault();
    const path = link.getAttribute('data-route') || link.getAttribute('href');
    if (path) navigate(path);
    // Close mobile nav if open
    const mobileNav = el('mobile-nav');
    if (mobileNav) mobileNav.classList.remove('open');
  });

  // Browser back/forward
  window.addEventListener('popstate', () => route());

  // Mobile nav toggle
  const toggle = el('nav-toggle');
  if (toggle) {
    toggle.addEventListener('click', () => {
      const nav = el('mobile-nav');
      if (nav) nav.classList.toggle('open');
    });
  }

  // Initial route
  route();
})();
