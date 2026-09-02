/* ================================================================
   BillboardIQ Auth API — Cloudflare Pages Functions + D1
   Binding required: D1 database bound as `DB` in Pages settings.
   Optional secrets: RESEND_API_KEY (owner email notification on new
   signups — silently skipped if unset), OWNER_NOTIFY_EMAIL (destination,
   defaults to OWNER_NOTIFY_EMAIL constant below).
   MFA is mandatory for provider/agent/admin/superuser (MFA_REQUIRED_ROLES)
   — enforced fresh on every request from current role + MFA status, so a
   role change or a newly-added mandatory role takes effect immediately
   for already-open sessions, not just new logins (see getAuth()).

   Companies (schema/008+): billboards belong to a `company`, shared by
   every user in it (provider or agent role) — not just their creator.
   `provider` accounts own/add billboards; `agent` accounts manage
   existing inventory and their own `customers` (lightweight tenants like
   "Coca-Cola") without creating new billboards. Budgets on a customer are
   informational only — nothing here blocks a booking.

   Endpoints (all under /api/):
     GET  auth/status          → { needsBootstrap }
     GET  auth/companies       → public, company picker for signup
     POST auth/bootstrap       → create FIRST superuser (only when DB empty)
     POST auth/register        → public signup (role: user/provider/agent)
     POST auth/login           → step 1 (password)
     POST auth/mfa/verify      → step 2 (TOTP code) → session
     POST auth/mfa/enroll      → get secret + otpauth URI (auth required)
     POST auth/mfa/confirm     → confirm enrollment with code
     POST auth/logout
     GET  me
     GET  admin/users          → admin+
     POST admin/role           → superuser
     POST admin/users/delete   → superuser
     GET  admin/audit          → superuser
     GET  admin/ai-engine/status → superuser, pending snapshot count
     POST admin/ai-engine/run  → superuser, streams NDJSON progress — analyzes
                                  queued pending_snapshots with Claude vision
     GET  admin/companies      → superuser, company list + aggregate stats
     POST admin/companies/create → superuser, pre-onboard a company
     GET  admin/companies/<id> → superuser, members + per-user login count + audit slice + inventory/revenue stats
     GET  admin/stats/overview → superuser, platform-wide aggregates for the console's live dashboard charts
     GET  formats/list         → provider+, own billboard-format catalog
     POST formats/create       → provider+
     POST formats/delete       → provider+
     GET  billboards/<id>/traffic → company/admin+, collected traffic-engine data
     GET  customers/list, POST customers/create|update|delete → provider/agent+, own company's tenants
     GET  customers/<id>/suggestions → provider/agent+, available billboards matching a tenant's categories
     POST billboards/assign-customer → provider/agent+, tag a booked billboard to a customer
     GET  favorites/mine, POST favorites/toggle → any signed-in user
     GET  company/dashboard    → any company member, inventory/revenue/favorites stats
     GET  company/customers-overview → provider/agent+, per-customer spend vs. budget
   ================================================================ */

const PBKDF2_ITERATIONS = 100000; // lower to 50000 if you ever hit CPU limits on free tier
const SESSION_DAYS = 7;
const MFA_PENDING_MINUTES = 5;
const LOCKOUT_AFTER = 5;          // failed attempts
const LOCKOUT_MINUTES = 15;
const MIN_PASSWORD_LEN = 10;
const MFA_REQUIRED_ROLES = ['provider', 'agent', 'admin', 'superuser'];
const ROLE_RANK = { user: 1, provider: 1, agent: 1, admin: 2, superuser: 3 };
const PUBLISH_ROLES = ['provider', 'admin', 'superuser']; // who can add brand-new billboards
const MANAGE_INVENTORY_ROLES = ['provider', 'agent', 'admin', 'superuser']; // who can edit/tag a company's existing inventory
const COMPANY_ROLES = ['provider', 'agent']; // roles that require a company at signup
const EXPIRING_SOON_MS = 30 * 86400000; // booking_end within this window counts as "expiring soon" on the dashboard
const CLAUDE_MODEL = 'claude-opus-4-8';
const OWNER_NOTIFY_EMAIL = 'wenga212@gmail.com';

const enc = new TextEncoder();

/* ---------------- tiny utils ---------------- */
const json = (data, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...extraHeaders }
  });
const bad = (error, status = 400, extra = {}) => json({ error, ...extra }, status);

function hex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(str) {
  const out = new Uint8Array(str.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(str.substr(i * 2, 2), 16);
  return out;
}
function randHex(nBytes) {
  const a = new Uint8Array(nBytes);
  crypto.getRandomValues(a);
  return hex(a.buffer);
}
async function sha256hex(str) {
  return hex(await crypto.subtle.digest('SHA-256', enc.encode(str)));
}
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

/* ---------------- passwords (PBKDF2-SHA256) ---------------- */
async function derive(password, saltBytes) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations: PBKDF2_ITERATIONS },
    key, 256
  );
  return hex(bits);
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return { hash: await derive(password, salt), salt: hex(salt.buffer) };
}
async function verifyPassword(password, saltHex, expectedHash) {
  const got = await derive(password, fromHex(saltHex));
  return safeEqual(got, expectedHash);
}

/* ---------------- TOTP (RFC 6238, SHA-1, 6 digits, 30s) ---------------- */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32encode(bytes) {
  let bits = 0, value = 0, out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
function b32decode(str) {
  const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0; const out = [];
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch); bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
async function hotp(secretBytes, counter) {
  const key = await crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const msg = new ArrayBuffer(8);
  new DataView(msg).setUint32(4, counter); // high 4 bytes stay zero (fine until far future)
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const off = sig[19] & 0xf;
  const code = (((sig[off] & 0x7f) << 24) | (sig[off + 1] << 16) | (sig[off + 2] << 8) | sig[off + 3]) % 1000000;
  return code.toString().padStart(6, '0');
}
async function verifyTotp(secretB32, code) {
  if (!/^\d{6}$/.test(code || '')) return false;
  const secret = b32decode(secretB32);
  const step = Math.floor(Date.now() / 30000);
  for (const c of [step - 1, step, step + 1]) {
    if (safeEqual(await hotp(secret, c), code)) return true;
  }
  return false;
}

/* ---------------- sessions & cookies ---------------- */
function getCookie(req, name) {
  const c = req.headers.get('Cookie') || '';
  const m = c.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? m[1] : null;
}
function sessionCookie(token, expMs) {
  return 'bbiq_session=' + token + '; HttpOnly; Secure; SameSite=Lax; Path=/; Expires=' + new Date(expMs).toUTCString();
}
const CLEAR_COOKIE = 'bbiq_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0';

async function createSession(env, req, userId, restricted) {
  const token = randHex(32);
  const th = await sha256hex(token);
  const exp = Date.now() + SESSION_DAYS * 86400000;
  await env.DB.prepare(
    'INSERT INTO sessions (token_hash, user_id, restricted, expires_at, created_at, ip, user_agent) VALUES (?,?,?,?,?,?,?)'
  ).bind(
    th, userId, restricted ? 1 : 0, exp, Date.now(),
    req.headers.get('CF-Connecting-IP') || '',
    (req.headers.get('User-Agent') || '').slice(0, 200)
  ).run();
  await env.DB.prepare('UPDATE users SET last_login=? WHERE id=?').bind(Date.now(), userId).run();
  return { token, exp };
}

async function getAuth(env, req) {
  const tok = getCookie(req, 'bbiq_session');
  if (!tok) return null;
  const th = await sha256hex(tok);
  const row = await env.DB.prepare(
    'SELECT s.token_hash AS session_hash, s.expires_at AS session_expires, u.* ' +
    'FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?'
  ).bind(th).first();
  if (!row || row.session_expires < Date.now()) return null;
  // Recomputed fresh every request from the user's *current* role and MFA
  // status — not trusted from whatever was stored on the sessions row at
  // login time. That's what makes a role change (e.g. promoting someone
  // into an MFA-mandatory role, or demoting them out of one) take effect
  // immediately on their very next request, without needing them to log
  // out and back in, and without leaving a demoted user stuck behind an
  // MFA wall for a role they no longer have.
  row.restricted = MFA_REQUIRED_ROLES.includes(row.role) && !row.mfa_enabled;
  return row;
}

function safeUser(u, restricted) {
  return {
    id: u.id, email: u.email, name: u.name, role: u.role,
    companyName: u.company_name || null,
    companyId: u.company_id || null,
    mfaEnabled: !!u.mfa_enabled,
    verified: !!u.verified,
    restricted: !!restricted,
    lastLogin: u.last_login, createdAt: u.created_at
  };
}

async function audit(env, userId, action, detail) {
  try {
    await env.DB.prepare('INSERT INTO audit_log (user_id, action, detail, created_at) VALUES (?,?,?,?)')
      .bind(userId || null, action, (detail || '').slice(0, 300), Date.now()).run();
  } catch (e) { /* audit must never break auth */ }
}

// Notifies the site owner by email whenever a new account is created (a
// genuinely new sign-in request, as opposed to an existing user logging
// back in). Uses Resend's REST API — no SDK needed, just a fetch — gated
// behind env.RESEND_API_KEY so this is a silent no-op until that secret is
// set (wrangler pages secret put RESEND_API_KEY). Never throws into the
// caller: a notification failure must never block someone from signing up.
async function notifyOwnerOfNewAccount(env, { email, name, role, companyName }) {
  if (!env.RESEND_API_KEY) return;
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + env.RESEND_API_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: env.RESEND_FROM || 'BillboardIQ <onboarding@resend.dev>',
        to: [env.OWNER_NOTIFY_EMAIL || OWNER_NOTIFY_EMAIL],
        subject: 'BillboardIQ: new ' + role + ' account — ' + email,
        text: 'A new account just signed up.\n\n' +
          'Name: ' + name + '\n' +
          'Email: ' + email + '\n' +
          'Role: ' + role + (companyName ? '\nCompany: ' + companyName : '') + '\n' +
          'Time: ' + new Date().toISOString()
      })
    });
  } catch (e) { /* notification must never break signup */ }
}

/* ---------------- AI traffic engine (manual run, superuser only) ----------
   Mirrors worker/src/index.js's analyzeScreenshot() — that Worker only
   captures screenshots into pending_snapshots; this is the interactive
   analysis half (Claude vision call + write to traffic_snapshots), now
   triggerable from the admin console instead of a Claude Code session. */
async function analyzeScreenshot(env, imageBase64) {
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      model: CLAUDE_MODEL,
      max_tokens: 400,
      output_config: {
        format: {
          type: 'json_schema',
          schema: {
            type: 'object',
            properties: {
              congestionScore: { type: 'integer' },
              densityLabel: { type: 'string', enum: ['free', 'heavy', 'severe'] },
              note: { type: 'string' }
            },
            required: ['congestionScore', 'densityLabel', 'note'],
            additionalProperties: false
          }
        }
      },
      messages: [{
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: imageBase64 } },
          {
            type: 'text',
            text: 'This is a screenshot of Google Maps with the live traffic layer enabled, centered on a billboard location. ' +
              "Read the colored road segments in roughly a 500m radius around the center of the image, using Google's own " +
              'traffic-layer legend: green = free-flowing (roughly 50mph+, no delay), orange = medium traffic (roughly ' +
              '25-50mph), red = heavy delays (under 25mph), dark red = extremely slow or stationary (often an incident). ' +
              'Estimate an overall congestion score from 0 (completely free-flowing, all green) to 100 (gridlocked, dark red ' +
              'throughout) — the more orange/red visible and the larger the affected area, the higher the score. Pick ' +
              'densityLabel "free" if the score would be under 50, "heavy" if 50 or higher, or "severe" specifically for ' +
              'extremely slow/stationary dark-red conditions (typically 85+). Write one short sentence describing what you ' +
              'see (which roads are congested, and which color dominates). If no colored traffic data is visible at all, ' +
              'use congestionScore 0, densityLabel "free", and say so in the note.'
          }
        ]
      }]
    })
  });
  if (!resp.ok) throw new Error('Claude vision call failed: ' + resp.status + ' ' + (await resp.text()));
  const data = await resp.json();
  const textBlock = (data.content || []).find(b => b.type === 'text');
  if (!textBlock) throw new Error('No text block in Claude response');
  return JSON.parse(textBlock.text);
}

// Streams newline-delimited JSON progress events while it works through
// pending_snapshots one row at a time — the response body IS the job, so
// there's no separate polling endpoint to keep in sync.
function runAiEngine(env, me) {
  const encoder = new TextEncoder();
  let ctrl;
  const stream = new ReadableStream({ start(c) { ctrl = c; } });
  const send = obj => ctrl.enqueue(encoder.encode(JSON.stringify(obj) + '\n'));

  (async () => {
    let processed = 0, failed = 0;
    try {
      const rows = await env.DB.prepare(
        'SELECT id, billboard_id, captured_at, image_data FROM pending_snapshots ORDER BY captured_at ASC'
      ).all();
      const pending = rows.results || [];
      send({ type: 'start', total: pending.length });

      if (!pending.length) {
        send({ type: 'log', message: 'No pending snapshots — nothing to analyze.' });
      }

      for (let i = 0; i < pending.length; i++) {
        const row = pending[i];
        send({ type: 'log', message: `Analyzing ${row.billboard_id} (${i + 1}/${pending.length})…`, done: i, total: pending.length });
        try {
          const base64 = row.image_data.replace(/^data:image\/\w+;base64,/, '');
          const result = await analyzeScreenshot(env, base64);
          await env.DB.prepare(
            `INSERT INTO traffic_snapshots (id, billboard_id, captured_at, congestion_score, density_label, note, created_at)
             VALUES (?,?,?,?,?,?,?)`
          ).bind('TS-' + shortId(), row.billboard_id, row.captured_at, result.congestionScore, result.densityLabel, result.note, Date.now()).run();
          await env.DB.prepare('DELETE FROM pending_snapshots WHERE id=?').bind(row.id).run();
          processed++;
          send({
            type: 'log',
            message: `→ ${row.billboard_id}: congestion ${result.congestionScore} (${result.densityLabel}) — ${result.note}`,
            done: i + 1, total: pending.length
          });
        } catch (e) {
          failed++;
          send({ type: 'log', message: `✗ ${row.billboard_id} failed: ${e.message}`, done: i + 1, total: pending.length, error: true });
        }
      }

      await audit(env, me.id, 'ai_engine_run', `${processed} processed, ${failed} failed`);
      send({ type: 'complete', processed, failed });
    } catch (e) {
      send({ type: 'error', message: e.message });
    } finally {
      ctrl.close();
    }
  })();

  return new Response(stream, {
    headers: { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }
  });
}

function validEmail(e) { return typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 200; }

/* ---------------- billboards helpers ---------------- */

// Every billboard column EXCEPT image_data, which is far too big to ship in a
// list payload. Listings expose `hasImage` and fetch the bytes separately from
// GET billboards/<id>/image.
const BB_LIST_COLS = `b.id, b.owner_id, b.company_id, b.customer_id, b.title, b.area, b.description, b.lat, b.lng, b.size,
  b.type, b.category, b.illuminated, b.price, b.traffic, b.peak_hours,
  b.audience_male, b.audience_female, b.audience_age, b.audience_income,
  b.availability, b.approval_state, b.rejection_note, b.reviewed_by, b.reviewed_at,
  b.owner_verified, b.created_at, b.updated_at, b.data_sources,
  b.format_id, b.building_name, b.resolution, b.ad_duration,
  b.booking_start, b.booking_end, b.facing, b.ai_insights, b.ai_insights_updated_at,
  (b.image_data IS NOT NULL) AS has_image`;

const COMPASS_DIRECTIONS = ['N', 'NE', 'E', 'SE', 'S', 'SW', 'W', 'NW'];

const MAX_IMAGE_CHARS = 1600000; // base64 chars ≈ 1.2MB binary, under D1's ~2MB row cap
const IMAGE_DATA_URL = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/;

// Returns { value } on success (string data URL or null to clear), or { error }.
function normalizeImage(input) {
  if (input === null || input === '') return { value: null };
  if (typeof input !== 'string') return { error: 'Invalid image payload.' };
  if (input.length > MAX_IMAGE_CHARS) return { error: 'That image is too large — please use a smaller photo.' };
  if (!IMAGE_DATA_URL.test(input)) return { error: 'Image must be a JPEG, PNG, or WebP.' };
  return { value: input };
}

function shortId() {
  // 6-char base36 ID, e.g. "K3M9AZ"
  const bytes = crypto.getRandomValues(new Uint8Array(4));
  return [...bytes].map(b => b.toString(36).toUpperCase().padStart(2, '0')).join('').slice(0, 6);
}
function clamp(v, lo, hi, fallback) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(lo, Math.min(hi, Math.round(n)));
}
function bbRow(r) {
  if (!r) return null;
  let peak = [];
  try { peak = JSON.parse(r.peak_hours || '[]'); } catch (e) {}
  let dataSources = null;
  try { dataSources = r.data_sources ? JSON.parse(r.data_sources) : null; } catch (e) {}
  return {
    id: r.id,
    ownerId: r.owner_id,
    companyId: r.company_id || null,
    customerId: r.customer_id || null,
    ownerName: r.owner_name || undefined,
    ownerCompany: r.owner_company || undefined,
    ownerEmail: r.owner_email || undefined,
    ownerVerified: !!(r.owner_verified_flag ?? r.owner_verified),
    // image_data itself is never returned — see BB_LIST_COLS
    hasImage: !!(r.has_image ?? r.image_data),
    title: r.title,
    area: r.area,
    description: r.description || '',
    lat: r.lat, lng: r.lng,
    size: r.size,
    formatId: r.format_id || null,
    buildingName: r.building_name || null,
    resolution: r.resolution || null,
    adDuration: r.ad_duration || null,
    type: r.type,
    category: r.category,
    illuminated: !!r.illuminated,
    price: r.price,
    traffic: r.traffic,
    peakHours: peak,
    audience: {
      male: r.audience_male, female: r.audience_female,
      age: r.audience_age, income: r.audience_income
    },
    availability: r.availability,
    bookingStart: r.booking_start || null,
    bookingEnd: r.booking_end || null,
    facing: r.facing || null,
    aiInsights: r.ai_insights || null,
    aiInsightsUpdatedAt: r.ai_insights_updated_at || null,
    approvalState: r.approval_state,
    rejectionNote: r.rejection_note || null,
    reviewedAt: r.reviewed_at,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    dataSources: dataSources
  };
}
function formatRow(r) {
  if (!r) return null;
  return {
    id: r.id,
    type: r.type,
    size: r.size || null,
    buildingName: r.building_name || null,
    resolution: r.resolution || null,
    adDuration: r.ad_duration || null,
    createdAt: r.created_at
  };
}
function customerRow(r) {
  if (!r) return null;
  return {
    id: r.id,
    companyId: r.company_id,
    name: r.name,
    budget: r.budget != null ? r.budget : null,
    notes: r.notes || null,
    createdAt: r.created_at
  };
}
function validateCustomer(c) {
  if (!c || typeof c !== 'object') return 'Missing data.';
  if (!c.name || String(c.name).trim().length < 2) return 'Please enter the customer name.';
  if (String(c.name).length > 150) return 'Name is too long.';
  if (c.budget !== undefined && c.budget !== null && c.budget !== '') {
    const b = Number(c.budget);
    if (!Number.isFinite(b) || b < 0) return 'Budget must be zero or more.';
  }
  return null;
}
function validateFormat(f) {
  if (!f || typeof f !== 'object') return 'Missing data.';
  if (!['hoarding', 'banner', 'digital_display'].includes(f.type)) return 'Type must be hoarding, banner, or digital display.';
  if (f.type === 'digital_display') {
    if (!f.buildingName || String(f.buildingName).trim().length < 2) return 'Please enter the building name.';
    if (!f.resolution || String(f.resolution).trim().length < 2) return 'Please enter the screen resolution (e.g. "1920x1080").';
  } else {
    if (!f.size || String(f.size).trim().length < 2) return 'Please enter a size (e.g. "40x20 ft").';
  }
  return null;
}
function validateBillboard(b) {
  if (!b || typeof b !== 'object') return 'Missing data.';
  if (!b.title || String(b.title).trim().length < 3) return 'Title must be at least 3 characters.';
  if (String(b.title).length > 120) return 'Title is too long.';
  if (!b.area || String(b.area).trim().length < 2) return 'Please enter an area or neighbourhood.';
  const lat = Number(b.lat), lng = Number(b.lng);
  if (!Number.isFinite(lat) || lat < -90 || lat > 90) return 'Pick a location on the map (invalid latitude).';
  if (!Number.isFinite(lng) || lng < -180 || lng > 180) return 'Pick a location on the map (invalid longitude).';
  if (!b.size || String(b.size).trim().length < 2) return 'Please enter a size (e.g. "40x20 ft").';
  if (!['hoarding', 'banner', 'digital_display'].includes(b.type)) return 'Type must be hoarding, banner, or digital display.';
  if (!['highway', 'arterial', 'local'].includes(b.category)) return 'Category must be highway, arterial, or local.';
  const price = Number(b.price);
  if (!Number.isFinite(price) || price < 0) return 'Price must be zero or more.';
  if (price > 100000000) return 'That price looks too high — please double-check.';
  const traffic = Number(b.traffic);
  if (!Number.isFinite(traffic) || traffic < 0) return 'Traffic must be zero or more.';
  if (b.availability && !['available', 'pending', 'booked'].includes(b.availability)) return 'Invalid availability.';
  if (b.availability === 'booked') {
    const start = Number(b.bookingStart), end = Number(b.bookingEnd);
    if (!Number.isFinite(start) || !Number.isFinite(end)) return 'Please set a booking start and end date.';
    if (end <= start) return 'Booking end date must be after the start date.';
  }
  if (b.facing && !COMPASS_DIRECTIONS.includes(b.facing)) return 'Facing must be one of N, NE, E, SE, S, SW, W, NW.';
  return null;
}

function normalizeDataSources(input) {
  const src = (input && typeof input === 'object') ? input : {};
  const clean = { google: null, manual: null };
  if (src.google && src.google.enabled) {
    clean.google = {
      enabled: true,
      roadName: String(src.google.roadName || '').slice(0, 200) || null,
      roadCategory: ['highway','arterial','local'].includes(src.google.roadCategory) ? src.google.roadCategory : null,
      nearbyBusinesses: (src.google.nearbyBusinesses && typeof src.google.nearbyBusinesses === 'object') ? src.google.nearbyBusinesses : {},
      totalPOIs: Number(src.google.totalPOIs) || 0
    };
  }
  if (src.manual && src.manual.enabled) {
    clean.manual = {
      enabled: true,
      traffic: (Number.isFinite(Number(src.manual.traffic)) && Number(src.manual.traffic) >= 0) ? Math.round(Number(src.manual.traffic)) : null,
      peakHours: Array.isArray(src.manual.peakHours) ? src.manual.peakHours.filter(h => h >= 0 && h <= 23).map(Number) : [],
      audience: (src.manual.audience && typeof src.manual.audience === 'object') ? {
        male: clamp(src.manual.audience.male, 0, 100, null),
        female: clamp(src.manual.audience.female, 0, 100, null),
        age: String(src.manual.audience.age || '').slice(0, 20) || null,
        income: String(src.manual.audience.income || '').slice(0, 20) || null
      } : null,
      source: String(src.manual.source || '').trim().slice(0, 200) || null,
      date: String(src.manual.date || '').slice(0, 20) || null,
      notes: String(src.manual.notes || '').slice(0, 500) || null
    };
  }
  return clean;
}

/* ================================================================
   ROUTER
   ================================================================ */
export async function onRequest(context) {
  const { request, env } = context;
  if (!env.DB) return bad('D1 binding "DB" is missing — add it in Pages → Settings → Functions.', 500);

  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/?/, '').replace(/\/+$/, '');
  const method = request.method;

  let body = {};
  if (method === 'POST') {
    try { body = await request.json(); } catch (e) { body = {}; }
  }

  try {
    /* ---------- public ---------- */
    if (path === 'auth/status' && method === 'GET') {
      const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
      return json({ needsBootstrap: row.n === 0 });
    }

    if (path === 'auth/companies' && method === 'GET') {
      const rows = await env.DB.prepare('SELECT id, name, type FROM companies ORDER BY name ASC').all();
      return json({ companies: rows.results || [] });
    }

    if (path === 'auth/bootstrap' && method === 'POST') {
      const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
      if (row.n > 0) return bad('Bootstrap is disabled — users already exist.', 403);
      return await register(env, request, body, 'superuser', 'bootstrap');
    }

    if (path === 'auth/register' && method === 'POST') {
      const role = body.accountType === 'provider' ? 'provider' : body.accountType === 'agent' ? 'agent' : 'user';
      return await register(env, request, body, role, 'register');
    }

    if (path === 'auth/login' && method === 'POST') {
      return await login(env, request, body);
    }

    if (path === 'auth/mfa/verify' && method === 'POST') {
      return await mfaVerify(env, request, body);
    }

    /* ---------- authenticated ---------- */
    const me = await getAuth(env, request);

    if (path === 'me' && method === 'GET') {
      if (!me) return bad('Not signed in', 401);
      return json({ user: safeUser(me, me.restricted) });
    }

    if (path === 'auth/logout' && method === 'POST') {
      if (me) {
        await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(me.session_hash).run();
        await audit(env, me.id, 'logout', me.email);
      }
      return json({ ok: true }, 200, { 'Set-Cookie': CLEAR_COOKIE });
    }

    if (!me) return bad('Not signed in', 401);

    // Approved billboards for the map — signed-in users only (any role)
    if (path === 'billboards/public' && method === 'GET') {
      const rows = await env.DB.prepare(
        `SELECT ${BB_LIST_COLS}, u.name AS owner_name, u.company_name AS owner_company, u.verified AS owner_verified_flag
         FROM billboards b JOIN users u ON u.id=b.owner_id
         WHERE b.approval_state='approved' ORDER BY b.updated_at DESC LIMIT 1000`
      ).all();
      return json({ billboards: (rows.results || []).map(bbRow) });
    }

    // Listing photo — raw bytes so the browser can cache it and <img src> it directly.
    // Approved listings are visible to any signed-in user; drafts only to owner/admin.
    if (method === 'GET' && /^billboards\/[^/]+\/image$/.test(path)) {
      const bb = await env.DB.prepare(
        'SELECT owner_id, company_id, approval_state, image_data FROM billboards WHERE id=?'
      ).bind(path.split('/')[1]).first();
      if (!bb || !bb.image_data) return bad('No image for this listing', 404);
      if (bb.approval_state !== 'approved' && bb.company_id !== me.company_id && ROLE_RANK[me.role] < ROLE_RANK.admin) {
        return bad('Not your billboard', 403);
      }
      const m = IMAGE_DATA_URL.exec(bb.image_data);
      if (!m) return bad('Stored image is unreadable', 500);
      const bin = atob(m[2]);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new Response(bytes, {
        headers: { 'Content-Type': m[1], 'Cache-Control': 'private, max-age=300' }
      });
    }

    if (path === 'auth/mfa/enroll' && method === 'POST') {
      const secret = b32encode(crypto.getRandomValues(new Uint8Array(20)));
      await env.DB.prepare('UPDATE users SET mfa_pending_secret=? WHERE id=?').bind(secret, me.id).run();
      const label = encodeURIComponent('BillboardIQ:' + me.email);
      const otpauth = 'otpauth://totp/' + label + '?secret=' + secret + '&issuer=BillboardIQ&digits=6&period=30';
      await audit(env, me.id, 'mfa_enroll_start', me.email);
      return json({ secret, otpauth });
    }

    if (path === 'auth/mfa/confirm' && method === 'POST') {
      if (!me.mfa_pending_secret) return bad('No enrollment in progress — request a new QR code.');
      const ok = await verifyTotp(me.mfa_pending_secret, String(body.code || ''));
      if (!ok) { await audit(env, me.id, 'mfa_confirm_fail', me.email); return bad('That code didn\'t match — check your authenticator app and try again.', 401); }
      await env.DB.prepare('UPDATE users SET mfa_secret=mfa_pending_secret, mfa_pending_secret=NULL, mfa_enabled=1 WHERE id=?').bind(me.id).run();
      await env.DB.prepare('UPDATE sessions SET restricted=0 WHERE token_hash=?').bind(me.session_hash).run();
      await audit(env, me.id, 'mfa_enabled', me.email);
      const fresh = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(me.id).first();
      return json({ user: safeUser(fresh, false) });
    }

    /* ---------- restricted sessions stop here ---------- */
    if (me.restricted) return bad('MFA setup required before you can continue.', 403, { mfaSetupRequired: true });

    /* ---------- admin+ ---------- */
    if (path === 'admin/users' && method === 'GET') {
      if (ROLE_RANK[me.role] < ROLE_RANK.admin) return bad('Admin access required', 403);
      const rows = await env.DB.prepare(
        'SELECT id,email,name,role,company_name,company_id,mfa_enabled,verified,last_login,created_at FROM users ORDER BY created_at ASC'
      ).all();
      return json({ users: rows.results.map(u => safeUser(u, false)) });
    }

    /* ---------- superuser only ---------- */
    if (path === 'admin/role' && method === 'POST') {
      if (me.role !== 'superuser') return bad('Superuser access required', 403);
      const { userId, role } = body;
      if (!ROLE_RANK[role]) return bad('Invalid role');
      const target = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(userId).first();
      if (!target) return bad('User not found', 404);
      if (target.role === 'superuser' && role !== 'superuser') {
        const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE role='superuser'").first();
        if (c.n <= 1) return bad('Cannot demote the last superuser.', 400);
      }
      // Role takes effect on the target's very next request — see getAuth(),
      // which derives `restricted` fresh from current role + MFA status
      // rather than trusting anything cached on the sessions row.
      await env.DB.prepare('UPDATE users SET role=? WHERE id=?').bind(role, userId).run();
      await audit(env, me.id, 'role_change', target.email + ' → ' + role);
      return json({ ok: true });
    }

    if (path === 'admin/users/delete' && method === 'POST') {
      if (me.role !== 'superuser') return bad('Superuser access required', 403);
      const { userId } = body;
      if (userId === me.id) return bad('You cannot delete your own account.');
      const target = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(userId).first();
      if (!target) return bad('User not found', 404);
      if (target.role === 'superuser') {
        const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE role='superuser'").first();
        if (c.n <= 1) return bad('Cannot delete the last superuser.');
      }
      await env.DB.prepare('DELETE FROM users WHERE id=?').bind(userId).run();
      await audit(env, me.id, 'user_delete', target.email);
      return json({ ok: true });
    }

    if (path === 'admin/audit' && method === 'GET') {
      if (me.role !== 'superuser') return bad('Superuser access required', 403);
      const rows = await env.DB.prepare(
        'SELECT a.id, a.action, a.detail, a.created_at, u.email FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 100'
      ).all();
      return json({ events: rows.results });
    }

    if (path === 'admin/ai-engine/status' && method === 'GET') {
      if (me.role !== 'superuser') return bad('Superuser access required', 403);
      const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM pending_snapshots').first();
      return json({ pending: row.n });
    }

    if (path === 'admin/ai-engine/run' && method === 'POST') {
      if (me.role !== 'superuser') return bad('Superuser access required', 403);
      if (!env.ANTHROPIC_API_KEY) return bad('ANTHROPIC_API_KEY is not configured for this environment.', 500);
      return runAiEngine(env, me);
    }

    /* ---------- superuser: companies ---------- */
    if (path === 'admin/companies' && method === 'GET') {
      if (me.role !== 'superuser') return bad('Superuser access required', 403);
      const rows = await env.DB.prepare(
        `SELECT c.id, c.name, c.type, c.created_at,
                (SELECT COUNT(*) FROM users u WHERE u.company_id = c.id) AS memberCount,
                (SELECT COUNT(*) FROM billboards b WHERE b.company_id = c.id) AS billboardCount,
                (SELECT COUNT(*) FROM audit_log a JOIN users u2 ON u2.id = a.user_id
                   WHERE u2.company_id = c.id AND a.action = 'login_ok') AS totalLogins
         FROM companies c ORDER BY c.created_at DESC`
      ).all();
      return json({ companies: rows.results || [] });
    }

    if (path === 'admin/companies/create' && method === 'POST') {
      if (me.role !== 'superuser') return bad('Superuser access required', 403);
      const name = String(body.name || '').trim().slice(0, 150);
      if (!name || name.length < 2) return bad('Please enter a company name.');
      const type = body.type === 'agency' ? 'agency' : 'provider';
      const existingCo = await env.DB.prepare('SELECT id FROM companies WHERE name=?').bind(name).first();
      if (existingCo) return bad('A company with that name already exists.', 409);
      const id = 'CO-' + shortId();
      await env.DB.prepare('INSERT INTO companies (id, name, type, created_at) VALUES (?,?,?,?)')
        .bind(id, name, type, Date.now()).run();
      await audit(env, me.id, 'company_create', id + ' — ' + name);
      return json({ company: { id, name, type } });
    }

    // Member list (with per-user login count, derived from audit_log —
    // no separate counter column) + this company's slice of the audit log.
    if (method === 'GET' && /^admin\/companies\/[^/]+$/.test(path)) {
      if (me.role !== 'superuser') return bad('Superuser access required', 403);
      const id = path.split('/')[2];
      const co = await env.DB.prepare('SELECT * FROM companies WHERE id=?').bind(id).first();
      if (!co) return bad('Company not found', 404);
      const members = await env.DB.prepare(
        `SELECT u.id, u.email, u.name, u.role, u.last_login,
                (SELECT COUNT(*) FROM audit_log a WHERE a.user_id = u.id AND a.action = 'login_ok') AS loginCount
         FROM users u WHERE u.company_id = ? ORDER BY u.created_at ASC`
      ).bind(id).all();
      const auditRows = await env.DB.prepare(
        `SELECT a.id, a.action, a.detail, a.created_at, u.email
         FROM audit_log a JOIN users u ON u.id = a.user_id
         WHERE u.company_id = ? ORDER BY a.id DESC LIMIT 100`
      ).bind(id).all();
      return json({ company: co, members: members.results || [], audit: auditRows.results || [], stats: await computeCompanyStats(env, id) });
    }

    // Platform-wide aggregates for the admin console's overview charts
    // (role/company/billboard/traffic breakdowns, revenue, region spend).
    // Polled every ~20s by the dashboard's Console tab — cheap GROUP BY
    // queries, no joins across the full billboards table beyond what's
    // already indexed.
    if (path === 'admin/stats/overview' && method === 'GET') {
      if (me.role !== 'superuser') return bad('Superuser access required', 403);

      const roleRows = await env.DB.prepare('SELECT role, COUNT(*) AS n FROM users GROUP BY role').all();
      const coRows = await env.DB.prepare('SELECT type, COUNT(*) AS n FROM companies GROUP BY type').all();
      const coTotals = await env.DB.prepare(
        `SELECT (SELECT COUNT(*) FROM users WHERE company_id IS NOT NULL) AS members,
                (SELECT COUNT(*) FROM billboards WHERE company_id IS NOT NULL) AS billboards`
      ).first();
      const stateRows = await env.DB.prepare('SELECT approval_state AS s, COUNT(*) AS n FROM billboards GROUP BY approval_state').all();
      const availRows = await env.DB.prepare(
        `SELECT availability AS s, COUNT(*) AS n FROM billboards WHERE approval_state='approved' GROUP BY availability`
      ).all();
      const revRow = await env.DB.prepare(
        `SELECT SUM(CASE WHEN availability='booked' THEN price ELSE 0 END) AS booked, SUM(price) AS potential
         FROM billboards WHERE approval_state='approved'`
      ).first();
      // Only the most recent snapshot per billboard counts toward "current"
      // congestion — a correlated MAX() subquery instead of a window
      // function keeps this portable across whatever SQLite build D1 runs.
      const densityRows = await env.DB.prepare(
        `SELECT density_label AS s, COUNT(*) AS n
         FROM traffic_snapshots ts
         WHERE ts.captured_at = (SELECT MAX(captured_at) FROM traffic_snapshots WHERE billboard_id = ts.billboard_id)
           AND density_label IS NOT NULL
         GROUP BY density_label`
      ).all();
      const regionRows = await env.DB.prepare(
        `SELECT area, COALESCE(SUM(price),0) AS spend, COUNT(DISTINCT customer_id) AS customers
         FROM billboards WHERE availability='booked' AND approval_state='approved'
         GROUP BY area ORDER BY spend DESC LIMIT 8`
      ).all();

      const toMap = rows => Object.fromEntries(rows.map(r => [r.s ?? r.role, r.n]));

      return json({
        roles: toMap(roleRows.results || []),
        companies: {
          provider: (coRows.results || []).find(r => r.type === 'provider')?.n || 0,
          agency: (coRows.results || []).find(r => r.type === 'agency')?.n || 0,
          totalMembers: coTotals.members || 0,
          totalBillboards: coTotals.billboards || 0
        },
        billboardStatus: toMap(stateRows.results || []),
        billboardAvailability: toMap(availRows.results || []),
        trafficDensity: toMap(densityRows.results || []),
        revenue: { booked: revRow.booked || 0, potential: revRow.potential || 0 },
        regionSpend: (regionRows.results || []).map(r => ({ area: r.area, spend: r.spend, customers: r.customers }))
      });
    }

    /* ================================================================
       BILLBOARDS MODULE
       ================================================================ */

    // Owner: list MY billboards
    // Owner's own catalog of billboard formats — the Add Billboard "Size" dropdown
    // only ever shows the signed-in provider's own entries here.
    if (path === 'formats/list' && method === 'GET') {
      if (!PUBLISH_ROLES.includes(me.role)) return bad('A provider account is required to manage formats.', 403);
      const rows = await env.DB.prepare(
        'SELECT * FROM billboard_formats WHERE owner_id=? ORDER BY created_at DESC'
      ).bind(me.id).all();
      return json({ formats: (rows.results || []).map(formatRow) });
    }

    if (path === 'formats/create' && method === 'POST') {
      if (!PUBLISH_ROLES.includes(me.role)) return bad('A provider account is required to manage formats.', 403);
      const err = validateFormat(body);
      if (err) return bad(err);
      const id = 'FMT-' + shortId();
      await env.DB.prepare(
        `INSERT INTO billboard_formats (id, owner_id, type, size, building_name, resolution, ad_duration, created_at)
         VALUES (?,?,?,?,?,?,?,?)`
      ).bind(
        id, me.id, body.type,
        body.type === 'digital_display' ? null : String(body.size || '').trim().slice(0, 60),
        body.type === 'digital_display' ? String(body.buildingName || '').trim().slice(0, 200) : null,
        body.type === 'digital_display' ? String(body.resolution || '').trim().slice(0, 50) : null,
        body.type === 'digital_display' ? (String(body.adDuration || '').trim().slice(0, 100) || null) : null,
        Date.now()
      ).run();
      const fresh = await env.DB.prepare('SELECT * FROM billboard_formats WHERE id=?').bind(id).first();
      return json({ format: formatRow(fresh) });
    }

    if (path === 'formats/delete' && method === 'POST') {
      if (!PUBLISH_ROLES.includes(me.role)) return bad('A provider account is required to manage formats.', 403);
      await env.DB.prepare('DELETE FROM billboard_formats WHERE id=? AND owner_id=?').bind(body.id, me.id).run();
      return json({ ok: true });
    }

    // Company-wide: every provider/agent in the signed-in user's company
    // shares the same inventory, not just what they personally created.
    if (path === 'billboards/mine' && method === 'GET') {
      if (!MANAGE_INVENTORY_ROLES.includes(me.role)) return bad('A provider or agent account is required to manage listings.', 403);
      if (!me.company_id) return bad('Your account isn\'t linked to a company yet — contact your admin.', 403);
      const rows = await env.DB.prepare(
        `SELECT ${BB_LIST_COLS} FROM billboards b WHERE b.company_id=? ORDER BY b.updated_at DESC`
      ).bind(me.company_id).all();
      return json({ billboards: (rows.results || []).map(bbRow) });
    }

    // Provider (not agent): create a billboard (starts as draft), owned by their company
    if (path === 'billboards/create' && method === 'POST') {
      if (!PUBLISH_ROLES.includes(me.role)) return bad('A provider account is required to publish listings.', 403);
      if (!me.company_id) return bad('Your account isn\'t linked to a company yet — contact your admin.', 403);
      const err = validateBillboard(body);
      if (err) return bad(err);
      const img = normalizeImage(body.imageData === undefined ? null : body.imageData);
      if (img.error) return bad(img.error);
      const id = 'BB-' + shortId();
      const now = Date.now();
      const cleanSources = normalizeDataSources(body.dataSources);
      await env.DB.prepare(
        `INSERT INTO billboards
         (id, owner_id, company_id, title, area, description, lat, lng, size, type, category, illuminated,
          price, traffic, peak_hours, audience_male, audience_female, audience_age, audience_income,
          availability, approval_state, data_sources, image_data, format_id, building_name, resolution, ad_duration,
          booking_start, booking_end, facing, created_at, updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ).bind(
        id, me.id, me.company_id, body.title.trim(), body.area.trim(), (body.description || '').trim(),
        Number(body.lat), Number(body.lng), body.size.trim(), body.type, body.category,
        body.illuminated ? 1 : 0,
        Math.max(0, Math.round(Number(body.price))),
        Math.max(0, Math.round(Number(body.traffic))),
        JSON.stringify((body.peak_hours || []).filter(h => h >= 0 && h <= 23).map(Number)),
        clamp(body.audience_male, 0, 100, 50),
        clamp(body.audience_female, 0, 100, 50),
        (body.audience_age || '25-44').slice(0, 20),
        (body.audience_income || 'Mid').slice(0, 20),
        body.availability || 'available',
        'draft',
        JSON.stringify(cleanSources),
        img.value,
        body.formatId || null,
        body.type === 'digital_display' ? (String(body.buildingName || '').trim().slice(0, 200) || null) : null,
        body.type === 'digital_display' ? (String(body.resolution || '').trim().slice(0, 50) || null) : null,
        body.type === 'digital_display' ? (String(body.adDuration || '').trim().slice(0, 100) || null) : null,
        body.availability === 'booked' ? Math.round(Number(body.bookingStart)) : null,
        body.availability === 'booked' ? Math.round(Number(body.bookingEnd)) : null,
        body.facing || null,
        now, now
      ).run();
      await audit(env, me.id, 'billboard_create', id + ' — ' + body.title);
      const fresh = await env.DB.prepare('SELECT * FROM billboards WHERE id=?').bind(id).first();
      return json({ billboard: bbRow(fresh) });
    }

    // Collected traffic-analytics history for one billboard (owner or admin+ only) —
    // populated by the standalone traffic-engine Worker (worker/), never written here.
    if (method === 'GET' && /^billboards\/[^/]+\/traffic$/.test(path)) {
      const id = path.split('/')[1];
      const bb = await env.DB.prepare('SELECT owner_id, company_id, approval_state, ai_insights, ai_insights_updated_at FROM billboards WHERE id=?').bind(id).first();
      if (!bb) return bad('Billboard not found', 404);
      if (bb.approval_state !== 'approved' && bb.company_id !== me.company_id && ROLE_RANK[me.role] < ROLE_RANK.admin) {
        return bad('Not your billboard', 403);
      }
      const rows = await env.DB.prepare(
        'SELECT captured_at, congestion_score, density_label, note FROM traffic_snapshots WHERE billboard_id=? ORDER BY captured_at DESC LIMIT 500'
      ).bind(id).all();
      const snapshots = (rows.results || []).map(r => ({
        capturedAt: r.captured_at,
        congestionScore: r.congestion_score,
        densityLabel: r.density_label,
        note: r.note || null
      }));
      // Lets the client scale this billboard's charts against the busiest
      // reading across every listing (not just its own range), so a quiet
      // location visibly reads as quieter next to a busy one instead of both
      // charts independently stretching to fill their own axis. Scoped to
      // approved listings plus this billboard itself (covers the pending/
      // owner-preview case) so the range always includes what's on screen.
      const range = await env.DB.prepare(
        `SELECT MIN(ts.congestion_score) AS lo, MAX(ts.congestion_score) AS hi
         FROM traffic_snapshots ts JOIN billboards b ON b.id = ts.billboard_id
         WHERE b.approval_state = 'approved' OR b.id = ?`
      ).bind(id).first();
      return json({
        snapshots, aiInsights: bb.ai_insights || null, aiInsightsUpdatedAt: bb.ai_insights_updated_at || null,
        globalMin: range && range.lo != null ? range.lo : null,
        globalMax: range && range.hi != null ? range.hi : null
      });
    }

    // Get a single billboard (company member or admin+ only)
    if (path.startsWith('billboards/') && method === 'GET' && !path.startsWith('billboards/mine') && !path.startsWith('billboards/pending') && !path.startsWith('billboards/all') && !path.endsWith('/traffic') && !path.endsWith('/image')) {
      const id = path.split('/')[1];
      const bb = await env.DB.prepare('SELECT * FROM billboards WHERE id=?').bind(id).first();
      if (!bb) return bad('Billboard not found', 404);
      if (bb.company_id !== me.company_id && ROLE_RANK[me.role] < ROLE_RANK.admin) return bad('Not your billboard', 403);
      return json({ billboard: bbRow(bb) });
    }

    // Update a billboard (any company member, or admin+; editing an approved
    // one flips it back to pending unless an admin is the one editing)
    if (path === 'billboards/update' && method === 'POST') {
      if (!MANAGE_INVENTORY_ROLES.includes(me.role)) return bad('A provider or agent account is required to manage listings.', 403);
      const bb = await env.DB.prepare('SELECT owner_id, company_id, approval_state FROM billboards WHERE id=?').bind(body.id).first();
      if (!bb) return bad('Billboard not found', 404);
      const isAdmin = ROLE_RANK[me.role] >= ROLE_RANK.admin;
      if (bb.company_id !== me.company_id && !isAdmin) return bad('Not your company\'s billboard', 403);
      const err = validateBillboard(body);
      if (err) return bad(err);
      // Only touch image_data when the client actually sent the key: absent = keep
      // the existing photo, null = clear it, string = replace it.
      const touchesImage = Object.prototype.hasOwnProperty.call(body, 'imageData');
      let img = { value: null };
      if (touchesImage) {
        img = normalizeImage(body.imageData);
        if (img.error) return bad(img.error);
      }
      // If the owner (not an admin) edits an already-approved listing, re-queue for review
      let nextState = bb.approval_state;
      if (!isAdmin && bb.approval_state === 'approved') nextState = 'pending';
      const cleanSources = normalizeDataSources(body.dataSources);
      await env.DB.prepare(
        `UPDATE billboards SET
           title=?, area=?, description=?, lat=?, lng=?, size=?, type=?, category=?, illuminated=?,
           price=?, traffic=?, peak_hours=?, audience_male=?, audience_female=?, audience_age=?, audience_income=?,
           availability=?, approval_state=?, data_sources=?, format_id=?, building_name=?, resolution=?, ad_duration=?,
           booking_start=?, booking_end=?, facing=?,${touchesImage ? ' image_data=?,' : ''} updated_at=?
         WHERE id=?`
      ).bind(...[
        body.title.trim(), body.area.trim(), (body.description || '').trim(),
        Number(body.lat), Number(body.lng), body.size.trim(), body.type, body.category,
        body.illuminated ? 1 : 0,
        Math.max(0, Math.round(Number(body.price))),
        Math.max(0, Math.round(Number(body.traffic))),
        JSON.stringify((body.peak_hours || []).filter(h => h >= 0 && h <= 23).map(Number)),
        clamp(body.audience_male, 0, 100, 50),
        clamp(body.audience_female, 0, 100, 50),
        (body.audience_age || '25-44').slice(0, 20),
        (body.audience_income || 'Mid').slice(0, 20),
        body.availability || 'available',
        nextState,
        JSON.stringify(cleanSources),
        body.formatId || null,
        body.type === 'digital_display' ? (String(body.buildingName || '').trim().slice(0, 200) || null) : null,
        body.type === 'digital_display' ? (String(body.resolution || '').trim().slice(0, 50) || null) : null,
        body.type === 'digital_display' ? (String(body.adDuration || '').trim().slice(0, 100) || null) : null,
        body.availability === 'booked' ? Math.round(Number(body.bookingStart)) : null,
        body.availability === 'booked' ? Math.round(Number(body.bookingEnd)) : null,
        body.facing || null,
        ...(touchesImage ? [img.value] : []),
        Date.now(),
        body.id
      ]).run();
      await audit(env, me.id, 'billboard_update', body.id + (nextState !== bb.approval_state ? ' → ' + nextState : ''));
      const fresh = await env.DB.prepare('SELECT * FROM billboards WHERE id=?').bind(body.id).first();
      return json({ billboard: bbRow(fresh) });
    }

    // Company member submits a draft for review
    if (path === 'billboards/submit' && method === 'POST') {
      if (!MANAGE_INVENTORY_ROLES.includes(me.role)) return bad('A provider or agent account is required to manage listings.', 403);
      const bb = await env.DB.prepare('SELECT owner_id, company_id, approval_state FROM billboards WHERE id=?').bind(body.id).first();
      if (!bb) return bad('Billboard not found', 404);
      if (bb.company_id !== me.company_id && ROLE_RANK[me.role] < ROLE_RANK.admin) return bad('Not your billboard', 403);
      if (bb.approval_state === 'approved') return bad('Already approved.');
      if (bb.approval_state === 'pending') return bad('Already awaiting review.');
      await env.DB.prepare('UPDATE billboards SET approval_state=?, rejection_note=NULL, updated_at=? WHERE id=?')
        .bind('pending', Date.now(), body.id).run();
      await audit(env, me.id, 'billboard_submit', body.id);
      return json({ ok: true });
    }

    // Delete
    if (path === 'billboards/delete' && method === 'POST') {
      if (!MANAGE_INVENTORY_ROLES.includes(me.role)) return bad('A provider or agent account is required to manage listings.', 403);
      const bb = await env.DB.prepare('SELECT owner_id, company_id, approval_state FROM billboards WHERE id=?').bind(body.id).first();
      if (!bb) return bad('Billboard not found', 404);
      if (bb.company_id !== me.company_id && ROLE_RANK[me.role] < ROLE_RANK.admin) return bad('Not your billboard', 403);
      await env.DB.prepare('DELETE FROM billboards WHERE id=?').bind(body.id).run();
      await audit(env, me.id, 'billboard_delete', body.id);
      return json({ ok: true });
    }

    // Tag/untag a customer to a billboard (agents managing bookings for
    // their clients). Both must belong to the signed-in user's company.
    if (path === 'billboards/assign-customer' && method === 'POST') {
      if (!MANAGE_INVENTORY_ROLES.includes(me.role)) return bad('A provider or agent account is required.', 403);
      const bb = await env.DB.prepare('SELECT company_id FROM billboards WHERE id=?').bind(body.id).first();
      if (!bb) return bad('Billboard not found', 404);
      if (bb.company_id !== me.company_id && ROLE_RANK[me.role] < ROLE_RANK.admin) return bad('Not your company\'s billboard', 403);
      let customerId = null;
      if (body.customerId) {
        const cust = await env.DB.prepare('SELECT id, company_id FROM customers WHERE id=?').bind(body.customerId).first();
        if (!cust || cust.company_id !== bb.company_id) return bad('Invalid customer.', 400);
        customerId = cust.id;
      }
      await env.DB.prepare('UPDATE billboards SET customer_id=?, updated_at=? WHERE id=?').bind(customerId, Date.now(), body.id).run();
      await audit(env, me.id, 'billboard_assign_customer', body.id + (customerId ? ' → ' + customerId : ' (cleared)'));
      return json({ ok: true });
    }

    /* ================================================================
       CUSTOMERS MODULE (agent tenants, e.g. "Coca-Cola")
       ================================================================ */
    if (path === 'customers/list' && method === 'GET') {
      if (!MANAGE_INVENTORY_ROLES.includes(me.role)) return bad('A provider or agent account is required.', 403);
      if (!me.company_id) return bad('Your account isn\'t linked to a company yet.', 403);
      const rows = await env.DB.prepare('SELECT * FROM customers WHERE company_id=? ORDER BY created_at DESC').bind(me.company_id).all();
      return json({ customers: (rows.results || []).map(customerRow) });
    }

    if (path === 'customers/create' && method === 'POST') {
      if (!MANAGE_INVENTORY_ROLES.includes(me.role)) return bad('A provider or agent account is required.', 403);
      if (!me.company_id) return bad('Your account isn\'t linked to a company yet.', 403);
      const err = validateCustomer(body);
      if (err) return bad(err);
      const id = 'CUST-' + shortId();
      await env.DB.prepare(
        'INSERT INTO customers (id, company_id, name, budget, notes, created_by, created_at) VALUES (?,?,?,?,?,?,?)'
      ).bind(
        id, me.company_id, String(body.name).trim(),
        body.budget != null && body.budget !== '' ? Math.round(Number(body.budget)) : null,
        String(body.notes || '').trim().slice(0, 500) || null,
        me.id, Date.now()
      ).run();
      await audit(env, me.id, 'customer_create', id + ' — ' + body.name);
      const fresh = await env.DB.prepare('SELECT * FROM customers WHERE id=?').bind(id).first();
      return json({ customer: customerRow(fresh) });
    }

    if (path === 'customers/update' && method === 'POST') {
      if (!MANAGE_INVENTORY_ROLES.includes(me.role)) return bad('A provider or agent account is required.', 403);
      const cust = await env.DB.prepare('SELECT company_id FROM customers WHERE id=?').bind(body.id).first();
      if (!cust) return bad('Customer not found', 404);
      if (cust.company_id !== me.company_id && ROLE_RANK[me.role] < ROLE_RANK.admin) return bad('Not your company\'s customer', 403);
      const err = validateCustomer(body);
      if (err) return bad(err);
      await env.DB.prepare('UPDATE customers SET name=?, budget=?, notes=? WHERE id=?').bind(
        String(body.name).trim(),
        body.budget != null && body.budget !== '' ? Math.round(Number(body.budget)) : null,
        String(body.notes || '').trim().slice(0, 500) || null,
        body.id
      ).run();
      const fresh = await env.DB.prepare('SELECT * FROM customers WHERE id=?').bind(body.id).first();
      return json({ customer: customerRow(fresh) });
    }

    if (path === 'customers/delete' && method === 'POST') {
      if (!MANAGE_INVENTORY_ROLES.includes(me.role)) return bad('A provider or agent account is required.', 403);
      const cust = await env.DB.prepare('SELECT company_id FROM customers WHERE id=?').bind(body.id).first();
      if (!cust) return bad('Customer not found', 404);
      if (cust.company_id !== me.company_id && ROLE_RANK[me.role] < ROLE_RANK.admin) return bad('Not your company\'s customer', 403);
      // Explicit clear rather than relying on an ON DELETE SET NULL FK
      // action — billboards.customer_id was added without one, so this is
      // the reliable way to avoid a dangling/rejected delete either way.
      await env.DB.prepare('UPDATE billboards SET customer_id=NULL WHERE customer_id=?').bind(body.id).run();
      await env.DB.prepare('DELETE FROM customers WHERE id=?').bind(body.id).run();
      await audit(env, me.id, 'customer_delete', body.id);
      return json({ ok: true });
    }

    // Simple heuristic — top available company billboards sharing a
    // category with what this customer already has booked. Not ML, just a
    // first pass so an agent has somewhere to start.
    if (method === 'GET' && /^customers\/[^/]+\/suggestions$/.test(path)) {
      if (!MANAGE_INVENTORY_ROLES.includes(me.role)) return bad('A provider or agent account is required.', 403);
      const custId = path.split('/')[1];
      const cust = await env.DB.prepare('SELECT company_id FROM customers WHERE id=?').bind(custId).first();
      if (!cust || cust.company_id !== me.company_id) return bad('Customer not found', 404);
      const catRows = await env.DB.prepare(
        'SELECT DISTINCT category FROM billboards WHERE customer_id=? AND company_id=?'
      ).bind(custId, me.company_id).all();
      const categories = (catRows.results || []).map(r => r.category);
      if (!categories.length) return json({ suggestions: [] });
      const placeholders = categories.map(() => '?').join(',');
      const rows = await env.DB.prepare(
        `SELECT ${BB_LIST_COLS} FROM billboards b WHERE b.company_id=? AND b.availability='available' AND b.category IN (${placeholders}) LIMIT 10`
      ).bind(me.company_id, ...categories).all();
      return json({ suggestions: (rows.results || []).map(bbRow) });
    }

    /* ================================================================
       FAVORITES (any signed-in user)
       ================================================================ */
    if (path === 'favorites/mine' && method === 'GET') {
      const rows = await env.DB.prepare('SELECT billboard_id FROM favorites WHERE user_id=?').bind(me.id).all();
      return json({ billboardIds: (rows.results || []).map(r => r.billboard_id) });
    }

    if (path === 'favorites/toggle' && method === 'POST') {
      const billboardId = String(body.billboardId || '');
      if (!billboardId) return bad('Missing billboardId.');
      const bb = await env.DB.prepare('SELECT id FROM billboards WHERE id=?').bind(billboardId).first();
      if (!bb) return bad('Billboard not found', 404);
      const existingFav = await env.DB.prepare('SELECT 1 FROM favorites WHERE user_id=? AND billboard_id=?').bind(me.id, billboardId).first();
      if (existingFav) {
        await env.DB.prepare('DELETE FROM favorites WHERE user_id=? AND billboard_id=?').bind(me.id, billboardId).run();
        return json({ favorited: false });
      }
      await env.DB.prepare('INSERT INTO favorites (user_id, billboard_id, created_at) VALUES (?,?,?)').bind(me.id, billboardId, Date.now()).run();
      return json({ favorited: true });
    }

    /* ================================================================
       COMPANY DASHBOARDS
       ================================================================ */
    // Inventory/revenue/favorites snapshot for the signed-in user's whole
    // company — the numbers behind the stat tiles + pie chart on dashboard.html.
    if (path === 'company/dashboard' && method === 'GET') {
      if (!me.company_id) return bad('Your account isn\'t linked to a company yet.', 403);
      return json(await computeCompanyStats(env, me.company_id));
    }

    // Agent view: per-customer active-billboard count, spend, and budget
    // headroom (informational only — nothing here blocks a booking).
    if (path === 'company/customers-overview' && method === 'GET') {
      if (!MANAGE_INVENTORY_ROLES.includes(me.role)) return bad('A provider or agent account is required.', 403);
      if (!me.company_id) return bad('Your account isn\'t linked to a company yet.', 403);
      const rows = await env.DB.prepare(
        `SELECT c.id, c.name, c.budget, c.notes, c.created_at,
                COUNT(b.id) AS activeBillboardCount, COALESCE(SUM(b.price), 0) AS spend
         FROM customers c
         LEFT JOIN billboards b ON b.customer_id = c.id AND b.availability = 'booked'
         WHERE c.company_id = ?
         GROUP BY c.id ORDER BY c.created_at DESC`
      ).bind(me.company_id).all();
      const list = (rows.results || []).map(r => ({
        id: r.id, name: r.name, budget: r.budget != null ? r.budget : null, notes: r.notes || null, createdAt: r.created_at,
        activeBillboardCount: r.activeBillboardCount, spend: r.spend,
        remaining: r.budget != null ? r.budget - r.spend : null
      }));
      return json({ customers: list });
    }

    /* ---------- admin: billboard review ---------- */
    if (path === 'billboards/pending' && method === 'GET') {
      if (ROLE_RANK[me.role] < ROLE_RANK.admin) return bad('Admin access required', 403);
      const rows = await env.DB.prepare(
        `SELECT ${BB_LIST_COLS}, u.email AS owner_email, u.name AS owner_name, u.company_name AS owner_company
         FROM billboards b JOIN users u ON u.id=b.owner_id
         WHERE b.approval_state='pending' ORDER BY b.updated_at ASC`
      ).all();
      return json({ billboards: (rows.results || []).map(bbRow) });
    }

    if (path === 'billboards/all' && method === 'GET') {
      if (ROLE_RANK[me.role] < ROLE_RANK.admin) return bad('Admin access required', 403);
      const state = url.searchParams.get('state');
      let sql = `SELECT ${BB_LIST_COLS}, u.email AS owner_email, u.name AS owner_name, u.company_name AS owner_company
                 FROM billboards b JOIN users u ON u.id=b.owner_id`;
      const args = [];
      if (state && ['draft', 'pending', 'approved', 'rejected'].includes(state)) {
        sql += ' WHERE b.approval_state=?';
        args.push(state);
      }
      sql += ' ORDER BY b.updated_at DESC LIMIT 500';
      const rows = await env.DB.prepare(sql).bind(...args).all();
      return json({ billboards: (rows.results || []).map(bbRow) });
    }

    if (path === 'billboards/approve' && method === 'POST') {
      if (ROLE_RANK[me.role] < ROLE_RANK.admin) return bad('Admin access required', 403);
      const bb = await env.DB.prepare('SELECT owner_id, approval_state FROM billboards WHERE id=?').bind(body.id).first();
      if (!bb) return bad('Billboard not found', 404);
      await env.DB.prepare(
        'UPDATE billboards SET approval_state=?, rejection_note=NULL, reviewed_by=?, reviewed_at=?, updated_at=? WHERE id=?'
      ).bind('approved', me.id, Date.now(), Date.now(), body.id).run();
      await audit(env, me.id, 'billboard_approve', body.id);
      return json({ ok: true });
    }

    if (path === 'billboards/reject' && method === 'POST') {
      if (ROLE_RANK[me.role] < ROLE_RANK.admin) return bad('Admin access required', 403);
      const note = String(body.note || '').trim().slice(0, 500);
      if (!note) return bad('Please include a rejection reason so the owner can fix the listing.');
      const bb = await env.DB.prepare('SELECT owner_id, approval_state FROM billboards WHERE id=?').bind(body.id).first();
      if (!bb) return bad('Billboard not found', 404);
      await env.DB.prepare(
        'UPDATE billboards SET approval_state=?, rejection_note=?, reviewed_by=?, reviewed_at=?, updated_at=? WHERE id=?'
      ).bind('rejected', note, me.id, Date.now(), Date.now(), body.id).run();
      await audit(env, me.id, 'billboard_reject', body.id + ' — ' + note.slice(0, 80));
      return json({ ok: true });
    }

    // Admin: verify an owner (badge on public map)
    if (path === 'admin/verify-owner' && method === 'POST') {
      if (ROLE_RANK[me.role] < ROLE_RANK.admin) return bad('Admin access required', 403);
      const verified = body.verified ? 1 : 0;
      const target = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(body.userId).first();
      if (!target) return bad('User not found', 404);
      await env.DB.prepare('UPDATE users SET verified=? WHERE id=?').bind(verified, body.userId).run();
      await audit(env, me.id, verified ? 'owner_verify' : 'owner_unverify', target.email);
      return json({ ok: true });
    }

    return bad('Not found', 404);
  } catch (err) {
    return bad('Server error: ' + (err && err.message ? err.message : 'unknown'), 500);
  }
}

/* ================================================================
   FLOWS
   ================================================================ */
// Resolves the company for a provider/agent signup: either joins an
// existing one (body.companyId, picked from GET auth/companies) or
// creates a new one (body.newCompanyName [+ newCompanyType]). Returns
// { companyId, companyName } or { error }. Called only after the
// duplicate-email check in register() so a failed signup doesn't leave an
// orphan company behind (D1/Workers has no cheap cross-statement
// transaction here, same non-atomic style as the rest of this file).
// Inventory/revenue/approval snapshot for one company — shared by the
// company's own dashboard.html (company/dashboard, scoped to me.company_id)
// and the superuser drill-down in the Console tab (admin/companies/<id>,
// scoped to an arbitrary company id).
async function computeCompanyStats(env, companyId) {
  const totals = await env.DB.prepare(
    `SELECT
       COUNT(*) AS total,
       SUM(CASE WHEN availability='booked' THEN 1 ELSE 0 END) AS booked,
       SUM(CASE WHEN availability='available' THEN 1 ELSE 0 END) AS available,
       SUM(CASE WHEN availability='pending' THEN 1 ELSE 0 END) AS pendingAvailability,
       SUM(CASE WHEN availability='booked' THEN price ELSE 0 END) AS revenue,
       SUM(CASE WHEN availability='booked' AND booking_end IS NOT NULL AND booking_end <= ? THEN 1 ELSE 0 END) AS expiringSoon
     FROM billboards WHERE company_id=?`
  ).bind(Date.now() + EXPIRING_SOON_MS, companyId).first();
  const favRow = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM favorites f JOIN billboards b ON b.id=f.billboard_id WHERE b.company_id=?`
  ).bind(companyId).first();
  const approvalRow = await env.DB.prepare(
    `SELECT
       SUM(CASE WHEN approval_state='approved' THEN 1 ELSE 0 END) AS approved,
       SUM(CASE WHEN approval_state='pending' THEN 1 ELSE 0 END) AS pending,
       SUM(CASE WHEN approval_state='draft' THEN 1 ELSE 0 END) AS draft,
       SUM(CASE WHEN approval_state='rejected' THEN 1 ELSE 0 END) AS rejected
     FROM billboards WHERE company_id=?`
  ).bind(companyId).first();
  return {
    total: totals.total || 0,
    booked: totals.booked || 0,
    available: totals.available || 0,
    pendingAvailability: totals.pendingAvailability || 0,
    revenue: totals.revenue || 0,
    expiringSoon: totals.expiringSoon || 0,
    totalFavorites: favRow.n || 0,
    approvalBreakdown: {
      approved: approvalRow.approved || 0,
      pending: approvalRow.pending || 0,
      draft: approvalRow.draft || 0,
      rejected: approvalRow.rejected || 0
    }
  };
}

async function resolveCompany(env, body) {
  if (body.companyId) {
    const co = await env.DB.prepare('SELECT id, name FROM companies WHERE id=?').bind(body.companyId).first();
    if (!co) return { error: 'Selected company not found — refresh and try again.' };
    return { companyId: co.id, companyName: co.name };
  }
  const newName = String(body.newCompanyName || '').trim().slice(0, 150);
  if (!newName || newName.length < 2) return { error: 'Please select your company, or enter a new company name.' };
  const type = body.newCompanyType === 'agency' ? 'agency' : 'provider';
  const existingCo = await env.DB.prepare('SELECT id FROM companies WHERE name=?').bind(newName).first();
  if (existingCo) return { error: 'That company name is already registered — select it from the list instead.' };
  const id = 'CO-' + shortId();
  await env.DB.prepare('INSERT INTO companies (id, name, type, created_at) VALUES (?,?,?,?)')
    .bind(id, newName, type, Date.now()).run();
  return { companyId: id, companyName: newName };
}

async function register(env, request, body, role, auditAction) {
  const email = String(body.email || '').trim().toLowerCase();
  const name = String(body.name || '').trim().slice(0, 100);
  const password = String(body.password || '');
  if (!validEmail(email)) return bad('Please enter a valid email address.');
  if (!name) return bad('Please enter your name.');
  if (password.length < MIN_PASSWORD_LEN) return bad('Password must be at least ' + MIN_PASSWORD_LEN + ' characters.');

  const existing = await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first();
  if (existing) return bad('That email is already registered.', 409);

  let companyId = null, companyName = null;
  if (COMPANY_ROLES.includes(role)) {
    const co = await resolveCompany(env, body);
    if (co.error) return bad(co.error);
    companyId = co.companyId;
    companyName = co.companyName;
  }

  const { hash, salt } = await hashPassword(password);
  const id = crypto.randomUUID();
  await env.DB.prepare(
    'INSERT INTO users (id,email,name,role,company_name,company_id,password_hash,password_salt,created_at) VALUES (?,?,?,?,?,?,?,?,?)'
  ).bind(id, email, name, role, companyName, companyId, hash, salt, Date.now()).run();
  await audit(env, id, auditAction, email + ' (' + role + ')' + (companyName ? ' @ ' + companyName : ''));
  await notifyOwnerOfNewAccount(env, { email, name, role, companyName });

  // Sign them straight in. MFA-mandatory roles get a restricted session.
  const restricted = MFA_REQUIRED_ROLES.includes(role);
  const { token, exp } = await createSession(env, request, id, restricted);
  const fresh = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(id).first();
  return json(
    { user: safeUser(fresh, restricted), mfaSetupRequired: restricted },
    200, { 'Set-Cookie': sessionCookie(token, exp) }
  );
}

async function login(env, request, body) {
  // opportunistic cleanup
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(Date.now()).run();
  await env.DB.prepare('DELETE FROM mfa_pending WHERE expires_at < ?').bind(Date.now()).run();

  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  const user = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email).first();

  if (user && user.locked_until && user.locked_until > Date.now()) {
    return bad('Too many failed attempts — try again in a few minutes.', 429);
  }

  const ok = user ? await verifyPassword(password, user.password_salt, user.password_hash) : false;
  if (!ok) {
    if (user) {
      const fails = (user.failed_attempts || 0) + 1;
      const lock = fails >= LOCKOUT_AFTER ? Date.now() + LOCKOUT_MINUTES * 60000 : null;
      await env.DB.prepare('UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?').bind(fails, lock, user.id).run();
      await audit(env, user.id, lock ? 'login_locked' : 'login_fail', email);
    }
    return bad('Invalid email or password.', 401);
  }

  await env.DB.prepare('UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?').bind(user.id).run();

  if (user.mfa_enabled) {
    const pending = randHex(32);
    await env.DB.prepare('INSERT INTO mfa_pending (token_hash, user_id, expires_at, attempts) VALUES (?,?,?,0)')
      .bind(await sha256hex(pending), user.id, Date.now() + MFA_PENDING_MINUTES * 60000).run();
    return json({ mfaRequired: true, pending });
  }

  const restricted = MFA_REQUIRED_ROLES.includes(user.role);
  const { token, exp } = await createSession(env, request, user.id, restricted);
  await audit(env, user.id, 'login_ok', email + (restricted ? ' (mfa setup pending)' : ''));
  return json(
    { user: safeUser(user, restricted), mfaSetupRequired: restricted },
    200, { 'Set-Cookie': sessionCookie(token, exp) }
  );
}

async function mfaVerify(env, request, body) {
  const pending = String(body.pending || '');
  const code = String(body.code || '');
  if (!pending) return bad('Missing MFA session — sign in again.', 400);

  const th = await sha256hex(pending);
  const row = await env.DB.prepare('SELECT * FROM mfa_pending WHERE token_hash=?').bind(th).first();
  if (!row || row.expires_at < Date.now()) return bad('MFA session expired — sign in again.', 401);

  const user = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(row.user_id).first();
  if (!user || !user.mfa_secret) return bad('MFA session invalid — sign in again.', 401);

  const ok = await verifyTotp(user.mfa_secret, code);
  if (!ok) {
    const attempts = (row.attempts || 0) + 1;
    if (attempts >= 5) {
      await env.DB.prepare('DELETE FROM mfa_pending WHERE token_hash=?').bind(th).run();
      await audit(env, user.id, 'mfa_fail', 'pending token burned');
      return bad('Too many wrong codes — sign in again.', 429);
    }
    await env.DB.prepare('UPDATE mfa_pending SET attempts=? WHERE token_hash=?').bind(attempts, th).run();
    await audit(env, user.id, 'mfa_fail', user.email);
    return bad('That code didn\'t match — try again.', 401);
  }

  await env.DB.prepare('DELETE FROM mfa_pending WHERE token_hash=?').bind(th).run();
  const { token, exp } = await createSession(env, request, user.id, false);
  await audit(env, user.id, 'login_ok', user.email + ' (mfa)');
  return json({ user: safeUser(user, false) }, 200, { 'Set-Cookie': sessionCookie(token, exp) });
}
