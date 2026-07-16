/* ================================================================
   BillboardIQ Auth API — Cloudflare Pages Functions + D1
   Binding required: D1 database bound as `DB` in Pages settings.
   Endpoints (all under /api/):
     GET  auth/status          → { needsBootstrap }
     POST auth/bootstrap       → create FIRST superuser (only when DB empty)
     POST auth/register        → public signup (role: user)
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
   ================================================================ */

const PBKDF2_ITERATIONS = 100000; // lower to 50000 if you ever hit CPU limits on free tier
const SESSION_DAYS = 7;
const MFA_PENDING_MINUTES = 5;
const LOCKOUT_AFTER = 5;          // failed attempts
const LOCKOUT_MINUTES = 15;
const MIN_PASSWORD_LEN = 10;
const MFA_REQUIRED_ROLES = ['admin', 'superuser'];
const ROLE_RANK = { user: 1, admin: 2, superuser: 3 };

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
    'SELECT s.token_hash AS session_hash, s.restricted, s.expires_at AS session_expires, u.* ' +
    'FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?'
  ).bind(th).first();
  if (!row || row.session_expires < Date.now()) return null;
  return row;
}

function safeUser(u, restricted) {
  return {
    id: u.id, email: u.email, name: u.name, role: u.role,
    mfaEnabled: !!u.mfa_enabled,
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

function validEmail(e) { return typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 200; }

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

    if (path === 'auth/bootstrap' && method === 'POST') {
      const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
      if (row.n > 0) return bad('Bootstrap is disabled — users already exist.', 403);
      return await register(env, request, body, 'superuser', 'bootstrap');
    }

    if (path === 'auth/register' && method === 'POST') {
      return await register(env, request, body, 'user', 'register');
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
        'SELECT id,email,name,role,mfa_enabled,last_login,created_at FROM users ORDER BY created_at ASC'
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
      await env.DB.prepare('UPDATE users SET role=? WHERE id=?').bind(role, userId).run();
      // Force re-auth if promoted into an MFA-mandatory role without MFA
      if (MFA_REQUIRED_ROLES.includes(role) && !target.mfa_enabled) {
        await env.DB.prepare('UPDATE sessions SET restricted=1 WHERE user_id=?').bind(userId).run();
      }
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

    return bad('Not found', 404);
  } catch (err) {
    return bad('Server error: ' + (err && err.message ? err.message : 'unknown'), 500);
  }
}

/* ================================================================
   FLOWS
   ================================================================ */
async function register(env, request, body, role, auditAction) {
  const email = String(body.email || '').trim().toLowerCase();
  const name = String(body.name || '').trim().slice(0, 100);
  const password = String(body.password || '');
  if (!validEmail(email)) return bad('Please enter a valid email address.');
  if (!name) return bad('Please enter your name.');
  if (password.length < MIN_PASSWORD_LEN) return bad('Password must be at least ' + MIN_PASSWORD_LEN + ' characters.');

  const existing = await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first();
  if (existing) return bad('That email is already registered.', 409);

  const { hash, salt } = await hashPassword(password);
  const id = crypto.randomUUID();
  await env.DB.prepare(
    'INSERT INTO users (id,email,name,role,password_hash,password_salt,created_at) VALUES (?,?,?,?,?,?,?)'
  ).bind(id, email, name, role, hash, salt, Date.now()).run();
  await audit(env, id, auditAction, email + ' (' + role + ')');

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
