'use strict';
/*
 * نظام جولة اللياقة - الخادم
 * Node.js only, no external packages. Data is kept in DATA_DIR/db.json with daily backups.
 *
 * Environment variables:
 *   PORT            port to listen on (the host usually sets it)
 *   DATA_DIR        folder for the data file and backups (default ./data). Must be on a persistent disk.
 *   ADMIN_USERNAME  manager login name (default admin)
 *   ADMIN_PASSWORD  manager password (required on first start; changing it later resets the manager password)
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = +process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || process.env.RAILWAY_VOLUME_MOUNT_PATH || path.join(__dirname, 'data');
const ON_HOST = !!(process.env.RAILWAY_ENVIRONMENT || process.env.RAILWAY_PROJECT_ID || process.env.RENDER);
const NO_DISK = ON_HOST && !process.env.DATA_DIR && !process.env.RAILWAY_VOLUME_MOUNT_PATH;
if (NO_DISK) console.warn('\n!!! No persistent volume is attached. Data will be lost on the next deploy. Attach a volume to this service.\n');
const PUB = path.join(__dirname, 'public');
const DBF = path.join(DATA, 'db.json');
const BAK = path.join(DATA, 'backups');
const COLS = ['members', 'subs', 'pay', 'exp', 'att', 'classes', 'book', 'freezeReq', 'pt', 'campaigns', 'daily', 'leads', 'cash', 'plans', 'trainers'];
const STAFF = ['manager', 'reception'];
const LOG_MAX = 3000;

fs.mkdirSync(BAK, { recursive: true });

/* ---------------- storage ---------------- */
let db = loadDb();
let changeLog = [];          // recent changes for staff devices: {rev, c, op, v|id}
let saveTimer = null;

function loadDb() {
  let d = null;
  try { d = JSON.parse(fs.readFileSync(DBF, 'utf8')); } catch (e) {
    if (fs.existsSync(DBF)) { console.error('db.json could not be read:', e.message); process.exit(1); }
  }
  d = d || {};
  d.rev = d.rev || 1;
  d.state = d.state || {};
  d.users = d.users || [];
  d.creds = d.creds || {};
  d.secret = d.secret || crypto.randomBytes(32).toString('hex');
  return d;
}
function writeNow() {
  clearTimeout(saveTimer); saveTimer = null;
  // once a day, keep a copy of the data as it was before today's first change
  const day = new Date().toISOString().slice(0, 10), bf = path.join(BAK, day + '.json');
  if (fs.existsSync(DBF) && !fs.existsSync(bf)) {
    try {
      fs.copyFileSync(DBF, bf);
      const old = fs.readdirSync(BAK).filter(f => /^\d{4}-\d{2}-\d{2}\.json$/.test(f)).sort();
      old.slice(0, Math.max(0, old.length - 30)).forEach(f => fs.unlinkSync(path.join(BAK, f)));
    } catch (e) { console.error('backup failed', e.message); }
  }
  const tmp = DBF + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DBF);
}
function persist() { if (!saveTimer) saveTimer = setTimeout(writeNow, 150); }
process.on('SIGTERM', () => { try { if (saveTimer) writeNow(); } finally { process.exit(0); } });
process.on('SIGINT', () => { try { if (saveTimer) writeNow(); } finally { process.exit(0); } });

/* ---------------- passwords + sessions ---------------- */
function hashPw(p) {
  const salt = crypto.randomBytes(16).toString('hex');
  return 's1$' + salt + '$' + crypto.scryptSync(String(p), salt, 64).toString('hex');
}
function checkPw(p, h) {
  if (!h || typeof h !== 'string') return false;
  const [, salt, hex] = h.split('$');
  if (!salt || !hex) return false;
  const a = crypto.scryptSync(String(p), salt, 64), b = Buffer.from(hex, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const b64 = s => Buffer.from(s).toString('base64url');
function sign(payload) {
  const body = b64(JSON.stringify(payload));
  return body + '.' + crypto.createHmac('sha256', db.secret).update(body).digest('base64url');
}
function unsign(tok) {
  if (!tok || tok.indexOf('.') < 0) return null;
  const [body, mac] = tok.split('.');
  const want = crypto.createHmac('sha256', db.secret).update(body).digest('base64url');
  if (mac.length !== want.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(want))) return null;
  try { const p = JSON.parse(Buffer.from(body, 'base64url').toString()); return p.exp > Date.now() ? p : null; } catch (e) { return null; }
}

// manager account from environment
(function ensureAdmin() {
  const uname = (process.env.ADMIN_USERNAME || 'admin').trim().toLowerCase();
  const pw = process.env.ADMIN_PASSWORD;
  let a = db.users.find(u => u.id === 'admin');
  if (!a && !pw) { console.warn('\n!!! ADMIN_PASSWORD is not set. Set it in your hosting variables to create the manager account.\n'); return; }
  if (!a) { a = { id: 'admin', username: uname, name: 'المدير', role: 'manager', pv: 1 }; db.users.push(a); }
  a.username = uname;
  if (pw && !checkPw(pw, a.hash)) { a.hash = hashPw(pw); a.pv = (a.pv || 0) + 1; }
  writeNow();
})();

const st = () => db.state;
const findTrainer = id => (st().trainers || []).find(t => t.id === id);
const findMember = id => (st().members || []).find(m => m.id === id);
const normPhone = p => String(p || '').replace(/\D/g, '');

function principal(s) {
  // returns {role, ref, name} for a valid session, else null
  if (!s) return null;
  if (s.k === 'u') {
    const u = db.users.find(x => x.id === s.id);
    if (!u || (u.pv || 0) !== s.pv) return null;
    return { role: u.role, ref: '', name: u.name || u.username, key: 'u:' + u.id };
  }
  const c = db.creds[s.k + ':' + s.id];
  if (!c || (c.pv || 0) !== s.pv) return null;
  if (s.k === 't') { const t = findTrainer(s.id); return t ? { role: 'trainer', ref: t.id, name: t.name, key: 't:' + t.id } : null; }
  if (s.k === 'm') { const m = findMember(s.id); return m ? { role: 'trainee', ref: m.id, name: m.name, key: 'm:' + m.id } : null; }
  return null;
}

/* ---------------- rate limiting ---------------- */
const hits = new Map();
function limited(key, max, ms) {
  const now = Date.now(), h = (hits.get(key) || []).filter(t => now - t < ms);
  h.push(now); hits.set(key, h);
  return h.length > max;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some(t => now - t < 3600e3)) hits.delete(k); }, 600e3).unref();

/* ---------------- role views ---------------- */
const pick = (o, keys) => { const r = {}; keys.forEach(k => { if (o[k] !== undefined) r[k] = o[k]; }); return r; };
function viewFor(p) {
  const s = st();
  if (p.role === 'manager') return s;
  if (p.role === 'reception') {
    const o = Object.assign({}, s); delete o.exp; delete o.cash;
    o.settings = Object.assign({}, s.settings || {}); delete o.settings.pin;
    return o;
  }
  const set = pick(s.settings || {}, ['gym', 'soonDays', 'churnDays', 'portalLink', 'dailyPrice']);
  const trainers = (s.trainers || []).map(t => pick(t, ['id', 'name', 'spec']));
  if (p.role === 'trainer') {
    return {
      settings: set, trainers, plans: s.plans || [], classes: s.classes || [], book: s.book || [], att: s.att || [],
      members: (s.members || []).map(m => pick(m, ['id', 'code', 'name', 'phone', 'gender', 'trainerId', 'joined', 'birth', 'notes'])),
      subs: (s.subs || []).map(x => pick(x, ['id', 'memberId', 'planId', 'planName', 'start', 'end', 'cancelled', 'freezes', 'freezeMax'])),
      pt: (s.pt || []).filter(x => x.trainerId === p.ref)
    };
  }
  // trainee: only their own records
  const me = p.ref, own = a => (a || []).filter(x => x.memberId === me);
  return {
    settings: set, trainers, plans: s.plans || [], classes: s.classes || [],
    members: (s.members || []).filter(m => m.id === me),
    subs: own(s.subs), pay: own(s.pay), att: own(s.att), pt: own(s.pt), freezeReq: own(s.freezeReq),
    book: (s.book || []).map(b => b.memberId === me ? b : { id: b.id, classId: b.classId, date: b.date })
  };
}

/* ---------------- sync ---------------- */
function canWrite(p, c, oldV, newV) {
  const r = p.role;
  if (r === 'manager') return true;
  if (r === 'reception') return ['exp', 'cash', 'plans', 'trainers'].indexOf(c) < 0;
  if (r === 'trainer') {
    if (c === 'book') return true;
    if (c === 'pt') return (!oldV || oldV.trainerId === p.ref) && (!newV || newV.trainerId === p.ref);
    return false;
  }
  if (r === 'trainee') {
    if (c === 'book') return (!oldV || oldV.memberId === p.ref) && (!newV || newV.memberId === p.ref);
    if (c === 'freezeReq') return !oldV && newV && newV.memberId === p.ref && newV.status === 'pending';
    return false;
  }
  return false;
}
function numFrom(code) { return parseInt(String(code || '').replace(/\D/g, ''), 10) || 0; }

function applySync(p, ops) {
  if (!Array.isArray(ops) || ops.length > 20000) throw httpErr(400, 'طلب غير صالح');
  const s = st(), remap = { members: {}, subs: {} }, logged = [];
  const maps = {};
  const mapOf = c => maps[c] || (maps[c] = new Map((s[c] = s[c] || []).map((x, i) => [x.id, i])));
  // validate everything first so a refused batch changes nothing
  for (const op of ops) {
    if (!op || typeof op !== 'object') throw httpErr(400, 'طلب غير صالح');
    if (op.c === 'meta') { if (['nextCode', 'nextInv'].indexOf(op.k) < 0 || STAFF.indexOf(p.role) < 0) throw httpErr(403, 'غير مسموح'); continue; }
    if (op.c === 'settings') { if (p.role !== 'manager' || !op.v || typeof op.v !== 'object') throw httpErr(403, 'الإعدادات للمدير فقط'); continue; }
    if (COLS.indexOf(op.c) < 0) throw httpErr(400, 'نوع بيانات غير معروف');
    const id = op.op === 'put' ? op.v && op.v.id : op.id;
    if (typeof id !== 'string' || !id || id.length > 80) throw httpErr(400, 'معرّف غير صالح');
    if (op.op !== 'put' && op.op !== 'del') throw httpErr(400, 'عملية غير معروفة');
    const i = mapOf(op.c).get(id), old = i === undefined ? null : s[op.c][i];
    if (!canWrite(p, op.c, old, op.op === 'put' ? op.v : null)) throw httpErr(403, 'لا تملك صلاحية تعديل هذه البيانات');
  }
  for (const op of ops) {
    if (op.c === 'meta') { s[op.k] = Math.max(s[op.k] || 0, +op.v || 0); continue; }
    if (op.c === 'settings') {
      const v = Object.assign({}, op.v);
      if (p.role !== 'manager') v.pin = (s.settings || {}).pin;
      s.settings = v; logged.push({ c: 'settings', op: 'set', v: s.settings }); continue;
    }
    const arr = s[op.c], m = mapOf(op.c);
    if (op.op === 'put') {
      const v = op.v, i = m.get(v.id);
      if (i === undefined) {
        if (op.c === 'members' && arr.some(x => x.code === v.code)) {
          s.nextCode = Math.max(s.nextCode || 1001, ...arr.map(x => numFrom(x.code) + 1));
          v.code = 'M-' + (s.nextCode++); remap.members[v.id] = v.code;
        }
        if (op.c === 'subs' && arr.some(x => x.inv === v.inv)) {
          s.nextInv = Math.max(s.nextInv || 1, ...arr.map(x => numFrom(x.inv) + 1));
          v.inv = 'INV-' + String(s.nextInv++).padStart(4, '0'); remap.subs[v.id] = v.inv;
        }
        m.set(v.id, arr.length); arr.push(v);
      } else arr[i] = v;
      logged.push({ c: op.c, op: 'put', v });
    } else {
      const i = m.get(op.id);
      if (i !== undefined) { arr.splice(i, 1); maps[op.c] = null; logged.push({ c: op.c, op: 'del', id: op.id }); }
      if (op.c === 'members') delete db.creds['m:' + op.id];
      if (op.c === 'trainers') delete db.creds['t:' + op.id];
    }
  }
  if (logged.length || ops.some(o => o.c === 'meta')) {
    db.rev++;
    logged.forEach(e => changeLog.push(Object.assign({ rev: db.rev }, e)));
    if (changeLog.length > LOG_MAX) changeLog = changeLog.slice(-LOG_MAX);
    persist();
  }
  return { rev: db.rev, remap };
}

/* ---------------- http helpers ---------------- */
function httpErr(status, msg) { const e = new Error(msg); e.status = status; return e; }
function send(res, status, obj, headers) {
  const body = JSON.stringify(obj);
  res.writeHead(status, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, headers || {}));
  res.end(body);
}
function readBody(req, max) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', d => { n += d.length; if (n > max) { reject(httpErr(413, 'البيانات المرسلة كبيرة جداً')); req.destroy(); } else chunks.push(d); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch (e) { reject(httpErr(400, 'طلب غير صالح')); } });
    req.on('error', reject);
  });
}
function cookies(req) {
  const o = {}; (req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return o;
}
function isHttps(req) { return req.headers['x-forwarded-proto'] === 'https' || !!req.socket.encrypted; }
function sessCookie(req, tok, maxAge) {
  return 'gs=' + encodeURIComponent(tok) + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + maxAge + (isHttps(req) ? '; Secure' : '');
}
function clientIp(req) { return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim(); }

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json', '.json': 'application/json' };
function serveStatic(req, res) {
  let rel = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (rel === '/' || !path.extname(rel)) rel = '/index.html';
  const f = path.normalize(path.join(PUB, rel));
  if (!f.startsWith(PUB)) { res.writeHead(403); return res.end(); }
  fs.readFile(f, (err, buf) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'Cache-Control': rel === '/index.html' ? 'no-cache' : 'public, max-age=86400', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin' });
    res.end(buf);
  });
}

/* ---------------- routes ---------------- */
async function api(req, res, route) {
  const method = req.method;
  if (method !== 'GET' && req.headers['x-requested-with'] !== 'gym') throw httpErr(403, 'طلب مرفوض');
  const sess = unsign(cookies(req).gs), p = principal(sess);
  const need = roles => { if (!p) throw httpErr(401, 'سجّل الدخول أولاً'); if (roles && roles.indexOf(p.role) < 0) throw httpErr(403, 'غير مسموح'); };

  if (route === 'login' && method === 'POST') {
    const ip = clientIp(req);
    if (limited('login:' + ip, 12, 15 * 60e3)) throw httpErr(429, 'محاولات كثيرة. انتظر 15 دقيقة ثم حاول مجدداً');
    const b = await readBody(req, 4096), u = String(b.u || '').trim().toLowerCase(), pw = String(b.p || '');
    let tok = null;
    const staff = db.users.find(x => x.username === u);
    if (staff && checkPw(pw, staff.hash)) tok = { k: 'u', id: staff.id, pv: staff.pv || 0 };
    if (!tok && normPhone(u).length >= 9) {
      const ph = normPhone(u);
      const t = (st().trainers || []).find(x => normPhone(x.phone) === ph), ct = t && db.creds['t:' + t.id];
      if (ct && checkPw(pw, ct.hash)) tok = { k: 't', id: t.id, pv: ct.pv || 0 };
      if (!tok) {
        const m = (st().members || []).find(x => normPhone(x.phone) === ph), cm = m && db.creds['m:' + m.id];
        if (cm && checkPw(pw, cm.hash)) tok = { k: 'm', id: m.id, pv: cm.pv || 0 };
      }
    }
    if (!tok) {
      const m = (st().members || []).find(x => String(x.code || '').toLowerCase() === u), cm = m && db.creds['m:' + m.id];
      if (cm && checkPw(pw, cm.hash)) tok = { k: 'm', id: m.id, pv: cm.pv || 0 };
    }
    if (!tok) throw httpErr(401, 'اسم المستخدم أو رقم الجوال أو كلمة المرور غير صحيحة');
    tok.exp = Date.now() + 30 * 86400e3;
    const who = principal(tok);
    return send(res, 200, { role: who.role, ref: who.ref, name: who.name, rev: db.rev }, { 'Set-Cookie': sessCookie(req, sign(tok), 30 * 86400) });
  }
  if (route === 'logout' && method === 'POST') return send(res, 200, { ok: true }, { 'Set-Cookie': sessCookie(req, '', 0) });
  if (route === 'me') { need(); return send(res, 200, { role: p.role, ref: p.ref, name: p.name, rev: db.rev }); }
  if (route === 'rev') { need(); return send(res, 200, { rev: db.rev }); }
  if (route === 'state') { need(); return send(res, 200, { rev: db.rev, state: viewFor(p), warn: NO_DISK && p.role === 'manager' ? 'لا يوجد قرص دائم مربوط بالخادم، وستُحذف البيانات عند أي تحديث. اربط Volume بالخدمة من لوحة الاستضافة قبل إدخال بيانات حقيقية.' : '' }); }
  if (route === 'changes') {
    need(STAFF);
    const since = +new URL(req.url, 'http://x').searchParams.get('since') || 0;
    if (!changeLog.length || since < changeLog[0].rev - 1) return send(res, 200, { full: true, rev: db.rev });
    let ch = changeLog.filter(e => e.rev > since);
    if (p.role === 'reception') ch = ch.filter(e => e.c !== 'exp' && e.c !== 'cash').map(e => e.c === 'settings' ? Object.assign({}, e, { v: Object.assign({}, e.v, { pin: undefined }) }) : e);
    return send(res, 200, { rev: db.rev, changes: ch });
  }
  if (route === 'sync' && method === 'POST') {
    need();
    const b = await readBody(req, 12 * 1024 * 1024);
    return send(res, 200, applySync(p, b.ops));
  }
  if (route === 'creds' && method === 'POST') {
    need(STAFF);
    const b = await readBody(req, 4096), kind = b.kind === 'trainer' ? 't' : 'm', pw = String(b.password || '');
    if (kind === 't' && p.role !== 'manager') throw httpErr(403, 'كلمات مرور المدربين يضبطها المدير');
    if (typeof b.id !== 'string' || !b.id) throw httpErr(400, 'معرّف غير صالح');
    if (pw.length < 4) throw httpErr(400, 'كلمة المرور 4 أحرف على الأقل');
    const k = kind + ':' + b.id, old = db.creds[k];
    db.creds[k] = { hash: hashPw(pw), pv: ((old && old.pv) || 0) + 1 };
    persist();
    return send(res, 200, { ok: true });
  }
  if (route === 'password' && method === 'POST') {
    need();
    const b = await readBody(req, 4096), np = String(b.new || '');
    if (np.length < 6) throw httpErr(400, 'كلمة المرور الجديدة 6 أحرف على الأقل');
    if (limited('pw:' + p.key, 8, 15 * 60e3)) throw httpErr(429, 'محاولات كثيرة، انتظر قليلاً');
    let rec, isUser = p.key.startsWith('u:');
    if (isUser) { rec = db.users.find(u => 'u:' + u.id === p.key); if (rec.id === 'admin') throw httpErr(400, 'كلمة مرور المدير الرئيسي تُغيَّر من متغير ADMIN_PASSWORD في الاستضافة'); }
    else rec = db.creds[p.key];
    if (!rec || !checkPw(String(b.old || ''), rec.hash)) throw httpErr(400, 'كلمة المرور الحالية غير صحيحة');
    rec.hash = hashPw(np); rec.pv = (rec.pv || 0) + 1;
    persist();
    const tok = { k: isUser ? 'u' : p.key[0], id: p.key.slice(2), pv: rec.pv, exp: Date.now() + 30 * 86400e3 };
    return send(res, 200, { ok: true }, { 'Set-Cookie': sessCookie(req, sign(tok), 30 * 86400) });
  }
  if (route === 'pin' && method === 'POST') {
    need(STAFF);
    if (limited('pin:' + p.key, 10, 15 * 60e3)) throw httpErr(429, 'محاولات كثيرة، انتظر قليلاً');
    const b = await readBody(req, 1024), want = String((st().settings || {}).pin || '1234');
    return send(res, 200, { ok: String(b.pin || '') === want });
  }
  if (route === 'users') {
    need(['manager']);
    if (method === 'GET') return send(res, 200, { users: db.users.map(u => ({ id: u.id, username: u.username, name: u.name, role: u.role, main: u.id === 'admin' })) });
    const b = await readBody(req, 4096);
    if (b.action === 'create') {
      const un = String(b.username || '').trim().toLowerCase(), pw = String(b.password || '');
      if (!/^[a-z0-9._-]{3,32}$/.test(un)) throw httpErr(400, 'اسم المستخدم بالإنجليزية والأرقام فقط، من 3 إلى 32 حرفاً');
      if (db.users.some(u => u.username === un)) throw httpErr(400, 'اسم المستخدم مستخدم من قبل');
      if (pw.length < 6) throw httpErr(400, 'كلمة المرور 6 أحرف على الأقل');
      db.users.push({ id: 'u' + crypto.randomBytes(6).toString('hex'), username: un, name: String(b.name || un).slice(0, 60), role: b.role === 'manager' ? 'manager' : 'reception', hash: hashPw(pw), pv: 1 });
    } else if (b.action === 'delete') {
      if (b.id === 'admin') throw httpErr(400, 'لا يمكن حذف حساب المدير الرئيسي');
      db.users = db.users.filter(u => u.id !== b.id);
    } else if (b.action === 'password') {
      const u = db.users.find(x => x.id === b.id), pw = String(b.password || '');
      if (!u) throw httpErr(404, 'الحساب غير موجود');
      if (u.id === 'admin') throw httpErr(400, 'كلمة مرور المدير الرئيسي تُغيَّر من متغير ADMIN_PASSWORD في الاستضافة');
      if (pw.length < 6) throw httpErr(400, 'كلمة المرور 6 أحرف على الأقل');
      u.hash = hashPw(pw); u.pv = (u.pv || 0) + 1;
    } else throw httpErr(400, 'طلب غير صالح');
    persist();
    return send(res, 200, { ok: true });
  }
  if (route === 'backup') {
    need(['manager']);
    const day = new Date().toISOString().slice(0, 10);
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': 'attachment; filename="round-gym-backup-' + day + '.json"', 'Cache-Control': 'no-store' });
    return res.end(JSON.stringify({ exportedAt: new Date().toISOString(), rev: db.rev, state: db.state }, null, 1));
  }
  throw httpErr(404, 'غير موجود');
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname === '/healthz') { res.writeHead(200); return res.end('ok'); }
  if (u.pathname.startsWith('/api/')) {
    try { await api(req, res, u.pathname.slice(5)); }
    catch (e) {
      const status = e.status || 500;
      if (status === 500) console.error(e);
      if (!res.headersSent) send(res, status, { error: status === 500 ? 'خطأ في الخادم' : e.message });
    }
    return;
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  serveStatic(req, res);
});
server.listen(PORT, () => console.log('نظام جولة اللياقة يعمل على المنفذ ' + PORT + ' · البيانات في ' + DATA));
