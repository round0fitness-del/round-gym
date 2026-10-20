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
const Push = require('./push.js');

const PORT = +process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || process.env.RAILWAY_VOLUME_MOUNT_PATH || path.join(__dirname, 'data');
const ON_HOST = !!(process.env.RAILWAY_ENVIRONMENT || process.env.RAILWAY_PROJECT_ID || process.env.RENDER);
const NO_DISK = ON_HOST && !process.env.DATA_DIR && !process.env.RAILWAY_VOLUME_MOUNT_PATH;
if (NO_DISK) console.warn('\n!!! No persistent volume is attached. Data will be lost on the next deploy. Attach a volume to this service.\n');
const PUB = path.join(__dirname, 'public');
const DBF = path.join(DATA, 'db.json');
const BAK = path.join(DATA, 'backups');
const COLS = ['members', 'subs', 'pay', 'exp', 'att', 'classes', 'book', 'freezeReq', 'pt', 'campaigns', 'daily', 'leads', 'cash', 'plans', 'trainers', 'shifts', 'ptPlans', 'ptPacks', 'ptSess', 'treq', 'ptTpl', 'comms', 'jrnl', 'periods', 'budget', 'coa', 'fsruns', 'fb', 'posts'];
const STAFF = ['manager', 'reception'];
const OFFICE = ['manager', 'reception', 'accountant'];
const META_KEYS = ['nextCode', 'nextInv', 'nextCn'];
const STAMP = ['pay', 'exp', 'cash', 'daily', 'shifts', 'subs', 'ptPacks', 'ptSess', 'treq', 'jrnl', 'comms', 'fb'];
const PT_PRIVATE = ['note', 'exercises', 'perf'];
const AUDIT_MAX = 20000;
const HIDDEN = { reception: ['exp', 'cash', 'pt', 'jrnl', 'budget', 'comms', 'ptTpl', 'treq', 'coa', 'fsruns', 'fb'], accountant: ['pt', 'ptTpl', 'treq', 'fb'] };
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
  d.audit = d.audit || [];
  d.vapid = d.vapid || Push.newVapid();
  d.push = d.push || [];
  d.pushSent = d.pushSent || {};
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

/* ---------------- audit log ---------------- */
const fmtMoney = n => (Math.round((+n || 0) * 100) / 100).toLocaleString('en-US') + ' ر.س';
const mTr = id => { const t = (st().trainers || []).find(x => x.id === id); return t ? t.name : 'مدربة'; };
const mName = id => { const m = findMember(id); return m ? m.name : 'عضو محذوف'; };
function audit(p, act, detail, c, ref) {
  db.audit.push({ t: new Date().toISOString(), by: p ? p.name : 'النظام', role: p ? p.role : '', act, detail: detail || '', c: c || '', ref: ref || '' });
  if (db.audit.length > AUDIT_MAX) db.audit = db.audit.slice(-AUDIT_MAX);
}
const SET_LABELS = { gym: 'اسم النادي', soonDays: 'أيام التنبيه', churnDays: 'أيام الانقطاع', dailyPrice: 'سعر الدخول اليومي', openingCash: 'الرصيد الافتتاحي', discLimit: 'حد خصم الاستقبال', portalLink: 'رابط صفحة المتدرب' };
function auditSettings(p, old, v) {
  old = old || {};
  if ((old.pin || '1234') !== (v.pin || '1234')) audit(p, 'تغيير رمز المدير', '', 'settings');
  const ch = Object.keys(SET_LABELS).filter(k => old[k] !== undefined && String(old[k]) !== String(v[k])).map(k => SET_LABELS[k] + ': ' + old[k] + ' ← ' + v[k]);
  if (ch.length) audit(p, 'تعديل الإعدادات', ch.join('، '), 'settings');
  if (JSON.stringify(old.site || null) !== JSON.stringify(v.site || null)) audit(p, 'تحديث محتوى الموقع', '', 'settings');
}
function auditOp(p, c, op, old, v) {
  const del = op === 'del';
  if (c === 'plans') {
    if (del) return old && audit(p, 'حذف باقة', old.name, c, old.id);
    if (!old) return audit(p, 'إضافة باقة', v.name + ' · ' + fmtMoney(v.price), c, v.id);
    const ch = [];
    if (old.price !== v.price) ch.push('السعر ' + fmtMoney(old.price) + ' ← ' + fmtMoney(v.price));
    if (old.days !== v.days) ch.push('المدة ' + old.days + ' ← ' + v.days + ' يوم');
    if ((old.freeze || 0) !== (v.freeze || 0)) ch.push('التجميد ' + (old.freeze || 0) + ' ← ' + (v.freeze || 0) + ' يوم');
    if (old.name !== v.name) ch.push('الاسم ' + old.name + ' ← ' + v.name);
    if (ch.length) audit(p, 'تعديل باقة', v.name + ': ' + ch.join('، '), c, v.id);
    return;
  }
  if (c === 'subs') {
    if (del) return old && audit(p, 'حذف اشتراك', old.inv + ' · ' + mName(old.memberId), c, old.id);
    if (!old) { if (v.disc > 0) audit(p, 'خصم على اشتراك', v.inv + ' · ' + mName(v.memberId) + ' · ' + fmtMoney(v.disc), c, v.id); return; }
    if (!old.cancelled && v.cancelled) audit(p, 'إلغاء اشتراك', v.inv + ' · ' + mName(v.memberId), c, v.id);
    if (old.total !== v.total) audit(p, 'تعديل قيمة الفاتورة', v.inv + ' · ' + fmtMoney(old.total) + ' ← ' + fmtMoney(v.total), c, v.id);
    if ((old.freezes || []).length === (v.freezes || []).length && old.end !== v.end) audit(p, 'تعديل تاريخ انتهاء الاشتراك', v.inv + ' · ' + old.end + ' ← ' + v.end, c, v.id);
    return;
  }
  if (c === 'pay') {
    if (del) return old && audit(p, 'حذف دفعة', fmtMoney(old.amount) + ' · ' + (old.name || mName(old.memberId)), c, old.id);
    if (!old && v.amount < 0) return audit(p, 'استرداد', fmtMoney(-v.amount) + ' · ' + mName(v.memberId) + (v.cn ? ' · ' + v.cn : '') + (v.reason ? ' · ' + v.reason : ''), c, v.id);
    if (old && old.amount !== v.amount) audit(p, 'تعديل دفعة', fmtMoney(old.amount) + ' ← ' + fmtMoney(v.amount), c, v.id);
    return;
  }
  if (c === 'exp') {
    if (del) return old && audit(p, 'حذف مصروف', old.cat + ' · ' + fmtMoney(old.amount), c, old.id);
    if (!old) return audit(p, 'تسجيل مصروف', v.cat + ' · ' + fmtMoney(v.amount), c, v.id);
    if (old.amount !== v.amount) audit(p, 'تعديل مصروف', v.cat + ' · ' + fmtMoney(old.amount) + ' ← ' + fmtMoney(v.amount), c, v.id);
    return;
  }
  if (c === 'cash') {
    if (del) return old && audit(p, 'حذف حركة صندوق', fmtMoney(old.amount) + (old.note ? ' · ' + old.note : ''), c, old.id);
    if (!old) return audit(p, v.type === 'in' ? 'إيداع في الصندوق' : 'سحب من الصندوق', fmtMoney(v.amount) + (v.note ? ' · ' + v.note : ''), c, v.id);
    return;
  }
  if (c === 'pt') {
    if (del) return old && audit(p, 'حذف ملف تدريب شخصي', mName(old.memberId), c, old.id);
    if (old && v && old.sessions && v.sessions) {
      if (v.sessions.used !== old.sessions.used) audit(p, v.sessions.used > old.sessions.used ? 'خصم جلسة تدريب' : 'إرجاع جلسة تدريب', mName(v.memberId) + ' · ' + v.sessions.used + ' من ' + v.sessions.total, c, v.id);
      if (v.sessions.total !== old.sessions.total) audit(p, 'تعديل رصيد الجلسات', mName(v.memberId) + ' · ' + old.sessions.total + ' ← ' + v.sessions.total, c, v.id);
    }
    return;
  }
  if (c === 'ptPlans') {
    if (del) return old && audit(p, 'حذف باقة تدريب', old.name, c, old.id);
    if (!old) return audit(p, 'إضافة باقة تدريب', v.name + ' · ' + v.sessions + ' جلسة · ' + fmtMoney(v.price), c, v.id);
    if (old.price !== v.price || old.sessions !== v.sessions) audit(p, 'تعديل باقة تدريب', v.name + ': ' + fmtMoney(old.price) + ' ← ' + fmtMoney(v.price) + '، ' + old.sessions + ' ← ' + v.sessions + ' جلسة', c, v.id);
    return;
  }
  if (c === 'ptPacks') {
    if (del) return old && audit(p, 'حذف باقة تدريب مباعة', mName(old.memberId) + ' · ' + old.name, c, old.id);
    if (!old) return audit(p, 'بيع باقة تدريب شخصي', mName(v.memberId) + ' · ' + v.name + ' · ' + v.sessions + ' جلسة', c, v.id);
    const oa = old.adj || [], na = v.adj || [];
    if (na.length > oa.length) na.slice(oa.length).forEach(a => audit(p, 'تعديل يدوي لرصيد الجلسات', mName(v.memberId) + ' · ' + (a.n > 0 ? 'خصم ' + a.n : 'إضافة ' + (-a.n)) + ' جلسة · ' + (a.reason || ''), c, v.id));
    if (old.status !== 'cancelled' && v.status === 'cancelled') audit(p, 'إلغاء باقة تدريب', mName(v.memberId) + ' · ' + v.name, c, v.id);
    const ot = old.topups || [], nt = v.topups || [];
    if (nt.length > ot.length) nt.slice(ot.length).forEach(t => audit(p, t.subId ? 'إضافة رصيد جلسات (بفاتورة)' : 'إضافة رصيد جلسات يدوياً', mName(v.memberId) + ' · ' + v.name + ' · +' + t.n + ' جلسة' + (t.reason ? ' · ' + t.reason : ''), c, v.id));
    if (old.expires !== v.expires) audit(p, 'تمديد صلاحية باقة تدريب', mName(v.memberId) + ' · ' + old.expires + ' ← ' + v.expires, c, v.id);
    return;
  }
  if (c === 'ptSess') {
    if (del) return old && audit(p, 'حذف جلسة تدريب', mName(old.memberId) + ' · ' + old.date + ' ' + old.time, c, old.id);
    if (old && v.status === 'booked' && old.status === 'booked' && (old.date !== v.date || old.time !== v.time || old.trainerId !== v.trainerId)) return audit(p, 'إعادة جدولة جلسة', mName(v.memberId) + ' · ' + old.date + ' ' + old.time + ' ← ' + v.date + ' ' + v.time, c, v.id);
    if (!old || old.status === v.status && !!old.charged === !!v.charged && (+old.units || 1) === (+v.units || 1)) return;
    const lbl = { done: 'توثيق حضور جلسة', noshow: 'غياب عن جلسة', late_cancel: 'إلغاء متأخر لجلسة', cancelled: 'إلغاء جلسة ضمن المهلة', club_cancel: 'إلغاء جلسة من النادي أو المدربة', booked: 'إعادة حجز جلسة' }[v.status] || 'تحديث جلسة';
    return audit(p, old.status === v.status ? 'تعديل يدوي لخصم جلسة' : lbl, mName(v.memberId) + ' · ' + v.date + ' ' + v.time + (v.charged ? ' · خُصمت ' + ((+v.units || 1) === 0.5 ? 'نصف جلسة' : 'جلسة') + ' من الرصيد' : ' · بدون خصم') + (v.adjReason ? ' · ' + v.adjReason : ''), c, v.id);
  }
  if (c === 'jrnl') {
    if (del) return old && audit(p, 'حذف قيد يومية', (old.no || '') + ' · ' + (old.memo || ''), c, old.id);
    const tot = (v.lines || []).reduce((a, x) => a + (+x.dr || 0), 0);
    if (!old) return audit(p, v.status === 'posted' ? 'ترحيل قيد يومية' : 'إنشاء مسودة قيد', (v.no || '') + ' · ' + (v.memo || '') + ' · ' + fmtMoney(tot), c, v.id);
    if (old.status !== v.status) return audit(p, v.status === 'posted' ? 'ترحيل قيد يومية' : 'إلغاء ترحيل قيد', (v.no || '') + ' · ' + fmtMoney(tot), c, v.id);
    return audit(p, 'تعديل قيد يومية', (v.no || '') + ' · ' + fmtMoney(tot), c, v.id);
  }
  if (c === 'periods') return v ? audit(p, v.status === 'closed' ? 'إقفال فترة مالية' : 'إعادة فتح فترة مالية', v.id + (v.note ? ' · ' + v.note : ''), c, v.id) : null;
  if (c === 'comms') return v ? audit(p, v.status === 'paid' ? 'صرف عمولة مدربة' : 'اعتماد عمولة مدربة', mTr(v.trainerId) + ' · ' + v.ym + ' · ' + fmtMoney(v.amount), c, v.id) : null;
  if (c === 'fb') { if (!old && v) return audit(p, v.type === 'complaint' ? 'شكوى جديدة' : 'اقتراح جديد', (v.name || '') + ' · ' + (v.cat || ''), c, v.id); if (old && v && (old.status !== v.status || old.reply !== v.reply)) return audit(p, 'متابعة شكوى أو اقتراح', (v.name || '') + ' · ' + ({ new: 'جديدة', progress: 'قيد المعالجة', closed: 'مغلقة' })[v.status], c, v.id); return; }
  if (c === 'posts') { if (del) return old && audit(p, 'حذف مقال', old.title, c, old.id); if (!old || old.status !== v.status) return audit(p, v.status === 'published' ? 'نشر مقال' : 'حفظ مسودة مقال', v.title, c, v.id); return audit(p, 'تعديل مقال', v.title, c, v.id); }
  if (c === 'fsruns') return v ? audit(p, 'اعتماد القوائم المالية', v.no + ' · ' + v.from + ' ← ' + v.to, c, v.id) : null;
  if (c === 'coa') return v ? audit(p, old ? 'تعديل حساب' : 'إضافة حساب', v.id + ' · ' + v.name, c, v.id) : null;
  if (c === 'budget') return v ? audit(p, 'تعديل الموازنة', v.id + ' · ' + fmtMoney(v.monthly), c, v.id) : null;
  if (c === 'treq' && v && old && old.status !== v.status) return audit(p, v.status === 'approved' ? 'اعتماد طلب مدربة' : 'رفض طلب مدربة', mTr(v.trainerId) + ' · ' + ({ leave: 'إجازة', avail: 'تعديل التوفر', fix: 'تصحيح رصيد' })[v.type] + (v.from ? ' · ' + v.from + ' ← ' + v.to : ''), c, v.id);
  if (c === 'exp' && v && old && !old.paidAt && v.paidAt) return audit(p, 'سداد مستحق مورد', (v.supplier || v.cat) + ' · ' + fmtMoney(v.amount), c, v.id);
  if (c === 'members' && del && old) return audit(p, 'حذف عضو', old.name + ' · ' + old.code, c, old.id);
  if (c === 'freezeReq' && old && v && old.status !== v.status) return audit(p, v.status === 'approved' ? 'اعتماد طلب تجميد' : v.status === 'rejected' ? 'رفض طلب تجميد' : 'تحديث طلب تجميد', mName(v.memberId) + ' · ' + v.days + ' يوم', c, v.id);
  if (c === 'shifts' && !old && v) return audit(p, 'إغلاق وردية', 'المتوقع ' + fmtMoney(v.expTotal) + ' · المعدود ' + fmtMoney(v.cntTotal) + ' · الفرق ' + fmtMoney(v.diff), c, v.id);
  if (c === 'daily' && del && old) return audit(p, 'حذف زيارة يومية', old.name + ' · ' + fmtMoney(old.amount), c, old.id);
  if ((c === 'trainers' || c === 'classes') && del && old) return audit(p, c === 'trainers' ? 'حذف مدرب' : 'حذف حصة', old.name, c, old.id);
}

/* ---------------- role views ---------------- */
const packUnit = (s, k) => { const subs = (s.subs || []).filter(x => x.kind === 'pt' && (x.packId === k.id || x.id === k.subId)); const val = subs.reduce((a, x) => a + Math.max(0, +x.total || 0), 0), n = (+k.sessions || 0) + (k.topups || []).reduce((a, t) => a + (+t.n || 0), 0); return n ? Math.round(val / n * 100) / 100 : 0; };
const stripPt = x => { const o = Object.assign({}, x); PT_PRIVATE.forEach(k => delete o[k]); return o; };
const pick = (o, keys) => { const r = {}; keys.forEach(k => { if (o[k] !== undefined) r[k] = o[k]; }); return r; };
function viewFor(p) {
  const s = st();
  if (p.role === 'manager') return s;
  if (p.role === 'reception' || p.role === 'accountant') {
    const o = Object.assign({}, s);
    HIDDEN[p.role].forEach(k => delete o[k]);
    o.settings = Object.assign({}, s.settings || {}); delete o.settings.pin;
    if (p.role === 'accountant') o.members = (s.members || []).map(m => pick(m, ['id', 'code', 'name', 'phone', 'gender', 'trainerId', 'joined']));
    if (o.ptSess) o.ptSess = o.ptSess.map(stripPt);
    return o;
  }
  const set = pick(s.settings || {}, ['gym', 'soonDays', 'churnDays', 'portalLink', 'dailyPrice', 'ptCancelHours', 'ptLateCharge', 'ptNoShowCharge', 'classCancelHours', 'phone', 'legalName', 'crNo', 'vatNo', 'address', 'terms', 'termsVer', 'termsDate', 'offers', 'tpl', 'site']);
  const trainers = (s.trainers || []).map(t => pick(t, ['id', 'name', 'spec']));
  if (p.role === 'trainer') {
    const me = p.ref, classes = (s.classes || []).filter(c => c.trainerId === me), cids = new Set(classes.map(c => c.id));
    const book = (s.book || []).filter(b => cids.has(b.classId));
    const packs = (s.ptPacks || []).filter(k => (k.trainerIds || []).indexOf(me) >= 0);
    const ids = new Set((s.members || []).filter(m => m.trainerId === me).map(m => m.id));
    packs.forEach(k => ids.add(k.memberId)); (s.pt || []).filter(x => x.trainerId === me).forEach(x => ids.add(x.memberId)); book.forEach(b => ids.add(b.memberId));
    (s.ptSess || []).filter(x => x.trainerId === me).forEach(x => ids.add(x.memberId));
    const mine = a => (a || []).filter(x => ids.has(x.memberId));
    return {
      settings: set, trainers, plans: s.plans || [], classes, book, att: mine(s.att),
      members: (s.members || []).filter(m => ids.has(m.id)).map(m => pick(m, ['id', 'code', 'name', 'phone', 'gender', 'trainerId', 'joined', 'birth', 'notes'])),
      subs: mine(s.subs).filter(x => x.kind !== 'pt').map(x => pick(x, ['id', 'memberId', 'planId', 'planName', 'start', 'end', 'cancelled', 'freezes', 'freezeMax'])),
      pt: (s.pt || []).filter(x => ids.has(x.memberId)),
      ptPlans: s.ptPlans || [],
      ptPacks: packs.map(k => Object.assign({}, k, { uv: packUnit(s, k) })),
      ptSess: (s.ptSess || []).filter(x => ids.has(x.memberId) && (x.trainerId === me || packs.some(k => k.id === x.packId))),
      treq: (s.treq || []).filter(x => x.trainerId === me),
      ptTpl: (s.ptTpl || []).filter(x => !x.by || x.by === me || x.shared),
      comms: (s.comms || []).filter(x => x.trainerId === me),
      trainerSelf: pick((s.trainers || []).find(t => t.id === me) || {}, ['id', 'name', 'spec', 'avail', 'leaves']),
      posts: appPosts(s)
    };
  }
  // trainee: only their own records
  const me = p.ref, own = a => (a || []).filter(x => x.memberId === me);
  return {
    settings: set, trainers, plans: s.plans || [], classes: s.classes || [],
    members: (s.members || []).filter(m => m.id === me),
    subs: own(s.subs), pay: own(s.pay), att: own(s.att), pt: own(s.pt), freezeReq: own(s.freezeReq),
    ptPacks: own(s.ptPacks), ptSess: own(s.ptSess), ptPlans: s.ptPlans || [], fb: own(s.fb).map(x => { const o = Object.assign({}, x); delete o.note; return o; }),
    book: (s.book || []).map(b => b.memberId === me ? b : { id: b.id, classId: b.classId, date: b.date }),
    posts: appPosts(s)
  };
}

/* ---------------- blog ---------------- */
const POST_PUB = ['id', 'title', 'cat', 'excerpt', 'cover', 'pubAt', 'author', 'pin', 'read'];
const livePosts = (s, where) => (s.posts || []).filter(x => x.status === 'published' && x[where] !== false && (!x.pubAt || x.pubAt <= new Date().toISOString()))
  .sort((a, b) => (b.pin ? 1 : 0) - (a.pin ? 1 : 0) || String(b.pubAt || '').localeCompare(String(a.pubAt || '')));
const appPosts = s => livePosts(s, 'app').slice(0, 40).map(x => pick(x, POST_PUB.concat(['blocks', 'status'])));
const safeImg = u => /^\/uploads\/[A-Za-z0-9._-]+$/.test(String(u || '')) || /^https:\/\/[^\s"'<>]+$/.test(String(u || '')) ? String(u) : '';
function cleanPost(v) {
  const t = (x, n) => String(x == null ? '' : x).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').slice(0, n);
  v.title = t(v.title, 140).trim(); v.cat = t(v.cat, 40).trim(); v.excerpt = t(v.excerpt, 300).trim(); v.author = t(v.author, 60).trim();
  v.cover = safeImg(v.cover); v.status = v.status === 'published' ? 'published' : 'draft';
  v.site = v.site !== false; v.app = v.app !== false; v.pin = !!v.pin; v.notify = !!v.notify;
  if (v.pubAt && !/^\d{4}-\d\d-\d\dT[\d:.]+Z$/.test(String(v.pubAt))) v.pubAt = '';
  const B = Array.isArray(v.blocks) ? v.blocks.slice(0, 120) : [];
  v.blocks = B.map(b => {
    const k = ['p', 'h', 'img', 'quote', 'list', 'btn'].indexOf(b && b.t) >= 0 ? b.t : 'p';
    if (k === 'img') return { t: k, url: safeImg(b.url), cap: t(b.cap, 200) };
    if (k === 'btn') return { t: k, v: t(b.v, 60), url: /^(https:\/\/|\/|#|tel:|https:\/\/wa\.me\/)[^\s"'<>]*$/.test(String(b.url || '')) ? String(b.url).slice(0, 500) : '' };
    return { t: k, v: t(b.v, k === 'h' ? 160 : 6000) };
  }).filter(b => b.t === 'img' ? b.url : (b.v || '').trim());
  const words = v.blocks.reduce((a, b) => a + String(b.v || '').split(/\s+/).filter(Boolean).length, 0);
  v.read = Math.max(1, Math.round(words / 180));
  if (v.status === 'published' && !v.title) throw httpErr(400, 'اكتب عنوان المقال قبل النشر');
  if (v.status === 'published' && !v.blocks.length) throw httpErr(400, 'أضف محتوى للمقال قبل النشر');
}
function blogMeta(html, req, post) {
  const e = x => String(x || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const gym = (st().settings || {}).gym || 'جولة اللياقة', host = String(req.headers['x-forwarded-host'] || req.headers.host || '').replace(/[^A-Za-z0-9.:-]/g, '');
  const title = post ? post.title + ' | ' + gym : 'المدونة | ' + gym;
  const desc = post ? (post.excerpt || String((post.blocks.find(b => b.t === 'p') || {}).v || '').slice(0, 160)) : 'مقالات ونصائح في اللياقة والتغذية والفنون القتالية من فريق ' + gym;
  const img = post && post.cover ? (/^https:/.test(post.cover) ? post.cover : 'https://' + host + post.cover) : 'https://' + host + '/icon.png';
  return html.replace(/<title>[^<]*<\/title>/, '<title>' + e(title) + '</title>')
    .replace(/(<meta name="description" content=")[^"]*/, '$1' + e(desc))
    .replace(/(<meta property="og:type" content=")[^"]*/, '$1' + (post ? 'article' : 'website'))
    .replace(/(<meta property="og:title" content=")[^"]*/, '$1' + e(post ? post.title : title))
    .replace(/(<meta property="og:description" content=")[^"]*/, '$1' + e(desc))
    .replace(/(<meta property="og:image" content=")[^"]*/, '$1' + e(img));
}

/* ---------------- sync ---------------- */
function canWrite(p, c, oldV, newV) {
  const r = p.role;
  if (r === 'manager') return true;
  if (r === 'reception') {
    if (['exp', 'cash', 'plans', 'trainers', 'pt', 'ptPlans', 'jrnl', 'periods', 'budget', 'comms', 'ptTpl', 'treq', 'coa', 'fsruns', 'fb', 'posts'].indexOf(c) >= 0) return false;
    if (c === 'pay') return !oldV && !!newV && +newV.amount > 0;   // collecting only: no refunds, edits or deletions
    if (c === 'shifts') return !oldV && !!newV;
    return true;
  }
  if (r === 'accountant') {
    if (['pay', 'exp', 'cash', 'daily', 'budget', 'coa'].indexOf(c) >= 0) return true;
    if (c === 'jrnl') return !(oldV && oldV.status === 'posted' && (!newV || newV.status !== 'posted' || JSON.stringify(newV.lines) !== JSON.stringify(oldV.lines)));
    if (c === 'subs') return !!oldV && !!newV;                   // refunds and invoice corrections, not new sales
    if (c === 'shifts') return !oldV && !!newV;
    return false;
  }
  if (r === 'trainer') {
    if (c === 'book') { const mineC = id => (st().classes || []).some(x => x.id === id && x.trainerId === p.ref); return (!oldV || mineC(oldV.classId)) && (!newV || mineC(newV.classId)); }
    if (c === 'treq') return (!oldV || (oldV.trainerId === p.ref && oldV.status === 'pending')) && (!newV || (newV.trainerId === p.ref && newV.status === 'pending'));
    if (c === 'ptTpl') return (!oldV || oldV.by === p.ref) && (!newV || newV.by === p.ref);
    if (c === 'pt' || c === 'ptSess') return (!oldV || oldV.trainerId === p.ref) && (!newV || newV.trainerId === p.ref);
    return false;
  }
  if (r === 'trainee') {
    if (c === 'book') return (!oldV || oldV.memberId === p.ref) && (!newV || newV.memberId === p.ref);
    if (c === 'freezeReq') return !oldV && newV && newV.memberId === p.ref && newV.status === 'pending';
    if (c === 'fb') return !oldV && !!newV && newV.memberId === p.ref && ['complaint', 'suggestion'].indexOf(newV.type) >= 0 && String(newV.text || '').trim().length >= 3 && String(newV.text).length <= 2000;
    if (c === 'ptSess' && !oldV) return !!newV && newV.memberId === p.ref && newV.kind === 'class' && newV.status === 'booked' && !newV.charged;
    if (c === 'ptSess') return !!oldV && !!newV && oldV.memberId === p.ref && newV.memberId === p.ref && oldV.status === 'booked' && ['cancelled', 'late_cancel'].indexOf(newV.status) >= 0;
    return false;
  }
  return false;
}
const elev = new Map();
const PDATE = { pay: 'date', exp: 'date', cash: 'date', daily: 'date', jrnl: 'date', ptSess: 'date' };
function lockCheck(s, op, old) {
  const closed = new Set((s.periods || []).filter(x => x.status === 'closed').map(x => x.id));
  if (!closed.size) return;
  const isClosed = d => !!d && closed.has(String(d).slice(0, 7));
  const v = op.op === 'put' ? op.v : null, k = PDATE[op.c];
  const err = () => { throw httpErr(423, 'الفترة ' + String((v && v[k]) || (old && old[k]) || (v && v.start) || '').slice(0, 7) + ' مقفلة. يعيد المدير فتحها أولاً إذا لزم التعديل'); };
  if (op.c === 'subs') { if (!old && v && isClosed(v.start)) err(); if (old && v && isClosed(old.start) && (old.total !== v.total || old.disc !== v.disc)) err(); return; }
  if (op.c === 'exp' && old && v && old.paidAt !== v.paidAt && isClosed(v.paidAt)) err();
  if (!k) return;
  if (op.c === 'ptSess') { if (old && v && old.status === v.status && !!old.charged === !!v.charged && (+old.units || 1) === (+v.units || 1) && old.date === v.date) return; if ((old && old.status !== 'booked' && isClosed(old.date)) || (v && v.status !== 'booked' && isClosed(v.date))) err(); return; }
  if (old && isClosed(old[k])) err();
  if (v && !old && isClosed(v[k])) err();
  if (v && old && isClosed(v[k]) && !isClosed(old[k])) err();
}
const approved = p => p.role === 'manager' || (elev.get(p.key) || 0) > Date.now();
const packTot = k => (+k.sessions || 0) + (k.topups || []).reduce((a, t) => a + (+t.n || 0), 0) + (k.adj || []).filter(a => +a.n < 0).reduce((a, x) => a - (+x.n), 0);
const packUse = (k, sess) => sess.filter(x => x.packId === k.id && x.charged).reduce((a, x) => a + (+x.units || 1), 0) + (k.adj || []).filter(a => +a.n > 0).reduce((a, x) => a + (+x.n), 0);
const GRP = x => x && (x.fmt === 'pair' || x.fmt === 'group');
const mins = t => { const a = String(t || '0:0').split(':'); return (+a[0] || 0) * 60 + (+a[1] || 0); };
function sessHoursAway(x) {
  const off = (st().settings || {}).tzOffset || '+03:00';
  return (new Date(x.date + 'T' + x.time + ':00' + off) - Date.now()) / 36e5;
}
function numFrom(code) { return parseInt(String(code || '').replace(/\D/g, ''), 10) || 0; }

function applySync(p, ops) {
  if (!Array.isArray(ops) || ops.length > 20000) throw httpErr(400, 'طلب غير صالح');
  const s = st(), remap = { members: {}, subs: {} }, logged = [], hooks = [];
  const maps = {};
  const mapOf = c => maps[c] || (maps[c] = new Map((s[c] = s[c] || []).map((x, i) => [x.id, i])));
  // validate everything first so a refused batch changes nothing
  const pend = { ptPacks: new Map(), ptSess: new Map() };
  const cur = c => { const m = new Map((s[c] || []).map(x => [x.id, x])); pend[c].forEach((v, k) => { if (v) m.set(k, v); else m.delete(k); }); return [...m.values()]; };
  for (const op of ops) {
    if (!op || typeof op !== 'object') throw httpErr(400, 'طلب غير صالح');
    if (op.c === 'meta') { if (META_KEYS.indexOf(op.k) < 0 || OFFICE.indexOf(p.role) < 0) throw httpErr(403, 'غير مسموح'); continue; }
    if (op.c === 'settings') { if (p.role !== 'manager' || !op.v || typeof op.v !== 'object') throw httpErr(403, 'الإعدادات للمدير فقط'); continue; }
    if (COLS.indexOf(op.c) < 0) throw httpErr(400, 'نوع بيانات غير معروف');
    const id = op.op === 'put' ? op.v && op.v.id : op.id;
    if (typeof id !== 'string' || !id || id.length > 80) throw httpErr(400, 'معرّف غير صالح');
    if (op.op !== 'put' && op.op !== 'del') throw httpErr(400, 'عملية غير معروفة');
    const i = mapOf(op.c).get(id), old = i === undefined ? null : s[op.c][i];
    if (!canWrite(p, op.c, old, op.op === 'put' ? op.v : null)) throw httpErr(403, 'لا تملك صلاحية تعديل هذه البيانات');
    if (op.c === 'periods' && p.role !== 'manager') throw httpErr(403, 'إقفال الفترات وإعادة فتحها للمدير فقط');
    if (op.c === 'comms' && p.role !== 'manager') throw httpErr(403, 'اعتماد العمولات للمدير فقط');
    if (op.c === 'jrnl' && op.op === 'put') { const L = op.v.lines || []; const d = L.reduce((a, x) => a + (+x.dr || 0), 0), cr = L.reduce((a, x) => a + (+x.cr || 0), 0); if (op.v.status === 'posted' && (Math.abs(d - cr) > 0.005 || d <= 0)) throw httpErr(400, 'القيد غير متوازن: مجموع المدين يجب أن يساوي مجموع الدائن'); }
    lockCheck(s, op, old);
    if (op.c === 'posts' && op.op === 'put') { cleanPost(op.v); if (op.v.status === 'published' && (!old || old.status !== 'published' || !old.pubAt) && !op.v.pubAt) op.v.pubAt = new Date().toISOString(); }
    if (op.op === 'put' && op.c === 'book' && !old) {
      const v = op.v, cls = (s.classes || []).find(x => x.id === v.classId), taken = (s.book || []).filter(b => b.classId === v.classId && b.date === v.date);
      if (taken.some(b => b.memberId === v.memberId)) throw httpErr(409, 'محجوز مسبقاً في هذه الحصة');
      if (!v.wait && cls && cls.cap && taken.filter(b => !b.wait).length >= cls.cap) throw httpErr(409, 'اكتمل عدد المقاعد في هذه الحصة، يمكنك الانضمام لقائمة الانتظار');
    }
    if (op.c === 'ptPacks' && op.op === 'put') {
      const v = op.v, oa = (old && old.adj) || [], na = v.adj || [], ot = (old && old.topups) || [], nt = v.topups || [];
      if (na.length < oa.length || nt.length < ot.length) throw httpErr(403, 'لا يمكن حذف حركات الرصيد المسجلة');
      if (na.length > oa.length && !approved(p)) throw httpErr(403, 'إضافة أو خصم الجلسات يدوياً يحتاج موافقة المدير');
      if (nt.slice(ot.length).some(t => !t.subId) && !approved(p)) throw httpErr(403, 'إضافة رصيد بدون فاتورة تحتاج موافقة المدير');
      if (na.slice(oa.length).some(a => !String(a.reason || '').trim())) throw httpErr(400, 'اكتب سبب التعديل');
    }
    if (op.c === 'ptSess' && op.op === 'put') {
      const v = op.v;
      if (v.units != null && [0.5, 1].indexOf(+v.units) < 0) throw httpErr(400, 'قيمة الخصم غير صالحة');
      if (old && old.charged && !v.charged && !approved(p)) throw httpErr(403, 'استرجاع جلسة مخصومة يحتاج موافقة المدير');
      if (v.status === 'booked') {
        const sess = cur('ptSess').filter(x => x.id !== v.id), k = cur('ptPacks').find(x => x.id === v.packId);
        if (!old || old.status !== 'booked' || old.packId !== v.packId) {
          if (!k) throw httpErr(409, 'الباقة غير موجودة');
          if (k.status === 'cancelled') throw httpErr(409, 'الباقة ملغاة');
          const left = packTot(k) - packUse(k, sess) - sess.filter(x => x.packId === k.id && x.status === 'booked').length;
          if (left < 1) throw httpErr(409, 'نفد رصيد الباقة، لا يمكن حجز جلسة جديدة');
        }
        if (k && k.expires && v.date > k.expires) throw httpErr(409, 'موعد الجلسة بعد انتهاء صلاحية الباقة');
        const a0 = mins(v.time), a1 = a0 + (+v.dur || 60);
        const clash = sess.find(x => x.date === v.date && (x.status === 'booked' || x.status === 'done') && (x.trainerId === v.trainerId || x.memberId === v.memberId) && mins(x.time) < a1 && a0 < mins(x.time) + (+x.dur || 60)
          && !(x.memberId !== v.memberId && GRP(x) && GRP(v) && x.time === v.time && ((x.kind === 'class' && v.kind === 'class' && x.classId === v.classId) || (x.kind !== 'class' && v.kind !== 'class' && (x.service || '') === (v.service || '')))));
        if (clash) throw httpErr(409, clash.trainerId === v.trainerId ? 'المدرب لديه جلسة أخرى في هذا الوقت' : 'المتدرب لديه جلسة أخرى في هذا الوقت');
        if (GRP(v) && v.kind !== 'class') {
          const n = sess.filter(x => x.date === v.date && x.time === v.time && x.trainerId === v.trainerId && x.status === 'booked').length;
          if (n >= (+v.cap || (v.fmt === 'pair' ? 2 : 4))) throw httpErr(409, 'اكتمل عدد المشاركين في هذه الجلسة');
        }
      }
    }
    if (op.c === 'ptPacks' || op.c === 'ptSess') pend[op.c].set(id, op.op === 'put' ? op.v : null);
  }
  for (const op of ops) {
    if (op.c === 'meta') { s[op.k] = Math.max(s[op.k] || 0, +op.v || 0); continue; }
    if (op.c === 'settings') {
      const v = Object.assign({}, op.v);
      if (p.role !== 'manager') v.pin = (s.settings || {}).pin;
      auditSettings(p, s.settings, v);
      s.settings = v; logged.push({ c: 'settings', op: 'set', v: s.settings }); continue;
    }
    const arr = s[op.c], m = mapOf(op.c);
    if (op.op === 'put') {
      const v = op.v, i = m.get(v.id), old = i === undefined ? null : arr[i];
      if (STAMP.indexOf(op.c) >= 0) {
        if (old && old.by) { v.by = old.by; v.byName = old.byName; v.at = old.at; }
        else if (!old) { v.by = p.key; v.byName = p.name; v.at = new Date().toISOString(); }
      }
      if (op.c === 'ptSess' && old) {
        if (p.role === 'reception') PT_PRIVATE.forEach(k => { if (old[k] !== undefined) v[k] = old[k]; else delete v[k]; });
        if (p.role === 'trainee') {
          const set = s.settings || {}, late = sessHoursAway(old) < (+(old.kind === 'class' ? set.classCancelHours : set.ptCancelHours) || 0);
          Object.keys(v).forEach(k => delete v[k]); Object.assign(v, old);
          v.status = late ? 'late_cancel' : 'cancelled'; v.charged = late ? set.ptLateCharge !== false : false; v.cancelledBy = 'member'; v.cancelledAt = new Date().toISOString();
        }
      }
      if (op.c === 'fb' && !old && p.role === 'trainee') {
        const mm = (s.members || []).find(x => x.id === p.ref) || {};
        Object.assign(v, { memberId: p.ref, name: mm.name || '', phone: mm.phone || '', code: mm.code || '', status: 'new', reply: '', at: new Date().toISOString() });
        v.text = String(v.text || '').trim().slice(0, 2000); v.cat = String(v.cat || '').slice(0, 40);
      }
      auditOp(p, op.c, 'put', old, v);
      hooks.push([op.c, old, v]);
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
      if (i !== undefined) auditOp(p, op.c, 'del', arr[i], null);
      const gone = i !== undefined ? arr[i] : null;
      if (i !== undefined) { arr.splice(i, 1); maps[op.c] = null; logged.push({ c: op.c, op: 'del', id: op.id }); }
      if (op.c === 'book' && gone && !gone.wait) {
        const w = arr.filter(b => b.wait && b.classId === gone.classId && b.date === gone.date).sort((a, b) => String(a.at || a.id).localeCompare(String(b.at || b.id)))[0];
        if (w) { w.wait = false; w.promotedAt = new Date().toISOString(); logged.push({ c: 'book', op: 'put', v: w }); hooks.push(['promote', null, w]); audit(null, 'ترقية من قائمة الانتظار', mName(w.memberId) + ' · ' + w.date, 'book', w.id); }
      }
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
  try { pushHooks(p, hooks); } catch (e) { console.error('push hook', e.message); }
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

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json', '.json': 'application/json', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml' };
const UPL = path.join(DATA, 'uploads');
function serveStatic(req, res) {
  let rel; try { rel = decodeURIComponent(new URL(req.url, 'http://x').pathname); } catch (e) { res.writeHead(400); return res.end(); }
  let base = PUB;
  if (rel.startsWith('/uploads/')) { base = UPL; rel = rel.slice(8); }
  else if (rel === '/app' || rel.startsWith('/app/')) rel = '/index.html';
  else if (rel === '/' || !path.extname(rel)) rel = '/site.html';
  const f = path.normalize(path.join(base, rel));
  if (!f.startsWith(base + path.sep)) { res.writeHead(403); return res.end(); }
  const bm = /^\/blog(?:\/([A-Za-z0-9_-]{1,80}))?\/?$/.exec(decodeURIComponent(new URL(req.url, 'http://x').pathname));
  if (bm && rel === '/site.html') {
    const post = bm[1] ? livePosts(st(), 'site').find(x => x.id === bm[1]) : null;
    return fs.readFile(f, 'utf8', (err, html) => {
      if (err) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'Content-Type': MIME['.html'], 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin' });
      res.end(blogMeta(html, req, post));
    });
  }
  fs.readFile(f, (err, buf) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'Cache-Control': /\.html$|sw\.js$/.test(rel) ? 'no-cache' : base === UPL ? 'public, max-age=31536000, immutable' : 'public, max-age=86400', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin' });
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
      const m = (st().members || []).find(x => (x.uname && String(x.uname).toLowerCase() === u) || String(x.code || '').toLowerCase() === u), cm = m && db.creds['m:' + m.id];
      if (cm && checkPw(pw, cm.hash)) tok = { k: 'm', id: m.id, pv: cm.pv || 0 };
    }
    if (!tok) throw httpErr(401, 'اسم المستخدم أو رقم الجوال أو كلمة المرور غير صحيحة');
    tok.exp = Date.now() + 30 * 86400e3;
    const who = principal(tok);
    return send(res, 200, { role: who.role, ref: who.ref, name: who.name, key: who.key, rev: db.rev }, { 'Set-Cookie': sessCookie(req, sign(tok), 30 * 86400) });
  }
  if (route === 'site' && method === 'GET') {
    const s = st(), set = s.settings || {}, tn = id => { const t = (s.trainers || []).find(x => x.id === id); return t ? t.name : ''; };
    return send(res, 200, {
      gym: set.gym || 'جولة اللياقة', phone: set.phone || '', address: set.address || '', legalName: set.legalName || '', crNo: set.crNo || '', vatNo: set.vatNo || '',
      site: set.site || {},
      plans: (s.plans || []).filter(x => !x.archived && !x.hidden).map(x => pick(x, ['id', 'name', 'days', 'price'])),
      ptPlans: (s.ptPlans || []).filter(x => !x.archived).map(x => pick(x, ['id', 'name', 'sessions', 'validDays', 'price', 'service', 'fmt'])),
      classes: (s.classes || []).map(x => ({ id: x.id, name: x.name, days: x.days || [], time: x.time, dur: x.dur, trainer: tn(x.trainerId) })),
      trainers: (s.trainers || []).filter(x => !x.hidden).map(x => pick(x, ['id', 'name', 'spec'])),
      posts: livePosts(s, 'site').slice(0, 3).map(x => pick(x, POST_PUB))
    }, { 'Cache-Control': 'public, max-age=60' });
  }
  if (route === 'posts' && method === 'GET') {
    return send(res, 200, { posts: livePosts(st(), 'site').map(x => pick(x, POST_PUB)) }, { 'Cache-Control': 'public, max-age=60' });
  }
  if (route === 'post' && method === 'GET') {
    const id = new URL(req.url, 'http://x').searchParams.get('id') || '';
    const x = (st().posts || []).find(y => y.id === id);
    const ok = x && (x.status === 'published' && x.site !== false || (p && p.role === 'manager'));
    if (!ok) throw httpErr(404, 'المقال غير موجود');
    const more = livePosts(st(), 'site').filter(y => y.id !== id).slice(0, 3).map(y => pick(y, POST_PUB));
    return send(res, 200, { post: pick(x, POST_PUB.concat(['blocks', 'status'])), more }, { 'Cache-Control': x.status === 'published' ? 'public, max-age=60' : 'no-store' });
  }
  if (route === 'lead' && method === 'POST') {
    if (limited('lead:' + clientIp(req), 6, 3600e3)) throw httpErr(429, 'أرسلت طلبات كثيرة. حاول لاحقاً أو تواصل معنا على واتساب');
    const b = await readBody(req, 4096);
    const clean = (x, n) => String(x || '').replace(/[<>\u0000-\u001f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, n);
    if (b.website) return send(res, 200, { ok: true });
    const name = clean(b.name, 60), phone = String(b.phone || '').replace(/\D/g, '');
    if (name.length < 2) throw httpErr(400, 'اكتب اسمك');
    if (!/^05\d{8}$/.test(phone)) throw httpErr(400, 'رقم الجوال غير صحيح');
    const s = st(); s.leads = s.leads || [];
    const today = new Date(Date.now() + 3 * 3600e3).toISOString().slice(0, 10);
    const interest = clean(b.interest, 80), time = clean(b.time, 30), note = clean(b.note, 300);
    const plan = (s.plans || []).find(x => interest === 'باقة ' + x.name);
    const txt = ['طلب من الموقع: ' + (interest || 'زيارة تجريبية'), time ? 'الوقت المناسب: ' + time : '', note, b.consent ? 'وافق على التواصل' : 'لم يوافق على الرسائل التسويقية'].filter(Boolean).join(' · ');
    let l = s.leads.find(x => x.phone === phone && x.status !== 'won' && x.status !== 'lost');
    if (l) { l.log = l.log || []; l.log.push({ date: today, note: txt, st: l.status }); l.next = today; }
    else {
      l = { id: 'l' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex'), name, phone, source: 'الموقع الإلكتروني', planId: plan ? plan.id : '', status: 'new', next: today, notes: txt, created: today, log: [], web: true, consent: !!b.consent };
      s.leads.push(l);
    }
    db.rev++; changeLog.push({ rev: db.rev, c: 'leads', op: 'put', v: l });
    if (changeLog.length > LOG_MAX) changeLog = changeLog.slice(-LOG_MAX);
    persist();
    return send(res, 200, { ok: true });
  }
  if (route === 'upload' && method === 'POST') {
    need(['manager']);
    const b = await readBody(req, 7.2e6), mt = /^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/=]+)$/.exec(String(b.data || ''));
    if (!mt) throw httpErr(400, 'الصورة يجب أن تكون PNG أو JPG أو WEBP');
    const buf = Buffer.from(mt[2], 'base64');
    if (buf.length > 5e6) throw httpErr(413, 'حجم الصورة أكبر من 5 ميغابايت');
    fs.mkdirSync(UPL, { recursive: true });
    const name = Date.now().toString(36) + crypto.randomBytes(6).toString('hex') + '.' + (mt[1] === 'jpeg' ? 'jpg' : mt[1]);
    fs.writeFileSync(path.join(UPL, name), buf);
    audit(p, 'رفع صورة للموقع', name, 'site'); persist();
    return send(res, 200, { url: '/uploads/' + name });
  }
  if (route === 'push/key') { need(); return send(res, 200, { key: db.vapid.pub }); }
  if (route === 'push/sub' && method === 'POST') {
    need(); const b = await readBody(req, 4096), sub = b.sub || {};
    if (!/^https:\/\//.test(String(sub.endpoint || '')) || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) throw httpErr(400, 'اشتراك إشعارات غير صالح');
    db.push = db.push.filter(x => x.sub.endpoint !== sub.endpoint);
    db.push.push({ pk: p.key, sub: { endpoint: sub.endpoint, keys: { p256dh: String(sub.keys.p256dh), auth: String(sub.keys.auth) } }, at: new Date().toISOString(), ua: String(req.headers['user-agent'] || '').slice(0, 120) });
    const mine = db.push.filter(x => x.pk === p.key); if (mine.length > 5) db.push = db.push.filter(x => x.pk !== p.key || mine.slice(-5).indexOf(x) >= 0);
    persist(); return send(res, 200, { ok: true });
  }
  if (route === 'push/unsub' && method === 'POST') { need(); const b = await readBody(req, 4096); db.push = db.push.filter(x => !(x.pk === p.key && x.sub.endpoint === b.endpoint)); persist(); return send(res, 200, { ok: true }); }
  if (route === 'push/test' && method === 'POST') { need(); if (limited('pt:' + p.key, 5, 3600e3)) throw httpErr(429, 'حاول لاحقاً'); await notify([p.key], { title: 'الإشعارات تعمل ✓', body: 'ستصلك تذكيرات المواعيد والردود من ' + ((st().settings || {}).gym || 'النادي'), url: '/app', tag: 'test' }); return send(res, 200, { ok: true, n: db.push.filter(x => x.pk === p.key).length }); }
  if (route === 'logout' && method === 'POST') return send(res, 200, { ok: true }, { 'Set-Cookie': sessCookie(req, '', 0) });
  if (route === 'me') { need(); return send(res, 200, { role: p.role, ref: p.ref, name: p.name, key: p.key, rev: db.rev }); }
  if (route === 'rev') { need(); return send(res, 200, { rev: db.rev }); }
  if (route === 'state') { need(); return send(res, 200, { rev: db.rev, state: viewFor(p), warn: NO_DISK && p.role === 'manager' ? 'لا يوجد قرص دائم مربوط بالخادم، وستُحذف البيانات عند أي تحديث. اربط Volume بالخدمة من لوحة الاستضافة قبل إدخال بيانات حقيقية.' : '' }); }
  if (route === 'changes') {
    need(OFFICE);
    const since = +new URL(req.url, 'http://x').searchParams.get('since') || 0;
    if (!changeLog.length || since < changeLog[0].rev - 1) return send(res, 200, { full: true, rev: db.rev });
    let ch = changeLog.filter(e => e.rev > since);
    if (p.role !== 'manager') {
      const hide = HIDDEN[p.role] || [];
      ch = ch.filter(e => hide.indexOf(e.c) < 0).map(e => {
        if (e.c === 'settings') return Object.assign({}, e, { v: Object.assign({}, e.v, { pin: undefined }) });
        if (p.role === 'accountant' && e.c === 'members' && e.v) return Object.assign({}, e, { v: pick(e.v, ['id', 'code', 'name', 'phone', 'gender', 'trainerId', 'joined']) });
        if (e.c === 'ptSess' && e.v) return Object.assign({}, e, { v: stripPt(e.v) });
        return e;
      });
    }
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
    const who = kind === 't' ? (findTrainer(b.id) || {}).name : (findMember(b.id) || {}).name;
    if (old) audit(p, kind === 't' ? 'كلمة مرور جديدة لمدرب' : 'كلمة مرور جديدة لعضو', who || '', 'creds', b.id);
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
    const b = await readBody(req, 1024), want = String((st().settings || {}).pin || '1234'), ok = String(b.pin || '') === want;
    if (ok && p.role !== 'manager') { elev.set(p.key, Date.now() + 10 * 60e3); audit(p, 'موافقة المدير برمز المدير', String(b.why || '').slice(0, 120), 'settings'); persist(); }
    return send(res, 200, { ok });
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
      const role = ['manager', 'accountant'].indexOf(b.role) >= 0 ? b.role : 'reception';
      db.users.push({ id: 'u' + crypto.randomBytes(6).toString('hex'), username: un, name: String(b.name || un).slice(0, 60), role, hash: hashPw(pw), pv: 1 });
      audit(p, 'إنشاء حساب موظف', String(b.name || un) + ' · ' + un + ' · ' + ({ manager: 'مدير', accountant: 'محاسبة', reception: 'استقبال' })[role], 'users');
    } else if (b.action === 'delete') {
      if (b.id === 'admin') throw httpErr(400, 'لا يمكن حذف حساب المدير الرئيسي');
      const gone = db.users.find(u => u.id === b.id);
      db.users = db.users.filter(u => u.id !== b.id);
      if (gone) audit(p, 'حذف حساب موظف', gone.name + ' · ' + gone.username, 'users');
    } else if (b.action === 'password') {
      const u = db.users.find(x => x.id === b.id), pw = String(b.password || '');
      if (!u) throw httpErr(404, 'الحساب غير موجود');
      if (u.id === 'admin') throw httpErr(400, 'كلمة مرور المدير الرئيسي تُغيَّر من متغير ADMIN_PASSWORD في الاستضافة');
      if (pw.length < 6) throw httpErr(400, 'كلمة المرور 6 أحرف على الأقل');
      u.hash = hashPw(pw); u.pv = (u.pv || 0) + 1;
      audit(p, 'تغيير كلمة مرور موظف', u.name + ' · ' + u.username, 'users');
    } else throw httpErr(400, 'طلب غير صالح');
    persist();
    return send(res, 200, { ok: true });
  }
  if (route === 'audit') {
    need(['manager']);
    const lim = Math.min(5000, +new URL(req.url, 'http://x').searchParams.get('limit') || 1000);
    return send(res, 200, { total: db.audit.length, items: db.audit.slice(-lim).reverse() });
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
/* ---------------- push notifications ---------------- */
const PUSH_SUB = process.env.RAILWAY_PUBLIC_DOMAIN ? 'https://' + process.env.RAILWAY_PUBLIC_DOMAIN : 'mailto:admin@roundfitness.app';
async function notify(keys, data) {
  keys = [...new Set(keys.filter(Boolean))];
  const subs = db.push.filter(x => keys.indexOf(x.pk) >= 0);
  let gone = false;
  await Promise.all(subs.map(async x => { const code = await Push.send(x.sub, data, db.vapid, PUSH_SUB); if (code === 404 || code === 410) { x.dead = true; gone = true; } }));
  if (gone) { db.push = db.push.filter(x => !x.dead); persist(); }
}
const managerKeys = () => db.users.filter(u => u.role === 'manager').map(u => 'u:' + u.id);
const fmtT = t => { const a = String(t || '0:0').split(':').map(Number); return ((a[0] % 12) || 12) + ':' + String(a[1]).padStart(2, '0') + (a[0] < 12 ? ' ص' : ' م'); };
function pushHooks(p, hooks) {
  hooks.forEach(([c, old, v]) => {
    if (!v) return;
    if (c === 'posts' && v.status === 'published' && v.notify && v.app !== false && (!old || old.status !== 'published') && !db.pushSent['post' + v.id] && (!v.pubAt || v.pubAt <= new Date().toISOString())) { db.pushSent['post' + v.id] = Date.now() + 365 * 864e5; persist(); notify([...new Set(db.push.map(x => x.pk).filter(k => /^[mt]:/.test(k)))], { title: 'مقال جديد في المدونة', body: v.title, url: '/app#news', tag: 'post-' + v.id }); }
    if (c === 'fb' && !old) notify(managerKeys(), { title: v.type === 'complaint' ? 'شكوى جديدة' : 'اقتراح جديد', body: (v.name || '') + ' · ' + (v.cat || ''), url: '/app#feedback', tag: 'fb' });
    if (c === 'fb' && old && v.reply && v.reply !== old.reply) notify(['m:' + v.memberId], { title: 'تم الرد على ' + (v.type === 'complaint' ? 'شكواك' : 'اقتراحك'), body: String(v.reply).slice(0, 140), url: '/app#home', tag: 'fb-' + v.id });
    if (c === 'treq' && !old) notify(managerKeys(), { title: 'طلب جديد من مدربة', body: mTr(v.trainerId) + ' · ' + ({ leave: 'إجازة', avail: 'تعديل أوقات العمل', fix: 'تصحيح رصيد' })[v.type], url: '/app#coach', tag: 'treq' });
    if (c === 'treq' && old && old.status !== v.status) notify(['t:' + v.trainerId], { title: v.status === 'approved' ? 'اعتُمد طلبك' : 'رُفض طلبك', body: ({ leave: 'طلب الإجازة', avail: 'تعديل أوقات العمل', fix: 'تصحيح الرصيد' })[v.type] + (v.reply ? ' · ' + v.reply : ''), url: '/app#coach', tag: 'treq-' + v.id });
    if (c === 'promote') { const cl = (st().classes || []).find(x => x.id === v.classId); notify(['m:' + v.memberId], { title: 'توفر لك مقعد', body: 'انتقلتِ من قائمة الانتظار إلى ' + (cl ? cl.name : 'الحصة') + ' · ' + v.date, url: '/app#home', tag: 'bk-' + v.id }); }
    if (c === 'ptSess' && old && old.status === 'booked') {
      if (v.status === 'club_cancel') notify(['m:' + v.memberId], { title: 'أُلغيت جلستك من النادي', body: v.date + ' · ' + fmtT(v.time) + ' · أُعيدت الجلسة لرصيدك', url: '/app#home', tag: 'ps-' + v.id });
      if (v.status === 'booked' && (old.date !== v.date || old.time !== v.time)) { const to = p.role === 'trainee' ? [] : ['m:' + v.memberId]; if (p.role !== 'trainer') to.push('t:' + v.trainerId); notify(to, { title: 'تغيّر موعد الجلسة', body: v.date + ' · ' + fmtT(v.time), url: '/app', tag: 'ps-' + v.id }); }
    }
  });
}
function reminderTick() {
  const s = st(), now = Date.now(), off = (s.settings || {}).tzOffset || '+03:00', due = [];
  const win = at => at - now > 45 * 60e3 && at - now <= 75 * 60e3;
  (s.book || []).forEach(b => { if (b.wait) return; const c = (s.classes || []).find(x => x.id === b.classId); if (!c) return; const at = Date.parse(b.date + 'T' + c.time + ':00' + off); if (win(at)) due.push({ id: 'b' + b.id + b.date, keys: ['m:' + b.memberId], title: 'حصتك بعد ساعة', body: c.name + ' · ' + fmtT(c.time) }); });
  (s.ptSess || []).forEach(x => { if (x.status !== 'booked' || x.kind === 'class') return; const at = Date.parse(x.date + 'T' + x.time + ':00' + off); if (win(at)) { due.push({ id: 'p' + x.id + x.date + x.time, keys: ['m:' + x.memberId], title: 'جلستك بعد ساعة', body: 'تدريب شخصي · ' + fmtT(x.time) + ' · ' + mTr(x.trainerId) }); due.push({ id: 'pt' + x.id + x.date + x.time, keys: ['t:' + x.trainerId], title: 'جلسة بعد ساعة', body: mName(x.memberId) + ' · ' + fmtT(x.time) }); } });
  let changed = false;
  due.forEach(d => { if (db.pushSent[d.id]) return; db.pushSent[d.id] = now; changed = true; notify(d.keys, { title: d.title, body: d.body, url: '/app#home', tag: d.id }); });
  Object.keys(db.pushSent).forEach(k => { if (now - db.pushSent[k] > 2 * 864e5) { delete db.pushSent[k]; changed = true; } });
  if (changed) persist();
}
setInterval(() => { try { reminderTick(); } catch (e) { console.error('reminders', e.message); } }, +process.env.REMINDER_MS || 5 * 60e3).unref();

server.listen(PORT, () => console.log('نظام جولة اللياقة يعمل على المنفذ ' + PORT + ' · البيانات في ' + DATA));
