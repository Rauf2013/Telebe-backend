import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import { randomUUID } from 'crypto';
import { join, dirname, extname } from 'path';
import { fileURLToPath } from 'url';
import { users, applications, notifications, invites, events, passwordResets, phoneVerifications, stats } from './db.js';
import { sendPasswordResetLink, sendUniInviteLink, sendSmsOtp } from './mailer.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'edugate-dev-secret-change-in-prod';

app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use('/uploads', express.static(join(__dirname, 'uploads')));

/* ---------- multer (file uploads) ---------- */
const storage = multer.diskStorage({
  destination: join(__dirname, 'uploads'),
  filename: (_req, file, cb) => cb(null, `${randomUUID()}${extname(file.originalname)}`),
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

/* ---------- auth helpers ---------- */
function publicUser(u) {
  if (!u) return null;
  const { password: _pw, ...rest } = u;
  return rest;
}

function sign(user) {
  return jwt.sign(publicUser(user), JWT_SECRET, { expiresIn: '7d' });
}

function authRequired(roles = []) {
  return (req, res, next) => {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'no_token' });
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      if (roles.length && !roles.includes(payload.role)) return res.status(403).json({ error: 'forbidden' });
      req.user = payload;
      next();
    } catch {
      res.status(401).json({ error: 'invalid_token' });
    }
  };
}

/* ---------- AUTH ---------- */
// Step 1: Student fills the form → backend stores pending registration + sends SMS OTP.
//         Existing email + already-pending-phone collisions are caught here.
//         University-rep accounts are NOT created here — they come via /invites/:token/accept.
app.post('/api/auth/register', async (req, res) => {
  const { email, password, fullName, phone, whatsapp, country, city } = req.body || {};
  if (!email || !password || !fullName || !phone || !country || !city) {
    return res.status(400).json({ error: 'missing_fields' });
  }
  if (password.length < 6) return res.status(400).json({ error: 'weak_password' });
  if (users.findByEmail(email)) return res.status(409).json({ error: 'email_exists' });

  const hash = await bcrypt.hash(password, 10);
  const code = String(Math.floor(100000 + Math.random() * 900000));

  phoneVerifications.upsert({
    phone,
    code,
    payload: {
      email: String(email).toLowerCase().trim(),
      fullName: String(fullName).trim(),
      password: hash,
      role: 'student',
      phone,
      whatsapp: whatsapp || null,
      country,
      city,
    },
  });
  try { await sendSmsOtp(phone, code); } catch (e) { console.error('SMS send failed:', e.message); }

  // We never echo the code in the response. In dev it's printed to the server console.
  res.json({ ok: true, requiresOtp: true, phone });
});

// Step 2: Student enters the 6-digit code → we verify, materialize the user, return a token.
app.post('/api/auth/verify-otp', async (req, res) => {
  const { phone, code } = req.body || {};
  if (!phone || !code) return res.status(400).json({ error: 'missing_fields' });

  const v = phoneVerifications.find(phone);
  if (!v) return res.status(400).json({ error: 'invalid_code' });
  if (new Date(v.expiresAt) < new Date()) {
    phoneVerifications.consume(phone);
    return res.status(400).json({ error: 'expired_code' });
  }
  if (v.attempts >= 5) {
    phoneVerifications.consume(phone);
    return res.status(429).json({ error: 'too_many_attempts' });
  }
  const submitted = String(code).replace(/\s+/g, '').trim();
  if (v.code !== submitted) {
    phoneVerifications.incrementAttempts(phone);
    return res.status(400).json({ error: 'invalid_code' });
  }

  // Race-safety: email might have been claimed between step 1 and step 2.
  if (users.findByEmail(v.payload.email)) {
    phoneVerifications.consume(phone);
    return res.status(409).json({ error: 'email_exists' });
  }

  const created = users.create({
    id: randomUUID(),
    email: v.payload.email,
    password: v.payload.password,
    fullName: v.payload.fullName,
    role: 'student',
    phone: v.payload.phone,
    whatsapp: v.payload.whatsapp ?? null,
    country: v.payload.country,
    city: v.payload.city,
    createdAt: new Date().toISOString(),
  });
  users.markPhoneVerified(created.id);
  // Re-read so the response (and the JWT) reflect the verified flag.
  const user = users.findById(created.id);
  // Email verification will happen separately later if/when we add an email step for students;
  // for now we leave it false so a future flow can flip it.
  phoneVerifications.consume(phone);
  res.json({ user: publicUser(user), token: sign(user) });
});

// Optional: re-send OTP if the user lost the SMS.
app.post('/api/auth/resend-otp', async (req, res) => {
  const { phone } = req.body || {};
  if (!phone) return res.status(400).json({ error: 'missing_fields' });
  const v = phoneVerifications.find(phone);
  if (!v) return res.status(404).json({ error: 'no_pending_registration' });
  const code = String(Math.floor(100000 + Math.random() * 900000));
  phoneVerifications.upsert({ phone, code, payload: v.payload });
  try { await sendSmsOtp(phone, code); } catch (e) { console.error('SMS send failed:', e.message); }
  res.json({ ok: true });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = users.findByEmail(email || '');
  if (!user) return res.status(401).json({ error: 'invalid_credentials' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' });
  res.json({ user: publicUser(user), token: sign(user) });
});

app.get('/api/auth/me', authRequired(), (req, res) => {
  const user = users.findById(req.user.id);
  res.json({ user: publicUser(user) });
});

/* ---------- PASSWORD RESET (link-based) ----------
   1) Client posts an email → we email a one-time link with a long random token.
   2) User clicks the link → frontend hits /verify-reset-token to render the form
      only if the token is still valid (not expired, not used).
   3) User submits a new password → /reset-password consumes the token and updates.
   No 6-digit codes anywhere — losing the email = restart the flow.
--------------------------------------------------------- */

// Long URL-safe random token. 48 hex chars = 192 bits of entropy — way more than enough.
function makeResetToken() {
  const bytes = new Uint8Array(24);
  (globalThis.crypto || require('crypto').webcrypto).getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

// 1) Send reset link via email. We never confirm whether the email exists.
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'missing_email' });

  const user = users.findByEmail(email);
  if (user) {
    const token = makeResetToken();
    passwordResets.upsert({ email: user.email, userId: user.id, token });
    // The link points at the frontend, not the API. APP_URL or FRONTEND_URL can override
    // the default of localhost:5173 (e.g. when running behind a tunnel or in production).
    const origin = (process.env.APP_URL || process.env.FRONTEND_URL || `${req.protocol}://${req.get('host').replace(/:\d+$/, ':5173')}`).replace(/\/$/, '');
    const link = `${origin}/reset-password/${token}`;
    try { await sendPasswordResetLink(user.email, user.fullName, link); }
    catch (err) { console.error('Reset mail failed:', err.message); }
  }
  res.json({ ok: true });
});

// 2) GET /verify-reset-token/:token — read-only check used by the page to decide
//    whether to render the password form or an "expired" message.
app.get('/api/auth/verify-reset-token/:token', (req, res) => {
  const reset = passwordResets.findByToken(req.params.token);
  if (!reset) return res.status(404).json({ error: 'invalid_token' });
  if (new Date(reset.expiresAt) < new Date()) {
    passwordResets.consume(reset.token);
    return res.status(410).json({ error: 'expired_token' });
  }
  // We hide the full email — only return the masked version for a friendly UX.
  const masked = reset.email.replace(/^(.).+(@.+)$/, (_m, first, dom) => `${first}***${dom}`);
  res.json({ ok: true, email: masked, expiresAt: reset.expiresAt });
});

// 3) Submit new password using the token from the URL. One-time use.
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body || {};
  if (!token || !newPassword) return res.status(400).json({ error: 'missing_fields' });
  if (newPassword.length < 6)  return res.status(400).json({ error: 'weak_password' });

  const reset = passwordResets.findByToken(token);
  if (!reset) return res.status(404).json({ error: 'invalid_token' });
  if (new Date(reset.expiresAt) < new Date()) {
    passwordResets.consume(reset.token);
    return res.status(410).json({ error: 'expired_token' });
  }
  const hash = await bcrypt.hash(newPassword, 10);
  users.updatePassword(reset.userId, hash);
  passwordResets.consume(reset.token);

  res.json({ ok: true });
});

app.patch('/api/auth/me', authRequired(), (req, res) => {
  const { fullName, phone, whatsapp, country, city } = req.body || {};
  if (!fullName) return res.status(400).json({ error: 'missing_fields' });
  const user = users.updateProfile(req.user.id, { fullName, phone, whatsapp, country, city });
  res.json({ user: publicUser(user), token: sign(user) });
});

app.post('/api/auth/password', authRequired(), async (req, res) => {
  const { current, next } = req.body || {};
  if (!current || !next || next.length < 6) return res.status(400).json({ error: 'invalid_input' });
  const user = users.findById(req.user.id);
  const ok = await bcrypt.compare(current, user.password);
  if (!ok) return res.status(401).json({ error: 'wrong_password' });
  users.updatePassword(req.user.id, await bcrypt.hash(next, 10));
  res.json({ ok: true });
});

/* ---------- NOTIFICATIONS ---------- */
function notify(userId, type, title, message, link) {
  notifications.create({ id: randomUUID(), userId, type, title, message, link });
}

/* ---------- EVENT LOG helper ---------- */
function logEvent(applicationId, actor, type, message) {
  events.create({
    applicationId,
    actorId: actor?.id,
    actorRole: actor?.role,
    type, message,
  });
}

app.get('/api/notifications', authRequired(), (req, res) => {
  res.json({
    notifications: notifications.listByUser(req.user.id),
    unread: notifications.unreadCount(req.user.id),
  });
});

app.post('/api/notifications/:id/read', authRequired(), (req, res) => {
  notifications.markRead(req.params.id, req.user.id);
  res.json({ ok: true });
});

app.post('/api/notifications/read-all', authRequired(), (req, res) => {
  notifications.markAllRead(req.user.id);
  res.json({ ok: true });
});

/* ---------- USERS ---------- */
app.get('/api/users/:id', authRequired(), (req, res) => {
  const user = users.findById(req.params.id);
  if (!user) return res.status(404).json({ error: 'not_found' });
  res.json({ user: publicUser(user) });
});

app.get('/api/users', authRequired(['moderator', 'university']), (_req, res) => {
  res.json({ users: users.list().map(publicUser) });
});

/* ---------- ADMIN: Moderator yönetimi ---------- */
app.get('/api/admin/moderators', authRequired(['moderator']), (_req, res) => {
  const list = users.list().filter(u => u.role === 'moderator').map(publicUser);
  res.json({ moderators: list });
});

app.post('/api/admin/moderators', authRequired(['moderator']), async (req, res) => {
  const { email, password, fullName, phone } = req.body || {};
  if (!email || !password || !fullName) return res.status(400).json({ error: 'missing_fields' });
  if (password.length < 6) return res.status(400).json({ error: 'weak_password' });
  if (users.findByEmail(email)) return res.status(409).json({ error: 'email_exists' });

  const hash = await bcrypt.hash(password, 10);
  const user = users.create({
    id: randomUUID(),
    email, password: hash, fullName, role: 'moderator', phone,
    createdAt: new Date().toISOString(),
  });
  users.markEmailVerified(user.id);
  res.json({ moderator: publicUser(users.findById(user.id)) });
});

/* ---------- INVITE SYSTEM (moderator + university representative) ---------- */
// Create moderator invite (legacy endpoint, unchanged behavior — still kind=moderator).
app.post('/api/admin/invites', authRequired(['moderator']), (req, res) => {
  const { note } = req.body || {};
  const inv = invites.create({ createdBy: req.user.id, note, kind: 'moderator' });
  res.json({ invite: inv });
});

// Create university-rep invite. Moderator picks the university + target email + name;
// we generate a one-time link and email it to the target.
app.post('/api/admin/uni-invites', authRequired(['moderator']), async (req, res) => {
  // universityName is purely cosmetic (used in the email body); the moderator UI sends it
  // because the backend has no copy of the universities catalog.
  const { targetEmail, targetName, universityId, universityName, note } = req.body || {};
  if (!targetEmail || !universityId) return res.status(400).json({ error: 'missing_fields' });

  const inv = invites.create({
    createdBy: req.user.id,
    kind: 'university',
    note,
    targetEmail: String(targetEmail).toLowerCase().trim(),
    targetName: targetName ?? null,
    universityId,
  });

  // Build the absolute link the user will click in the email. APP_URL takes priority for
  // any non-default frontend host (prod, staging, tunneled dev).
  const origin = process.env.APP_URL || `${req.protocol}://${req.get('host').replace(/:\d+$/, ':5173')}`;
  const link = `${origin.replace(/\/$/, '')}/invite/${inv.token}`;

  try { await sendUniInviteLink(targetEmail, targetName, link, universityName || universityId); }
  catch (e) { console.error('Uni invite mail failed:', e.message); }

  res.json({ invite: { ...inv, link } });
});

// Combined list (both moderator + university invites). UI filters per panel.
app.get('/api/admin/invites', authRequired(['moderator']), (req, res) => {
  const kind = req.query.kind;
  res.json({ invites: invites.listAll(kind) });
});

// Cancel/delete a moderator OR university invite (same endpoint, identified by token).
app.delete('/api/admin/invites/:token', authRequired(['moderator']), (req, res) => {
  invites.delete(req.params.token);
  res.json({ ok: true });
});

// Public: validate an invite token (used by /invite/:token page to decide what form to show).
app.get('/api/invites/:token', (req, res) => {
  const inv = invites.find(req.params.token);
  if (!inv) return res.status(404).json({ error: 'invalid_token' });
  if (inv.usedAt) return res.status(410).json({ error: 'already_used' });
  if (new Date(inv.expiresAt) < new Date()) return res.status(410).json({ error: 'expired' });
  res.json({
    ok: true,
    kind: inv.kind,
    expiresAt: inv.expiresAt,
    note: inv.note,
    targetEmail: inv.targetEmail,
    targetName: inv.targetName,
    universityId: inv.universityId,
  });
});

// Public: accept an invite — creates either a moderator OR a university-rep account.
app.post('/api/invites/:token/accept', async (req, res) => {
  const { email, password, fullName, phone, whatsapp } = req.body || {};
  if (!email || !password || !fullName) return res.status(400).json({ error: 'missing_fields' });
  if (password.length < 6) return res.status(400).json({ error: 'weak_password' });

  const inv = invites.find(req.params.token);
  if (!inv) return res.status(404).json({ error: 'invalid_token' });
  if (inv.usedAt) return res.status(410).json({ error: 'already_used' });
  if (new Date(inv.expiresAt) < new Date()) return res.status(410).json({ error: 'expired' });
  if (users.findByEmail(email)) return res.status(409).json({ error: 'email_exists' });

  const role = inv.kind === 'university' ? 'university' : 'moderator';
  // For uni invites the moderator has already chosen the target university — we trust the invite, not the body.
  const universityId = role === 'university' ? inv.universityId : null;
  if (role === 'university' && !universityId) return res.status(400).json({ error: 'missing_university' });

  const hash = await bcrypt.hash(password, 10);
  const created = users.create({
    id: randomUUID(),
    email, password: hash, fullName, role, phone, whatsapp: whatsapp ?? null,
    universityId,
    createdAt: new Date().toISOString(),
  });
  users.markEmailVerified(created.id);
  invites.consume(req.params.token, created.id);
  const user = users.findById(created.id);
  res.json({ user: publicUser(user), token: sign(user), role });
});

/* ---------- APPLICATIONS — STUDENT ---------- */
app.get('/api/applications/mine', authRequired(['student']), (req, res) => {
  res.json({ application: applications.findByStudent(req.user.id) ?? null });
});

app.post('/api/applications/choices', authRequired(['student']), (req, res) => {
  const { choices } = req.body || {};
  if (!Array.isArray(choices) || choices.length > 5) return res.status(400).json({ error: 'invalid_choices' });

  let app = applications.findByStudent(req.user.id);
  const isNew = !app;
  if (app) {
    app.choices = choices;
    app = applications.save(app);
  } else {
    app = applications.create({
      id: randomUUID(),
      studentId: req.user.id,
      status: 'draft',
      choices,
      documents: [],
      firstPaymentPaid: false,
      secondPaymentPaid: false,
      createdAt: new Date().toISOString(),
    });
  }
  logEvent(app.id, req.user, isNew ? 'created' : 'choices_updated',
    isNew ? `Müraciət yaradıldı (${choices.length} fakultə seçildi)` : `Fakultə seçimi yeniləndi (${choices.length} fakultə)`);
  res.json({ application: app });
});

app.post('/api/applications/documents', authRequired(['student']), upload.single('file'), (req, res) => {
  const { type } = req.body;
  if (!req.file || !type) return res.status(400).json({ error: 'missing_fields' });

  const app = applications.findByStudent(req.user.id);
  if (!app) return res.status(404).json({ error: 'no_application' });

  app.documents.push({
    id: randomUUID(), type,
    fileName: req.file.originalname,
    url: `/uploads/${req.file.filename}`,
    uploadedAt: new Date().toISOString(),
  });
  const saved = applications.save(app);
  logEvent(app.id, req.user, 'document_uploaded', `Sənəd yükləndi: ${type}`);
  res.json({ application: saved });
});

app.delete('/api/applications/documents/:docId', authRequired(['student']), (req, res) => {
  const app = applications.findByStudent(req.user.id);
  if (!app) return res.status(404).json({ error: 'no_application' });
  app.documents = app.documents.filter(d => d.id !== req.params.docId);
  res.json({ application: applications.save(app) });
});

app.post('/api/applications/payment/first', authRequired(['student']), (req, res) => {
  const app = applications.findByStudent(req.user.id);
  if (!app) return res.status(404).json({ error: 'no_application' });
  app.firstPaymentPaid = true;
  app.status = 'in_translation';
  const saved = applications.save(app);
  logEvent(app.id, req.user, 'first_payment', 'İlk ödəniş tamamlandı ($150)');
  users.list().filter(u => u.role === 'moderator').forEach(m =>
    notify(m.id, 'payment',
      'Yeni ödəniş alındı',
      `${users.findById(req.user.id)?.fullName} ilk ödənişi tamamladı. Sənədlər tərcüməyə hazırdır.`,
      '/moderator')
  );
  res.json({ application: saved });
});

app.post('/api/applications/payment/second', authRequired(['student']), (req, res) => {
  const app = applications.findByStudent(req.user.id);
  if (!app) return res.status(404).json({ error: 'no_application' });
  app.secondPaymentPaid = true;
  app.status = 'completed';
  const saved = applications.save(app);
  logEvent(app.id, req.user, 'second_payment', 'İkinci ödəniş tamamlandı ($350) — müraciət bağlandı');
  users.list().filter(u => u.role === 'moderator').forEach(m =>
    notify(m.id, 'payment',
      'İkinci ödəniş alındı',
      `${users.findById(req.user.id)?.fullName} ikinci ödənişi tamamladı. Müraciət tamamlandı.`,
      '/moderator')
  );
  res.json({ application: saved });
});

/* ---------- APPLICATIONS — MODERATOR ---------- */
app.get('/api/applications', authRequired(['moderator']), (_req, res) => {
  res.json({ applications: applications.list() });
});

app.post('/api/applications/:id/documents/:docId/translation',
  authRequired(['moderator']), upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'missing_file' });
    const app = applications.findById(req.params.id);
    if (!app) return res.status(404).json({ error: 'not_found' });
    const doc = app.documents.find(d => d.id === req.params.docId);
    if (!doc) return res.status(404).json({ error: 'doc_not_found' });
    doc.translatedUrl = `/uploads/${req.file.filename}`;
    const saved = applications.save(app);
    logEvent(app.id, req.user, 'translation_uploaded', `Tərcümə yükləndi: ${doc.type}`);
    notify(app.studentId, 'translation',
      'Sənədinizin tərcüməsi hazırdır',
      `"${doc.type}" sənədi tərcümə edildi.`,
      '/student');
    res.json({ application: saved });
  }
);

/* ---------- choice status change (mod + uni) ---------- */
app.post('/api/applications/:id/choices/:facultyId/status',
  authRequired(['moderator', 'university']), (req, res) => {
    const { status, tuitionFee, notes } = req.body || {};
    const allowed = {
      moderator:  ['under_review', 'sent_to_university', 'in_translation'],
      university: ['approved', 'rejected'],
    };
    if (!allowed[req.user.role].includes(status))
      return res.status(403).json({ error: 'forbidden_status' });

    const app = applications.findById(req.params.id);
    if (!app) return res.status(404).json({ error: 'not_found' });
    const choice = app.choices.find(c => c.facultyId === req.params.facultyId);
    if (!choice) return res.status(404).json({ error: 'choice_not_found' });

    // university reps can only act on their own university's choices
    if (req.user.role === 'university' && choice.universityId !== req.user.universityId)
      return res.status(403).json({ error: 'wrong_university' });

    choice.status = status;
    if (tuitionFee != null) choice.tuitionFee = Number(tuitionFee);
    if (notes != null) choice.notes = notes;

    const saved = applications.save(app);

    // Timeline
    const statusLabels = {
      under_review: 'Universitetə göndərildi',
      sent_to_university: 'Universitetə göndərildi',
      in_translation: 'Tərcüməyə qaytarıldı',
      approved: 'Qəbul təsdiqləndi',
      rejected: 'Müraciət geri qaytarıldı',
    };
    logEvent(app.id, req.user, `status_${status}`, statusLabels[status] || status);

    // Bildirimler
    if (req.user.role === 'moderator' && status === 'under_review') {
      // Üniversite temsilcilerine bildir
      users.list().filter(u => u.role === 'university' && u.universityId === choice.universityId)
        .forEach(rep => notify(rep.id, 'application',
          'Yeni müraciət',
          'Sizin universitetinizə yeni bir tələbə müraciəti gəldi.',
          '/university'));
    } else if (req.user.role === 'university') {
      // Moderatorlara bildir
      const studentName = users.findById(app.studentId)?.fullName ?? 'Tələbə';
      users.list().filter(u => u.role === 'moderator').forEach(m =>
        notify(m.id, 'decision',
          status === 'approved' ? 'Qəbul təsdiqləndi' : 'Müraciət rədd edildi',
          `${studentName} üçün qərar verildi.`,
          '/moderator')
      );
      // Öğrenciye de bildir (sadece status, harç bilgisi vermez)
      notify(app.studentId, 'decision',
        status === 'approved' ? '🎉 Qəbul oldunuz!' : 'Müraciətiniz haqqında',
        status === 'approved'
          ? 'Seçilmiş fakultənizə qəbul oldunuz. Detallar üçün kabinetinizə baxın.'
          : 'Müraciətinizin nəticəsi haqqında məlumat kabinetinizdədir.',
        '/student');
    }

    res.json({ application: saved });
  }
);

/* ---------- TIMELINE ---------- */
// Student kendi başvurusunun timeline'ını görür; moderator herhangi birini görür.
// University rep, kendi üniversitesine ait choice olan bir başvuruyu görebilir.
app.get('/api/applications/:id/events', authRequired(), (req, res) => {
  const app = applications.findById(req.params.id);
  if (!app) return res.status(404).json({ error: 'not_found' });
  if (req.user.role === 'student' && app.studentId !== req.user.id)
    return res.status(403).json({ error: 'forbidden' });
  if (req.user.role === 'university') {
    const owns = app.choices.some(c => c.universityId === req.user.universityId);
    if (!owns) return res.status(403).json({ error: 'forbidden' });
  }
  res.json({ events: events.listByApp(req.params.id) });
});

/* ---------- STATS ---------- */
app.get('/api/stats', (_req, res) => res.json(stats()));
app.get('/api/health', (_req, res) => res.json({ ok: true }));

/* ---------- Seed initial moderator on first boot ---------- */
async function seedModerator() {
  const existing = users.list().filter(u => u.role === 'moderator');
  if (existing.length > 0) return;
  const email = process.env.ADMIN_EMAIL    || 'admin@edugate.local';
  const pass  = process.env.ADMIN_PASSWORD || 'admin123';
  const name  = process.env.ADMIN_NAME     || 'System Administrator';
  const hash = await bcrypt.hash(pass, 10);
  const u = users.create({
    id: randomUUID(),
    email, password: hash, fullName: name, role: 'moderator',
    createdAt: new Date().toISOString(),
  });
  users.markEmailVerified(u.id);
  console.log(`✓ Seeded moderator: ${email} / ${pass}`);
}

await seedModerator();

app.listen(PORT, () => {
  console.log(`EduGate API → http://localhost:${PORT}`);
});
