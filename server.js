import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import { randomUUID } from 'crypto';
import { join, dirname, extname } from 'path';
import { fileURLToPath } from 'url';
import {
  users, applications, notifications, invites, events,
  passwordResets, phoneVerifications, messages, reapplyRequests,
  stats, ready as dbReady,
} from './db.js';
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
app.post('/api/auth/register', async (req, res) => {
  const { email, password, fullName, phone, whatsapp, country, city } = req.body || {};
  if (!email || !password || !fullName || !phone || !country || !city) {
    return res.status(400).json({ error: 'missing_fields' });
  }
  if (password.length < 6) return res.status(400).json({ error: 'weak_password' });
  if (await users.findByEmail(email)) return res.status(409).json({ error: 'email_exists' });

  const hash = await bcrypt.hash(password, 10);
  const code = String(Math.floor(100000 + Math.random() * 900000));

  await phoneVerifications.upsert({
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

  res.json({ ok: true, requiresOtp: true, phone });
});

// Step 2: Student enters the 6-digit code → we verify, materialize the user, return a token.
app.post('/api/auth/verify-otp', async (req, res) => {
  const { phone, code } = req.body || {};
  if (!phone || !code) return res.status(400).json({ error: 'missing_fields' });

  const v = await phoneVerifications.find(phone);
  if (!v) return res.status(400).json({ error: 'invalid_code' });
  if (new Date(v.expiresAt) < new Date()) {
    await phoneVerifications.consume(phone);
    return res.status(400).json({ error: 'expired_code' });
  }
  if (v.attempts >= 5) {
    await phoneVerifications.consume(phone);
    return res.status(429).json({ error: 'too_many_attempts' });
  }
  const submitted = String(code).replace(/\s+/g, '').trim();
  if (v.code !== submitted) {
    await phoneVerifications.incrementAttempts(phone);
    return res.status(400).json({ error: 'invalid_code' });
  }

  // Race-safety: email might have been claimed between step 1 and step 2.
  if (await users.findByEmail(v.payload.email)) {
    await phoneVerifications.consume(phone);
    return res.status(409).json({ error: 'email_exists' });
  }

  const created = await users.create({
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
  await users.markPhoneVerified(created.id);

  // Generate per-spec unique student code (e.g. AZ012-300526) and persist it.
  try {
    const code = await users.nextStudentCode(v.payload.country);
    await users.setStudentCode(created.id, code);
  } catch (e) {
    console.error('student code generation failed:', e.message);
  }

  const user = await users.findById(created.id);
  await phoneVerifications.consume(phone);
  res.json({ user: publicUser(user), token: sign(user) });
});

// Optional: re-send OTP if the user lost the SMS.
app.post('/api/auth/resend-otp', async (req, res) => {
  const { phone } = req.body || {};
  if (!phone) return res.status(400).json({ error: 'missing_fields' });
  const v = await phoneVerifications.find(phone);
  if (!v) return res.status(404).json({ error: 'no_pending_registration' });
  const code = String(Math.floor(100000 + Math.random() * 900000));
  await phoneVerifications.upsert({ phone, code, payload: v.payload });
  try { await sendSmsOtp(phone, code); } catch (e) { console.error('SMS send failed:', e.message); }
  res.json({ ok: true });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = await users.findByEmail(email || '');
  if (!user) return res.status(401).json({ error: 'invalid_credentials' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' });
  res.json({ user: publicUser(user), token: sign(user) });
});

app.get('/api/auth/me', authRequired(), async (req, res) => {
  const user = await users.findById(req.user.id);
  res.json({ user: publicUser(user) });
});

/* ---------- PASSWORD RESET (link-based) ---------- */
function makeResetToken() {
  const bytes = new Uint8Array(24);
  (globalThis.crypto || require('crypto').webcrypto).getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'missing_email' });

  const user = await users.findByEmail(email);
  if (user) {
    const token = makeResetToken();
    await passwordResets.upsert({ email: user.email, userId: user.id, token });
    const origin = (process.env.APP_URL || process.env.FRONTEND_URL || `${req.protocol}://${req.get('host').replace(/:\d+$/, ':5173')}`).replace(/\/$/, '');
    const link = `${origin}/reset-password/${token}`;
    try { await sendPasswordResetLink(user.email, user.fullName, link); }
    catch (err) { console.error('Reset mail failed:', err.message); }
  }
  res.json({ ok: true });
});

app.get('/api/auth/verify-reset-token/:token', async (req, res) => {
  const reset = await passwordResets.findByToken(req.params.token);
  if (!reset) return res.status(404).json({ error: 'invalid_token' });
  if (new Date(reset.expiresAt) < new Date()) {
    await passwordResets.consume(reset.token);
    return res.status(410).json({ error: 'expired_token' });
  }
  const masked = reset.email.replace(/^(.).+(@.+)$/, (_m, first, dom) => `${first}***${dom}`);
  res.json({ ok: true, email: masked, expiresAt: reset.expiresAt });
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body || {};
  if (!token || !newPassword) return res.status(400).json({ error: 'missing_fields' });
  if (newPassword.length < 6)  return res.status(400).json({ error: 'weak_password' });

  const reset = await passwordResets.findByToken(token);
  if (!reset) return res.status(404).json({ error: 'invalid_token' });
  if (new Date(reset.expiresAt) < new Date()) {
    await passwordResets.consume(reset.token);
    return res.status(410).json({ error: 'expired_token' });
  }
  const hash = await bcrypt.hash(newPassword, 10);
  await users.updatePassword(reset.userId, hash);
  await passwordResets.consume(reset.token);

  res.json({ ok: true });
});

app.patch('/api/auth/me', authRequired(), async (req, res) => {
  const { fullName, phone, whatsapp, country, city } = req.body || {};
  if (!fullName) return res.status(400).json({ error: 'missing_fields' });
  const user = await users.updateProfile(req.user.id, { fullName, phone, whatsapp, country, city });
  res.json({ user: publicUser(user), token: sign(user) });
});

app.post('/api/auth/password', authRequired(), async (req, res) => {
  const { current, next } = req.body || {};
  if (!current || !next || next.length < 6) return res.status(400).json({ error: 'invalid_input' });
  const user = await users.findById(req.user.id);
  const ok = await bcrypt.compare(current, user.password);
  if (!ok) return res.status(401).json({ error: 'wrong_password' });
  await users.updatePassword(req.user.id, await bcrypt.hash(next, 10));
  res.json({ ok: true });
});

/* ---------- NOTIFICATIONS / EVENT HELPERS ----------
   Fire-and-forget — we don't want a notification failure to break the response.
   Errors are logged so we can spot DB issues.
---------------------------------------------------- */
function notify(userId, type, title, message, link) {
  notifications.create({ id: randomUUID(), userId, type, title, message, link })
    .catch(e => console.error('notify failed:', e.message));
}

function logEvent(applicationId, actor, type, message) {
  events.create({
    applicationId,
    actorId: actor?.id,
    actorRole: actor?.role,
    type, message,
  }).catch(e => console.error('event log failed:', e.message));
}

app.get('/api/notifications', authRequired(), async (req, res) => {
  const [list, unread] = await Promise.all([
    notifications.listByUser(req.user.id),
    notifications.unreadCount(req.user.id),
  ]);
  res.json({ notifications: list, unread });
});

app.post('/api/notifications/:id/read', authRequired(), async (req, res) => {
  await notifications.markRead(req.params.id, req.user.id);
  res.json({ ok: true });
});

app.post('/api/notifications/read-all', authRequired(), async (req, res) => {
  await notifications.markAllRead(req.user.id);
  res.json({ ok: true });
});

/* ---------- USERS ---------- */
app.get('/api/users/:id', authRequired(), async (req, res) => {
  const user = await users.findById(req.params.id);
  if (!user) return res.status(404).json({ error: 'not_found' });
  res.json({ user: publicUser(user) });
});

app.get('/api/users', authRequired(['moderator', 'university']), async (_req, res) => {
  const all = await users.list();
  res.json({ users: all.map(publicUser) });
});

/* ---------- ADMIN: Moderator management ---------- */
app.get('/api/admin/moderators', authRequired(['moderator']), async (_req, res) => {
  const all = await users.list();
  const list = all.filter(u => u.role === 'moderator').map(publicUser);
  res.json({ moderators: list });
});

app.post('/api/admin/moderators', authRequired(['moderator']), async (req, res) => {
  const { email, password, fullName, phone } = req.body || {};
  if (!email || !password || !fullName) return res.status(400).json({ error: 'missing_fields' });
  if (password.length < 6) return res.status(400).json({ error: 'weak_password' });
  if (await users.findByEmail(email)) return res.status(409).json({ error: 'email_exists' });

  const hash = await bcrypt.hash(password, 10);
  const created = await users.create({
    id: randomUUID(),
    email, password: hash, fullName, role: 'moderator', phone,
    createdAt: new Date().toISOString(),
  });
  await users.markEmailVerified(created.id);
  const fresh = await users.findById(created.id);
  res.json({ moderator: publicUser(fresh) });
});

/* ---------- INVITE SYSTEM (moderator + university representative) ---------- */
app.post('/api/admin/invites', authRequired(['moderator']), async (req, res) => {
  const { note } = req.body || {};
  const inv = await invites.create({ createdBy: req.user.id, note, kind: 'moderator' });
  res.json({ invite: inv });
});

app.post('/api/admin/uni-invites', authRequired(['moderator']), async (req, res) => {
  const { targetEmail, targetName, universityId, universityName, note } = req.body || {};
  if (!targetEmail || !universityId) return res.status(400).json({ error: 'missing_fields' });

  const inv = await invites.create({
    createdBy: req.user.id,
    kind: 'university',
    note,
    targetEmail: String(targetEmail).toLowerCase().trim(),
    targetName: targetName ?? null,
    universityId,
  });

  const origin = process.env.APP_URL || `${req.protocol}://${req.get('host').replace(/:\d+$/, ':5173')}`;
  const link = `${origin.replace(/\/$/, '')}/invite/${inv.token}`;

  try { await sendUniInviteLink(targetEmail, targetName, link, universityName || universityId); }
  catch (e) { console.error('Uni invite mail failed:', e.message); }

  res.json({ invite: { ...inv, link } });
});

app.get('/api/admin/invites', authRequired(['moderator']), async (req, res) => {
  const kind = req.query.kind;
  const list = await invites.listAll(kind);
  res.json({ invites: list });
});

app.delete('/api/admin/invites/:token', authRequired(['moderator']), async (req, res) => {
  await invites.delete(req.params.token);
  res.json({ ok: true });
});

app.get('/api/invites/:token', async (req, res) => {
  const inv = await invites.find(req.params.token);
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

app.post('/api/invites/:token/accept', async (req, res) => {
  const { email, password, fullName, phone, whatsapp } = req.body || {};
  if (!email || !password || !fullName) return res.status(400).json({ error: 'missing_fields' });
  if (password.length < 6) return res.status(400).json({ error: 'weak_password' });

  const inv = await invites.find(req.params.token);
  if (!inv) return res.status(404).json({ error: 'invalid_token' });
  if (inv.usedAt) return res.status(410).json({ error: 'already_used' });
  if (new Date(inv.expiresAt) < new Date()) return res.status(410).json({ error: 'expired' });
  if (await users.findByEmail(email)) return res.status(409).json({ error: 'email_exists' });

  const role = inv.kind === 'university' ? 'university' : 'moderator';
  const universityId = role === 'university' ? inv.universityId : null;
  if (role === 'university' && !universityId) return res.status(400).json({ error: 'missing_university' });

  const hash = await bcrypt.hash(password, 10);
  const created = await users.create({
    id: randomUUID(),
    email, password: hash, fullName, role, phone, whatsapp: whatsapp ?? null,
    universityId,
    createdAt: new Date().toISOString(),
  });
  await users.markEmailVerified(created.id);
  await invites.consume(req.params.token, created.id);
  const user = await users.findById(created.id);
  res.json({ user: publicUser(user), token: sign(user), role });
});

/* ---------- APPLICATIONS — STUDENT ---------- */
app.get('/api/applications/mine', authRequired(['student']), async (req, res) => {
  const a = await applications.findByStudent(req.user.id);
  res.json({ application: a ?? null });
});

app.post('/api/applications/choices', authRequired(['student']), async (req, res) => {
  const { choices } = req.body || {};
  if (!Array.isArray(choices) || choices.length > 5) return res.status(400).json({ error: 'invalid_choices' });

  let app = await applications.findByStudent(req.user.id);
  const isNew = !app;
  if (app) {
    app.choices = choices;
    app = await applications.save(app);
  } else {
    app = await applications.create({
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

app.post('/api/applications/documents', authRequired(['student']), upload.single('file'), async (req, res) => {
  const { type } = req.body;
  if (!req.file || !type) return res.status(400).json({ error: 'missing_fields' });

  const app = await applications.findByStudent(req.user.id);
  if (!app) return res.status(404).json({ error: 'no_application' });

  app.documents.push({
    id: randomUUID(), type,
    fileName: req.file.originalname,
    url: `/uploads/${req.file.filename}`,
    uploadedAt: new Date().toISOString(),
  });
  const saved = await applications.save(app);
  logEvent(app.id, req.user, 'document_uploaded', `Sənəd yükləndi: ${type}`);
  res.json({ application: saved });
});

app.delete('/api/applications/documents/:docId', authRequired(['student']), async (req, res) => {
  const app = await applications.findByStudent(req.user.id);
  if (!app) return res.status(404).json({ error: 'no_application' });
  app.documents = app.documents.filter(d => d.id !== req.params.docId);
  const saved = await applications.save(app);
  res.json({ application: saved });
});

app.post('/api/applications/payment/first', authRequired(['student']), async (req, res) => {
  const app = await applications.findByStudent(req.user.id);
  if (!app) return res.status(404).json({ error: 'no_application' });
  app.firstPaymentPaid = true;
  app.status = 'in_translation';
  const saved = await applications.save(app);
  logEvent(app.id, req.user, 'first_payment', 'İlk ödəniş tamamlandı ($150)');

  const allUsers = await users.list();
  const me = await users.findById(req.user.id);
  allUsers.filter(u => u.role === 'moderator').forEach(m =>
    notify(m.id, 'payment',
      'Yeni ödəniş alındı',
      `${me?.fullName ?? 'Tələbə'} ilk ödənişi tamamladı. Sənədlər tərcüməyə hazırdır.`,
      '/moderator'),
  );
  res.json({ application: saved });
});

app.post('/api/applications/payment/second', authRequired(['student']), async (req, res) => {
  const app = await applications.findByStudent(req.user.id);
  if (!app) return res.status(404).json({ error: 'no_application' });
  app.secondPaymentPaid = true;
  app.status = 'completed';
  const saved = await applications.save(app);
  logEvent(app.id, req.user, 'second_payment', 'İkinci ödəniş tamamlandı ($350) — müraciət bağlandı');

  const allUsers = await users.list();
  const me = await users.findById(req.user.id);
  allUsers.filter(u => u.role === 'moderator').forEach(m =>
    notify(m.id, 'payment',
      'İkinci ödəniş alındı',
      `${me?.fullName ?? 'Tələbə'} ikinci ödənişi tamamladı. Müraciət tamamlandı.`,
      '/moderator'),
  );
  res.json({ application: saved });
});

/* ---------- APPLICATIONS — MODERATOR ---------- */
app.get('/api/applications', authRequired(['moderator']), async (_req, res) => {
  const list = await applications.list();
  res.json({ applications: list });
});

app.post('/api/applications/:id/documents/:docId/translation',
  authRequired(['moderator']), upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'missing_file' });
    const app = await applications.findById(req.params.id);
    if (!app) return res.status(404).json({ error: 'not_found' });
    const doc = app.documents.find(d => d.id === req.params.docId);
    if (!doc) return res.status(404).json({ error: 'doc_not_found' });
    doc.translatedUrl = `/uploads/${req.file.filename}`;
    const saved = await applications.save(app);
    logEvent(app.id, req.user, 'translation_uploaded', `Tərcümə yükləndi: ${doc.type}`);
    notify(app.studentId, 'translation',
      'Sənədinizin tərcüməsi hazırdır',
      `"${doc.type}" sənədi tərcümə edildi.`,
      '/student');
    res.json({ application: saved });
  },
);

/* ---------- choice status change (mod + uni) ---------- */
app.post('/api/applications/:id/choices/:facultyId/status',
  authRequired(['moderator', 'university']), async (req, res) => {
    const { status, tuitionFee, notes } = req.body || {};
    const allowed = {
      moderator:  ['under_review', 'sent_to_university', 'in_translation'],
      university: ['approved', 'rejected'],
    };
    if (!allowed[req.user.role].includes(status))
      return res.status(403).json({ error: 'forbidden_status' });

    const app = await applications.findById(req.params.id);
    if (!app) return res.status(404).json({ error: 'not_found' });
    const choice = app.choices.find(c => c.facultyId === req.params.facultyId);
    if (!choice) return res.status(404).json({ error: 'choice_not_found' });

    if (req.user.role === 'university' && choice.universityId !== req.user.universityId)
      return res.status(403).json({ error: 'wrong_university' });

    choice.status = status;
    if (tuitionFee != null) choice.tuitionFee = Number(tuitionFee);
    if (notes != null) choice.notes = notes;

    const saved = await applications.save(app);

    const statusLabels = {
      under_review: 'Universitetə göndərildi',
      sent_to_university: 'Universitetə göndərildi',
      in_translation: 'Tərcüməyə qaytarıldı',
      approved: 'Qəbul təsdiqləndi',
      rejected: 'Müraciət geri qaytarıldı',
    };
    logEvent(app.id, req.user, `status_${status}`, statusLabels[status] || status);

    if (req.user.role === 'moderator' && status === 'under_review') {
      const allUsers = await users.list();
      allUsers
        .filter(u => u.role === 'university' && u.universityId === choice.universityId)
        .forEach(rep => notify(rep.id, 'application',
          'Yeni müraciət',
          'Sizin universitetinizə yeni bir tələbə müraciəti gəldi.',
          '/university'));
    } else if (req.user.role === 'university') {
      const allUsers = await users.list();
      const studentRec = await users.findById(app.studentId);
      const studentName = studentRec?.fullName ?? 'Tələbə';
      allUsers.filter(u => u.role === 'moderator').forEach(m =>
        notify(m.id, 'decision',
          status === 'approved' ? 'Qəbul təsdiqləndi' : 'Müraciət rədd edildi',
          `${studentName} üçün qərar verildi.`,
          '/moderator'),
      );
      notify(app.studentId, 'decision',
        status === 'approved' ? '🎉 Qəbul oldunuz!' : 'Müraciətiniz haqqında',
        status === 'approved'
          ? 'Seçilmiş fakultənizə qəbul oldunuz. Detallar üçün kabinetinizə baxın.'
          : 'Müraciətinizin nəticəsi haqqında məlumat kabinetinizdədir.',
        '/student');
    }

    res.json({ application: saved });
  },
);

/* ---------- TIMELINE ---------- */
app.get('/api/applications/:id/events', authRequired(), async (req, res) => {
  const app = await applications.findById(req.params.id);
  if (!app) return res.status(404).json({ error: 'not_found' });
  if (req.user.role === 'student' && app.studentId !== req.user.id)
    return res.status(403).json({ error: 'forbidden' });
  if (req.user.role === 'university') {
    const owns = app.choices.some(c => c.universityId === req.user.universityId);
    if (!owns) return res.status(403).json({ error: 'forbidden' });
  }
  const list = await events.listByApp(req.params.id);
  res.json({ events: list });
});

/* ---------- MESSAGES (student ↔ university chat) ----------
   Per spec: chat is unlocked after the student's choice is approved by the
   university AND the second payment is paid (the "Müsbət cavab + ödənişdən
   sonra portal üzərindən universitetin təmsilçisi ilə yazışma" step).
   Both parties can read & write history for the application. Moderators are
   read-only for oversight.
---------------------------------------------------------- */
function canChatOnApp(app, user) {
  if (!app) return false;
  if (user.role === 'moderator') return true; // read-only audit
  const hasApproved = app.choices.some(c => c.status === 'approved');
  if (!hasApproved || !app.secondPaymentPaid) return false;
  if (user.role === 'student')    return app.studentId === user.id;
  if (user.role === 'university') return app.choices.some(c =>
    c.universityId === user.universityId && c.status === 'approved');
  return false;
}

app.get('/api/applications/:id/messages', authRequired(), async (req, res) => {
  const app = await applications.findById(req.params.id);
  if (!app) return res.status(404).json({ error: 'not_found' });
  if (!canChatOnApp(app, req.user)) return res.status(403).json({ error: 'chat_locked' });
  const list = await messages.listByApp(req.params.id);
  await messages.markRead(req.params.id, req.user.id).catch(() => {});
  res.json({ messages: list });
});

app.post('/api/applications/:id/messages', authRequired(['student', 'university']), async (req, res) => {
  const { content } = req.body || {};
  if (!content || !String(content).trim()) return res.status(400).json({ error: 'empty_message' });

  const app = await applications.findById(req.params.id);
  if (!app) return res.status(404).json({ error: 'not_found' });
  if (req.user.role === 'moderator') return res.status(403).json({ error: 'moderator_read_only' });
  if (!canChatOnApp(app, req.user)) return res.status(403).json({ error: 'chat_locked' });

  // Determine recipient: student -> the approved university rep; uni rep -> student.
  let recipientId;
  if (req.user.role === 'student') {
    const approved = app.choices.find(c => c.status === 'approved');
    if (!approved) return res.status(400).json({ error: 'no_approved_choice' });
    const allUsers = await users.list();
    const rep = allUsers.find(u => u.role === 'university' && u.universityId === approved.universityId);
    if (!rep) return res.status(400).json({ error: 'no_university_rep' });
    recipientId = rep.id;
  } else {
    recipientId = app.studentId;
  }

  const msg = await messages.create({
    applicationId: req.params.id,
    senderId: req.user.id,
    recipientId,
    content: String(content).trim().slice(0, 4000),
  });

  notify(recipientId, 'message', 'Yeni mesaj',
    `${req.user.fullName ?? 'İstifadəçi'} sizə mesaj göndərdi.`,
    req.user.role === 'student' ? '/university' : '/student');

  res.json({ message: msg });
});

/* ---------- RE-APPLY (student requests resending docs to other unis) ----------
   Per spec:
   - same-language: moderator sends docs to other same-language uni faculties
     without any new translation payment ("ödənişsiz davam edir").
   - country/language change: a new translation payment is required
     (firstPaymentPaid is reset to false; status drops back to documents_uploaded).
---------------------------------------------------------- */
app.post('/api/applications/:id/reapply', authRequired(['student']), async (req, res) => {
  const { reason, sameLanguage = true } = req.body || {};
  const app = await applications.findById(req.params.id);
  if (!app) return res.status(404).json({ error: 'not_found' });
  if (app.studentId !== req.user.id) return res.status(403).json({ error: 'forbidden' });

  const sameLang = !!sameLanguage;

  if (!sameLang) {
    app.firstPaymentPaid = false;
    app.status = 'first_payment_pending';
  } else {
    app.status = 'sent_to_university';
  }
  // Reset choice statuses that were finalized — they need to be re-evaluated.
  app.choices = app.choices.map(c =>
    c.status === 'rejected' || c.status === 'approved'
      ? { ...c, status: sameLang ? 'sent_to_university' : 'in_translation' }
      : c,
  );
  const saved = await applications.save(app);

  await reapplyRequests.create({
    applicationId: app.id,
    studentId: req.user.id,
    reason,
    sameLanguage: sameLang,
  });

  logEvent(app.id, req.user, sameLang ? 'reapply_same_lang' : 'reapply_country_change',
    sameLang
      ? `Tələbə yenidən müraciət istədi (eyni dil — ödənişsiz)`
      : `Tələbə ölkəni dəyişdi — yeni tərcümə ödənişi tələb olunur`);

  const allUsers = await users.list();
  const me = await users.findById(req.user.id);
  allUsers.filter(u => u.role === 'moderator').forEach(m =>
    notify(m.id, 'reapply',
      sameLang ? 'Yenidən müraciət (eyni dil)' : 'Yenidən müraciət (ölkə dəyişdi)',
      `${me?.fullName ?? 'Tələbə'} yenidən müraciət istəyir. ${reason ? `Səbəb: ${reason}` : ''}`,
      '/moderator'),
  );

  res.json({ application: saved, requiresNewPayment: !sameLang });
});

app.get('/api/moderator/reapplies', authRequired(['moderator']), async (_req, res) => {
  const list = await reapplyRequests.listPending();
  res.json({ requests: list });
});

app.post('/api/moderator/reapplies/:id/handle', authRequired(['moderator']), async (req, res) => {
  await reapplyRequests.handle(req.params.id, req.user.id);
  res.json({ ok: true });
});

/* ---------- STATS ---------- */
app.get('/api/stats', async (_req, res) => res.json(await stats()));
app.get('/api/health', (_req, res) => res.json({ ok: true }));

/* ---------- Seed initial moderator on first boot ---------- */
async function seedModerator() {
  const list = await users.list();
  if (list.some(u => u.role === 'moderator')) return;
  const email = process.env.ADMIN_EMAIL    || 'admin@edugate.local';
  const pass  = process.env.ADMIN_PASSWORD || 'admin123';
  const name  = process.env.ADMIN_NAME     || 'System Administrator';
  const hash = await bcrypt.hash(pass, 10);
  const created = await users.create({
    id: randomUUID(),
    email, password: hash, fullName: name, role: 'moderator',
    createdAt: new Date().toISOString(),
  });
  await users.markEmailVerified(created.id);
  console.log(`✓ Seeded moderator: ${email} / ${pass}`);
}

/* ---------- BOOT ----------
   Wait for the DB schema to be ready before we seed and start accepting
   traffic. Surfacing the error here gives a clean "couldn't reach the
   database" message instead of a flood of 500s on every request.
---------------------------- */
try {
  await dbReady;
  await seedModerator();
  app.listen(PORT, () => {
    console.log(`EduGate API → http://localhost:${PORT}`);
  });
} catch (err) {
  console.error('Server boot failed:', err.message);
  process.exit(1);
}
