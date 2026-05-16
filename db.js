import Database from 'better-sqlite3';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { mkdirSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DB_PATH = process.env.DB_PATH || join(__dirname, 'data', 'edugate.db');

mkdirSync(dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');     // better concurrency
db.pragma('foreign_keys = ON');

/* ---------- schema ---------- */
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    email           TEXT UNIQUE NOT NULL,
    password        TEXT NOT NULL,
    full_name       TEXT NOT NULL,
    role            TEXT NOT NULL CHECK(role IN ('student','university','moderator')),
    phone           TEXT,
    whatsapp        TEXT,
    university_id   TEXT,
    email_verified  INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS moderator_invites (
    token       TEXT PRIMARY KEY,
    created_by  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    note        TEXT,
    expires_at  TEXT NOT NULL,
    used_at     TEXT,
    used_by     TEXT,
    created_at  TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS app_events (
    id              TEXT PRIMARY KEY,
    application_id  TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    actor_id        TEXT REFERENCES users(id) ON DELETE SET NULL,
    actor_role      TEXT,
    type            TEXT NOT NULL,
    message         TEXT NOT NULL,
    created_at      TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS password_resets (
    email       TEXT PRIMARY KEY,
    code        TEXT NOT NULL,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    attempts    INTEGER NOT NULL DEFAULT 0,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS applications (
    id                   TEXT PRIMARY KEY,
    student_id           TEXT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status               TEXT NOT NULL DEFAULT 'draft',
    choices              TEXT NOT NULL DEFAULT '[]',   -- JSON array of FacultyChoice
    documents            TEXT NOT NULL DEFAULT '[]',   -- JSON array of ApplicationDocument
    first_payment_paid   INTEGER NOT NULL DEFAULT 0,
    second_payment_paid  INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    title       TEXT NOT NULL,
    message     TEXT NOT NULL,
    link        TEXT,
    read_at     TEXT,
    created_at  TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_users_email     ON users(email);
  CREATE INDEX IF NOT EXISTS idx_apps_student_id ON applications(student_id);
  CREATE INDEX IF NOT EXISTS idx_notif_user_id   ON notifications(user_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_events_app_id   ON app_events(application_id, created_at DESC);
`);

// Migration: email_verifications tablosu varsa düş (artık kullanılmıyor)
db.exec(`DROP TABLE IF EXISTS email_verifications`);
// Mevcut kullanıcıları onaylı yap (artık email doğrulama yok)
const cols = db.prepare(`PRAGMA table_info(users)`).all();
if (cols.some(c => c.name === 'email_verified')) {
  db.exec(`UPDATE users SET email_verified = 1 WHERE email_verified = 0`);
}

/* ---------- row <-> object mappers ---------- */
function rowToUser(r) {
  if (!r) return null;
  return {
    id: r.id, email: r.email, password: r.password, fullName: r.full_name,
    role: r.role, phone: r.phone || undefined, whatsapp: r.whatsapp || undefined,
    universityId: r.university_id || undefined,
    emailVerified: !!r.email_verified,
    createdAt: r.created_at,
  };
}

function rowToApp(r) {
  if (!r) return null;
  return {
    id: r.id, studentId: r.student_id, status: r.status,
    choices: JSON.parse(r.choices), documents: JSON.parse(r.documents),
    firstPaymentPaid: !!r.first_payment_paid,
    secondPaymentPaid: !!r.second_payment_paid,
    createdAt: r.created_at,
  };
}

/* ---------- USERS ---------- */
export const users = {
  findByEmail(email) {
    return rowToUser(db.prepare(`SELECT * FROM users WHERE LOWER(email) = LOWER(?)`).get(email));
  },
  findById(id) {
    return rowToUser(db.prepare(`SELECT * FROM users WHERE id = ?`).get(id));
  },
  list() {
    return db.prepare(`SELECT * FROM users ORDER BY created_at`).all().map(rowToUser);
  },
  create(u) {
    db.prepare(`
      INSERT INTO users (id,email,password,full_name,role,phone,whatsapp,university_id,created_at)
      VALUES (@id,@email,@password,@fullName,@role,@phone,@whatsapp,@universityId,@createdAt)
    `).run({
      id: u.id, email: u.email, password: u.password, fullName: u.fullName,
      role: u.role, phone: u.phone ?? null, whatsapp: u.whatsapp ?? null,
      universityId: u.universityId ?? null, createdAt: u.createdAt,
    });
    return this.findById(u.id);
  },
  updateProfile(id, { fullName, phone, whatsapp }) {
    db.prepare(`UPDATE users SET full_name = ?, phone = ?, whatsapp = ? WHERE id = ?`)
      .run(fullName, phone ?? null, whatsapp ?? null, id);
    return this.findById(id);
  },
  updatePassword(id, hash) {
    db.prepare(`UPDATE users SET password = ? WHERE id = ?`).run(hash, id);
  },
  markEmailVerified(id) {
    db.prepare(`UPDATE users SET email_verified = 1 WHERE id = ?`).run(id);
  },
};

/* ---------- MODERATOR INVITES ---------- */
function makeToken() {
  // 32 byte hex token
  const bytes = new Uint8Array(24);
  (globalThis.crypto || require('crypto').webcrypto).getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

export const invites = {
  create({ createdBy, note, ttlDays = 7 }) {
    const token = makeToken();
    const now = new Date();
    const expires = new Date(now.getTime() + ttlDays * 24 * 60 * 60 * 1000);
    db.prepare(`
      INSERT INTO moderator_invites (token, created_by, note, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(token, createdBy, note ?? null, expires.toISOString(), now.toISOString());
    return { token, expiresAt: expires.toISOString() };
  },
  find(token) {
    const r = db.prepare(`SELECT * FROM moderator_invites WHERE token = ?`).get(token);
    if (!r) return null;
    return {
      token: r.token, createdBy: r.created_by, note: r.note || undefined,
      expiresAt: r.expires_at, usedAt: r.used_at || undefined,
      usedBy: r.used_by || undefined, createdAt: r.created_at,
    };
  },
  consume(token, newUserId) {
    db.prepare(`UPDATE moderator_invites SET used_at = ?, used_by = ? WHERE token = ?`)
      .run(new Date().toISOString(), newUserId, token);
  },
  listAll() {
    return db.prepare(`SELECT * FROM moderator_invites ORDER BY created_at DESC`).all().map(r => ({
      token: r.token, createdBy: r.created_by, note: r.note || undefined,
      expiresAt: r.expires_at, usedAt: r.used_at || undefined,
      usedBy: r.used_by || undefined, createdAt: r.created_at,
    }));
  },
  delete(token) {
    db.prepare(`DELETE FROM moderator_invites WHERE token = ?`).run(token);
  },
};

/* ---------- APPLICATION EVENTS (timeline) ---------- */
export const events = {
  create({ applicationId, actorId, actorRole, type, message }) {
    const id = makeToken();
    db.prepare(`
      INSERT INTO app_events (id, application_id, actor_id, actor_role, type, message, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, applicationId, actorId ?? null, actorRole ?? null, type, message, new Date().toISOString());
  },
  listByApp(applicationId) {
    return db.prepare(`
      SELECT * FROM app_events WHERE application_id = ? ORDER BY created_at ASC
    `).all(applicationId).map(r => ({
      id: r.id, applicationId: r.application_id, actorId: r.actor_id || undefined,
      actorRole: r.actor_role || undefined, type: r.type, message: r.message,
      createdAt: r.created_at,
    }));
  },
};

/* ---------- APPLICATIONS ---------- */
export const applications = {
  findById(id) {
    return rowToApp(db.prepare(`SELECT * FROM applications WHERE id = ?`).get(id));
  },
  findByStudent(studentId) {
    return rowToApp(db.prepare(`SELECT * FROM applications WHERE student_id = ?`).get(studentId));
  },
  list() {
    return db.prepare(`SELECT * FROM applications ORDER BY created_at DESC`).all().map(rowToApp);
  },
  create(a) {
    db.prepare(`
      INSERT INTO applications (id,student_id,status,choices,documents,first_payment_paid,second_payment_paid,created_at)
      VALUES (?,?,?,?,?,?,?,?)
    `).run(
      a.id, a.studentId, a.status,
      JSON.stringify(a.choices), JSON.stringify(a.documents),
      a.firstPaymentPaid ? 1 : 0, a.secondPaymentPaid ? 1 : 0,
      a.createdAt,
    );
    return this.findById(a.id);
  },
  save(a) {
    db.prepare(`
      UPDATE applications
      SET status = ?, choices = ?, documents = ?,
          first_payment_paid = ?, second_payment_paid = ?
      WHERE id = ?
    `).run(
      a.status, JSON.stringify(a.choices), JSON.stringify(a.documents),
      a.firstPaymentPaid ? 1 : 0, a.secondPaymentPaid ? 1 : 0,
      a.id,
    );
    return this.findById(a.id);
  },
};

/* ---------- PASSWORD RESETS ---------- */
export const passwordResets = {
  upsert({ email, userId, code }) {
    const now = new Date();
    const expires = new Date(now.getTime() + 15 * 60 * 1000); // 15 dəqiqə
    db.prepare(`
      INSERT INTO password_resets (email, code, user_id, attempts, expires_at, created_at)
      VALUES (?, ?, ?, 0, ?, ?)
      ON CONFLICT(email) DO UPDATE SET
        code = excluded.code,
        user_id = excluded.user_id,
        attempts = 0,
        expires_at = excluded.expires_at,
        created_at = excluded.created_at
    `).run(email.toLowerCase(), code, userId, expires.toISOString(), now.toISOString());
    return { expiresAt: expires.toISOString() };
  },
  find(email) {
    const r = db.prepare(`SELECT * FROM password_resets WHERE email = ?`).get(email.toLowerCase());
    if (!r) return null;
    return {
      email: r.email, code: r.code, userId: r.user_id, attempts: r.attempts,
      expiresAt: r.expires_at, createdAt: r.created_at,
    };
  },
  incrementAttempts(email) {
    db.prepare(`UPDATE password_resets SET attempts = attempts + 1 WHERE email = ?`)
      .run(email.toLowerCase());
  },
  consume(email) {
    db.prepare(`DELETE FROM password_resets WHERE email = ?`).run(email.toLowerCase());
  },
};

/* ---------- NOTIFICATIONS ---------- */
function rowToNotif(r) {
  if (!r) return null;
  return {
    id: r.id, userId: r.user_id, type: r.type,
    title: r.title, message: r.message, link: r.link || undefined,
    readAt: r.read_at || undefined, createdAt: r.created_at,
  };
}

export const notifications = {
  listByUser(userId, limit = 50) {
    return db.prepare(
      `SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`
    ).all(userId, limit).map(rowToNotif);
  },
  unreadCount(userId) {
    return db.prepare(
      `SELECT COUNT(*) AS c FROM notifications WHERE user_id = ? AND read_at IS NULL`
    ).get(userId).c;
  },
  create({ id, userId, type, title, message, link }) {
    db.prepare(`
      INSERT INTO notifications (id, user_id, type, title, message, link, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, userId, type, title, message, link ?? null, new Date().toISOString());
  },
  markRead(id, userId) {
    db.prepare(`UPDATE notifications SET read_at = ? WHERE id = ? AND user_id = ?`)
      .run(new Date().toISOString(), id, userId);
  },
  markAllRead(userId) {
    db.prepare(`UPDATE notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL`)
      .run(new Date().toISOString(), userId);
  },
};

/* ---------- STATS ---------- */
export function stats() {
  const apps = applications.list();
  const total = apps.reduce((acc, a) => acc + a.choices.length, 0);
  const accepted = apps.reduce(
    (acc, a) => acc + a.choices.filter(c => c.status === 'approved').length, 0
  );
  return { applications: total, accepted };
}

export default db;
