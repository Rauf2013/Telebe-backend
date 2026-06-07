import pg from 'pg';

/**
 * EduGate data layer — PostgreSQL via the pure-JS `pg` driver.
 *
 * Why not SQLite anymore: better-sqlite3 is a native module that requires
 * node-gyp + Visual Studio Build Tools (Windows) or libstdc++ build chain
 * (Linux) at install time. That breaks `npm install` on many deploy hosts
 * (Render free tier, Vercel build images, Railway nixpacks, etc.) any time
 * Node bumps a minor version. `pg` is pure JavaScript over a TCP socket —
 * installs instantly on every platform, no compilation phase.
 *
 * Production hosting: free tier on Neon (https://neon.tech). Sign up,
 * create a project, copy the connection string into DATABASE_URL.
 * Local dev: point DATABASE_URL at the same Neon DB or run Postgres
 * locally — both are supported by this driver.
 *
 * All exported modules are ASYNC. server.js must `await` every call.
 */

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  console.error('\n⚠  DATABASE_URL is not set. Add it to backend/.env.');
  console.error('   Get a free one at https://neon.tech (or any Postgres host).\n');
}

// Use SSL when the host isn't localhost (Neon, Railway, Render Postgres all need it).
const needsSSL = !!process.env.DATABASE_URL && !/localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: needsSSL ? { rejectUnauthorized: false } : false,
  // Keep the pool small — free Postgres tiers cap connections (Neon free = 100).
  max: 5,
});

pool.on('error', (err) => {
  console.error('Unexpected pg pool error:', err.message);
});

/* ---------- schema ----------
   Idempotent: safe to run on every boot. Adds columns only if missing.
------------------------------- */
async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id              TEXT PRIMARY KEY,
      email           TEXT UNIQUE NOT NULL,
      password        TEXT NOT NULL,
      full_name       TEXT NOT NULL,
      role            TEXT NOT NULL CHECK (role IN ('student','university','moderator')),
      phone           TEXT,
      whatsapp        TEXT,
      country         TEXT,
      city            TEXT,
      university_id   TEXT,
      student_code    TEXT UNIQUE,
      email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
      phone_verified  BOOLEAN NOT NULL DEFAULT FALSE,
      created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    -- legacy DBs may miss student_code; add it idempotently
    ALTER TABLE users ADD COLUMN IF NOT EXISTS student_code TEXT UNIQUE;

    CREATE TABLE IF NOT EXISTS moderator_invites (
      token         TEXT PRIMARY KEY,
      kind          TEXT NOT NULL DEFAULT 'moderator',
      created_by    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      note          TEXT,
      target_email  TEXT,
      target_name   TEXT,
      university_id TEXT,
      expires_at    TIMESTAMPTZ NOT NULL,
      used_at       TIMESTAMPTZ,
      used_by       TEXT,
      created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS app_events (
      id              TEXT PRIMARY KEY,
      application_id  TEXT NOT NULL,
      actor_id        TEXT,
      actor_role      TEXT,
      type            TEXT NOT NULL,
      message         TEXT NOT NULL,
      created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS password_resets (
      email       TEXT PRIMARY KEY,
      code        TEXT NOT NULL,
      user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      attempts    INTEGER NOT NULL DEFAULT 0,
      expires_at  TIMESTAMPTZ NOT NULL,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS applications (
      id                   TEXT PRIMARY KEY,
      student_id           TEXT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status               TEXT NOT NULL DEFAULT 'draft',
      choices              JSONB NOT NULL DEFAULT '[]'::jsonb,
      documents            JSONB NOT NULL DEFAULT '[]'::jsonb,
      first_payment_paid   BOOLEAN NOT NULL DEFAULT FALSE,
      second_payment_paid  BOOLEAN NOT NULL DEFAULT FALSE,
      created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id          TEXT PRIMARY KEY,
      user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type        TEXT NOT NULL,
      title       TEXT NOT NULL,
      message     TEXT NOT NULL,
      link        TEXT,
      read_at     TIMESTAMPTZ,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS phone_verifications (
      phone       TEXT PRIMARY KEY,
      code        TEXT NOT NULL,
      payload     JSONB NOT NULL,
      attempts    INTEGER NOT NULL DEFAULT 0,
      expires_at  TIMESTAMPTZ NOT NULL,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id              TEXT PRIMARY KEY,
      application_id  TEXT NOT NULL,
      sender_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      recipient_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      content         TEXT NOT NULL,
      read_at         TIMESTAMPTZ,
      created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS reapply_requests (
      id              TEXT PRIMARY KEY,
      application_id  TEXT NOT NULL,
      student_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reason          TEXT,
      same_language   BOOLEAN NOT NULL DEFAULT TRUE,
      handled_at      TIMESTAMPTZ,
      handled_by      TEXT,
      created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_users_email     ON users(LOWER(email));
    CREATE INDEX IF NOT EXISTS idx_apps_student_id ON applications(student_id);
    CREATE INDEX IF NOT EXISTS idx_notif_user_id   ON notifications(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_events_app_id   ON app_events(application_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_msg_app_id      ON messages(application_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_msg_recipient   ON messages(recipient_id, read_at);
    CREATE INDEX IF NOT EXISTS idx_reapply_student ON reapply_requests(student_id, created_at DESC);
  `);
}

// Initialize on import. server.js awaits this before listening (see bottom of file).
export const ready = initSchema().catch(err => {
  console.error('Schema init failed:', err.message);
  throw err;
});

/* ---------- row mappers ---------- */
function toIso(d) { return d instanceof Date ? d.toISOString() : d; }

function rowToUser(r) {
  if (!r) return null;
  return {
    id: r.id, email: r.email, password: r.password, fullName: r.full_name,
    role: r.role, phone: r.phone || undefined, whatsapp: r.whatsapp || undefined,
    country: r.country || undefined, city: r.city || undefined,
    universityId: r.university_id || undefined,
    studentCode: r.student_code || undefined,
    emailVerified: !!r.email_verified,
    phoneVerified: !!r.phone_verified,
    createdAt: toIso(r.created_at),
  };
}

function rowToApp(r) {
  if (!r) return null;
  return {
    id: r.id, studentId: r.student_id, status: r.status,
    choices: r.choices ?? [],
    documents: r.documents ?? [],
    firstPaymentPaid: !!r.first_payment_paid,
    secondPaymentPaid: !!r.second_payment_paid,
    createdAt: toIso(r.created_at),
  };
}

function rowToInvite(r) {
  if (!r) return null;
  return {
    token: r.token,
    kind: r.kind || 'moderator',
    createdBy: r.created_by,
    note: r.note || undefined,
    targetEmail: r.target_email || undefined,
    targetName: r.target_name || undefined,
    universityId: r.university_id || undefined,
    expiresAt: toIso(r.expires_at),
    usedAt: r.used_at ? toIso(r.used_at) : undefined,
    usedBy: r.used_by || undefined,
    createdAt: toIso(r.created_at),
  };
}

function rowToReset(r) {
  if (!r) return null;
  return {
    email: r.email, token: r.code, userId: r.user_id, attempts: r.attempts,
    expiresAt: toIso(r.expires_at), createdAt: toIso(r.created_at),
  };
}

function rowToNotif(r) {
  if (!r) return null;
  return {
    id: r.id, userId: r.user_id, type: r.type,
    title: r.title, message: r.message, link: r.link || undefined,
    readAt: r.read_at ? toIso(r.read_at) : undefined,
    createdAt: toIso(r.created_at),
  };
}

/* ---------- USERS ---------- */
export const users = {
  async findByEmail(email) {
    const r = await pool.query(`SELECT * FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1`, [email]);
    return rowToUser(r.rows[0]);
  },
  async findById(id) {
    const r = await pool.query(`SELECT * FROM users WHERE id = $1`, [id]);
    return rowToUser(r.rows[0]);
  },
  async list() {
    const r = await pool.query(`SELECT * FROM users ORDER BY created_at`);
    return r.rows.map(rowToUser);
  },
  async create(u) {
    await pool.query(
      `INSERT INTO users (id,email,password,full_name,role,phone,whatsapp,country,city,university_id,created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [
        u.id, u.email, u.password, u.fullName, u.role,
        u.phone ?? null, u.whatsapp ?? null,
        u.country ?? null, u.city ?? null,
        u.universityId ?? null,
        u.createdAt ?? new Date().toISOString(),
      ],
    );
    return this.findById(u.id);
  },
  async updateProfile(id, { fullName, phone, whatsapp, country, city }) {
    const cur = await this.findById(id);
    await pool.query(
      `UPDATE users SET full_name = $1, phone = $2, whatsapp = $3, country = $4, city = $5 WHERE id = $6`,
      [
        fullName,
        phone ?? null,
        whatsapp ?? null,
        country ?? cur?.country ?? null,
        city ?? cur?.city ?? null,
        id,
      ],
    );
    return this.findById(id);
  },
  async updatePassword(id, hash) {
    await pool.query(`UPDATE users SET password = $1 WHERE id = $2`, [hash, id]);
  },
  async markEmailVerified(id) {
    await pool.query(`UPDATE users SET email_verified = TRUE WHERE id = $1`, [id]);
  },
  async markPhoneVerified(id) {
    await pool.query(`UPDATE users SET phone_verified = TRUE WHERE id = $1`, [id]);
  },
  /**
   * Generates the next student code for a given country on a given date.
   * Format: AAA999-DDMMYY   (e.g. AZ012-300526 = 12th AZ applicant on 30 May 2026)
   * Two-letter country code + zero-padded daily sequence + DDMMYY.
   * Sequence resets each calendar day per country.
   */
  async nextStudentCode(countryCode, dateIso = new Date().toISOString()) {
    const cc = String(countryCode || 'XX').toUpperCase().slice(0, 2);
    const d  = new Date(dateIso);
    const dd = String(d.getUTCDate()).padStart(2, '0');
    const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
    const yy = String(d.getUTCFullYear()).slice(-2);
    const datePart = `${dd}${mm}${yy}`;
    const prefix = `${cc}`;
    const suffix = `-${datePart}`;
    const r = await pool.query(
      `SELECT student_code FROM users
       WHERE student_code LIKE $1 AND student_code LIKE $2
       ORDER BY student_code DESC LIMIT 1`,
      [`${prefix}%`, `%${suffix}`],
    );
    let seq = 1;
    if (r.rows[0]) {
      const m = String(r.rows[0].student_code).match(/^([A-Z]{2})(\d{3})-(\d{6})$/);
      if (m) seq = Number(m[2]) + 1;
    }
    return `${prefix}${String(seq).padStart(3, '0')}${suffix}`;
  },
  async setStudentCode(id, code) {
    await pool.query(`UPDATE users SET student_code = $1 WHERE id = $2`, [code, id]);
  },
};

/* ---------- INVITES (moderator + university) ---------- */
function makeToken() {
  const bytes = new Uint8Array(24);
  (globalThis.crypto || require('crypto').webcrypto).getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

export const invites = {
  async create({ createdBy, note, kind = 'moderator', targetEmail, targetName, universityId, ttlDays = 7 }) {
    const token = makeToken();
    const expires = new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000).toISOString();
    await pool.query(
      `INSERT INTO moderator_invites
         (token, kind, created_by, note, target_email, target_name, university_id, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [token, kind, createdBy, note ?? null, targetEmail ?? null, targetName ?? null, universityId ?? null, expires],
    );
    return { token, kind, expiresAt: expires };
  },
  async find(token) {
    const r = await pool.query(`SELECT * FROM moderator_invites WHERE token = $1`, [token]);
    return rowToInvite(r.rows[0]);
  },
  async consume(token, newUserId) {
    await pool.query(
      `UPDATE moderator_invites SET used_at = NOW(), used_by = $1 WHERE token = $2`,
      [newUserId, token],
    );
  },
  async listAll(kind) {
    const r = kind
      ? await pool.query(`SELECT * FROM moderator_invites WHERE kind = $1 ORDER BY created_at DESC`, [kind])
      : await pool.query(`SELECT * FROM moderator_invites ORDER BY created_at DESC`);
    return r.rows.map(rowToInvite);
  },
  async delete(token) {
    await pool.query(`DELETE FROM moderator_invites WHERE token = $1`, [token]);
  },
};

/* ---------- APPLICATION EVENTS ---------- */
export const events = {
  async create({ applicationId, actorId, actorRole, type, message }) {
    await pool.query(
      `INSERT INTO app_events (id, application_id, actor_id, actor_role, type, message)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [makeToken(), applicationId, actorId ?? null, actorRole ?? null, type, message],
    );
  },
  async listByApp(applicationId) {
    const r = await pool.query(
      `SELECT * FROM app_events WHERE application_id = $1 ORDER BY created_at ASC`,
      [applicationId],
    );
    return r.rows.map(r => ({
      id: r.id, applicationId: r.application_id, actorId: r.actor_id || undefined,
      actorRole: r.actor_role || undefined, type: r.type, message: r.message,
      createdAt: toIso(r.created_at),
    }));
  },
};

/* ---------- APPLICATIONS ---------- */
export const applications = {
  async findById(id) {
    const r = await pool.query(`SELECT * FROM applications WHERE id = $1`, [id]);
    return rowToApp(r.rows[0]);
  },
  async findByStudent(studentId) {
    const r = await pool.query(`SELECT * FROM applications WHERE student_id = $1`, [studentId]);
    return rowToApp(r.rows[0]);
  },
  async list() {
    const r = await pool.query(`SELECT * FROM applications ORDER BY created_at DESC`);
    return r.rows.map(rowToApp);
  },
  async create(a) {
    await pool.query(
      `INSERT INTO applications
         (id, student_id, status, choices, documents, first_payment_paid, second_payment_paid, created_at)
       VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7, $8)`,
      [
        a.id, a.studentId, a.status,
        JSON.stringify(a.choices),
        JSON.stringify(a.documents),
        !!a.firstPaymentPaid, !!a.secondPaymentPaid,
        a.createdAt ?? new Date().toISOString(),
      ],
    );
    return this.findById(a.id);
  },
  async save(a) {
    await pool.query(
      `UPDATE applications
         SET status = $1, choices = $2::jsonb, documents = $3::jsonb,
             first_payment_paid = $4, second_payment_paid = $5
       WHERE id = $6`,
      [
        a.status,
        JSON.stringify(a.choices),
        JSON.stringify(a.documents),
        !!a.firstPaymentPaid, !!a.secondPaymentPaid,
        a.id,
      ],
    );
    return this.findById(a.id);
  },
};

/* ---------- PASSWORD RESETS (token-based) ----------
   The `code` column stores the long random token from the reset link.
   We still keep the `attempts` column for forward compatibility but it
   isn't really meaningful for opaque tokens.
---------------------------------------------------------- */
export const passwordResets = {
  async upsert({ email, userId, token, ttlMin = 60 }) {
    const expires = new Date(Date.now() + ttlMin * 60 * 1000).toISOString();
    await pool.query(
      `INSERT INTO password_resets (email, code, user_id, attempts, expires_at, created_at)
       VALUES ($1, $2, $3, 0, $4, NOW())
       ON CONFLICT (email) DO UPDATE SET
         code = EXCLUDED.code,
         user_id = EXCLUDED.user_id,
         attempts = 0,
         expires_at = EXCLUDED.expires_at,
         created_at = NOW()`,
      [email.toLowerCase(), token, userId, expires],
    );
    return { expiresAt: expires };
  },
  async findByEmail(email) {
    const r = await pool.query(`SELECT * FROM password_resets WHERE email = $1`, [email.toLowerCase()]);
    return rowToReset(r.rows[0]);
  },
  async findByToken(token) {
    const r = await pool.query(`SELECT * FROM password_resets WHERE code = $1`, [token]);
    return rowToReset(r.rows[0]);
  },
  async consume(token) {
    await pool.query(`DELETE FROM password_resets WHERE code = $1`, [token]);
  },
};

/* ---------- NOTIFICATIONS ---------- */
export const notifications = {
  async listByUser(userId, limit = 50) {
    const r = await pool.query(
      `SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`,
      [userId, limit],
    );
    return r.rows.map(rowToNotif);
  },
  async unreadCount(userId) {
    const r = await pool.query(
      `SELECT COUNT(*) AS c FROM notifications WHERE user_id = $1 AND read_at IS NULL`,
      [userId],
    );
    return Number(r.rows[0].c);
  },
  async create({ id, userId, type, title, message, link }) {
    await pool.query(
      `INSERT INTO notifications (id, user_id, type, title, message, link)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [id, userId, type, title, message, link ?? null],
    );
  },
  async markRead(id, userId) {
    await pool.query(
      `UPDATE notifications SET read_at = NOW() WHERE id = $1 AND user_id = $2`,
      [id, userId],
    );
  },
  async markAllRead(userId) {
    await pool.query(
      `UPDATE notifications SET read_at = NOW() WHERE user_id = $1 AND read_at IS NULL`,
      [userId],
    );
  },
};

/* ---------- PHONE VERIFICATIONS (SMS OTP for student registration) ---------- */
export const phoneVerifications = {
  async upsert({ phone, code, payload, ttlMin = 15 }) {
    const expires = new Date(Date.now() + ttlMin * 60 * 1000).toISOString();
    await pool.query(
      `INSERT INTO phone_verifications (phone, code, payload, attempts, expires_at, created_at)
       VALUES ($1, $2, $3::jsonb, 0, $4, NOW())
       ON CONFLICT (phone) DO UPDATE SET
         code = EXCLUDED.code,
         payload = EXCLUDED.payload,
         attempts = 0,
         expires_at = EXCLUDED.expires_at,
         created_at = NOW()`,
      [phone, code, JSON.stringify(payload), expires],
    );
    return { expiresAt: expires };
  },
  async find(phone) {
    const r = await pool.query(`SELECT * FROM phone_verifications WHERE phone = $1`, [phone]);
    const row = r.rows[0];
    if (!row) return null;
    return {
      phone: row.phone, code: row.code, payload: row.payload,
      attempts: row.attempts,
      expiresAt: toIso(row.expires_at), createdAt: toIso(row.created_at),
    };
  },
  async incrementAttempts(phone) {
    await pool.query(`UPDATE phone_verifications SET attempts = attempts + 1 WHERE phone = $1`, [phone]);
  },
  async consume(phone) {
    await pool.query(`DELETE FROM phone_verifications WHERE phone = $1`, [phone]);
  },
};

/* ---------- MESSAGES (student ↔ university chat) ---------- */
export const messages = {
  async create({ applicationId, senderId, recipientId, content }) {
    const id = makeToken();
    await pool.query(
      `INSERT INTO messages (id, application_id, sender_id, recipient_id, content)
       VALUES ($1, $2, $3, $4, $5)`,
      [id, applicationId, senderId, recipientId, content],
    );
    const r = await pool.query(`SELECT * FROM messages WHERE id = $1`, [id]);
    return rowToMessage(r.rows[0]);
  },
  async listByApp(applicationId) {
    const r = await pool.query(
      `SELECT * FROM messages WHERE application_id = $1 ORDER BY created_at ASC`,
      [applicationId],
    );
    return r.rows.map(rowToMessage);
  },
  async markRead(applicationId, recipientId) {
    await pool.query(
      `UPDATE messages SET read_at = NOW()
       WHERE application_id = $1 AND recipient_id = $2 AND read_at IS NULL`,
      [applicationId, recipientId],
    );
  },
  async unreadCount(userId) {
    const r = await pool.query(
      `SELECT COUNT(*) AS c FROM messages WHERE recipient_id = $1 AND read_at IS NULL`,
      [userId],
    );
    return Number(r.rows[0].c);
  },
};

function rowToMessage(r) {
  if (!r) return null;
  return {
    id: r.id, applicationId: r.application_id,
    senderId: r.sender_id, recipientId: r.recipient_id,
    content: r.content,
    readAt: r.read_at ? toIso(r.read_at) : undefined,
    createdAt: toIso(r.created_at),
  };
}

/* ---------- REAPPLY REQUESTS ---------- */
export const reapplyRequests = {
  async create({ applicationId, studentId, reason, sameLanguage }) {
    const id = makeToken();
    await pool.query(
      `INSERT INTO reapply_requests (id, application_id, student_id, reason, same_language)
       VALUES ($1, $2, $3, $4, $5)`,
      [id, applicationId, studentId, reason || null, !!sameLanguage],
    );
    return { id, applicationId, studentId, reason, sameLanguage };
  },
  async listPending() {
    const r = await pool.query(
      `SELECT * FROM reapply_requests WHERE handled_at IS NULL ORDER BY created_at DESC`,
    );
    return r.rows.map(rowToReapply);
  },
  async handle(id, moderatorId) {
    await pool.query(
      `UPDATE reapply_requests SET handled_at = NOW(), handled_by = $1 WHERE id = $2`,
      [moderatorId, id],
    );
  },
};

function rowToReapply(r) {
  if (!r) return null;
  return {
    id: r.id, applicationId: r.application_id, studentId: r.student_id,
    reason: r.reason || undefined, sameLanguage: !!r.same_language,
    handledAt: r.handled_at ? toIso(r.handled_at) : undefined,
    handledBy: r.handled_by || undefined,
    createdAt: toIso(r.created_at),
  };
}

/* ---------- STATS ---------- */
export async function stats() {
  const apps = await applications.list();
  const total = apps.reduce((acc, a) => acc + a.choices.length, 0);
  const accepted = apps.reduce(
    (acc, a) => acc + a.choices.filter(c => c.status === 'approved').length, 0,
  );
  return { applications: total, accepted };
}

export default pool;
