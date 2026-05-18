import nodemailer from 'nodemailer';

let transporter = null;
let usingEthereal = false;

async function getTransporter() {
  if (transporter) return transporter;

  if (process.env.SMTP_HOST) {
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });
    console.log(`✉  Mailer: ${process.env.SMTP_HOST}`);
    return transporter;
  }

  try {
    const test = await nodemailer.createTestAccount();
    transporter = nodemailer.createTransport({
      host: test.smtp.host, port: test.smtp.port, secure: test.smtp.secure,
      auth: { user: test.user, pass: test.pass },
    });
    usingEthereal = true;
    console.log(`✉  Mailer: Ethereal (dev) — mailler https://ethereal.email/messages adresində görünür`);
    return transporter;
  } catch {
    console.warn('⚠  Mailer disabled (no SMTP, no Ethereal). Codes will print to console.');
    transporter = null;
    return null;
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/** Send a one-time password-reset LINK by email. The token is embedded in the URL —
 *  user clicks → lands on /reset-password/:token where they enter a new password.
 *  No 6-digit codes anywhere in this flow.
 */
export async function sendPasswordResetLink(to, name, link) {
  const tr = await getTransporter();

  if (!tr) {
    console.log(`\n🔑 [DEV] Password reset link for ${to}: ${link}\n`);
    return { previewUrl: null };
  }

  const html = `
    <div style="font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 560px; margin: 0 auto; padding: 32px 24px; color: #1e293b;">
      <div style="text-align: center; margin-bottom: 32px;">
        <div style="display: inline-block; width: 56px; height: 56px; background: linear-gradient(135deg, #4f46e5, #7c3aed); border-radius: 14px; line-height: 56px; color: white; font-size: 28px; font-weight: 800;">E</div>
      </div>
      <h1 style="font-size: 22px; font-weight: 700; color: #0f172a; margin: 0 0 12px;">Şifrəni bərpa edin</h1>
      <p style="font-size: 15px; line-height: 1.6; color: #475569; margin: 0 0 24px;">
        Salam <strong>${escapeHtml(name)}</strong>,<br>
        Şifrənizi yeniləmək üçün aşağıdakı düyməyə basın. Link <strong>1 saat</strong> ərzində etibarlıdır və yalnız bir dəfə istifadə oluna bilər.
      </p>
      <div style="text-align: center; margin: 28px 0;">
        <a href="${link}" style="display: inline-block; background: linear-gradient(135deg, #4f46e5, #7c3aed); color: white; text-decoration: none; padding: 14px 32px; border-radius: 12px; font-weight: 700; font-size: 15px;">
          Şifrəni dəyiş
        </a>
      </div>
      <p style="font-size: 12px; color: #94a3b8; line-height: 1.6; word-break: break-all;">
        Düymə işləmirsə bu linki brauzerə yapışdırın:<br>${escapeHtml(link)}
      </p>
      <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 28px 0;">
      <p style="font-size: 12px; color: #94a3b8; text-align: center; margin: 0;">
        EduGate · Bu sorğunu siz göndərməmisinizsə, bu maili nəzərə almayın və şifrəniz dəyişməyəcək.
      </p>
    </div>
  `;

  const info = await tr.sendMail({
    from: process.env.MAIL_FROM || '"EduGate" <noreply@edugate.local>',
    to, subject: 'EduGate — Şifrə bərpa linki', html,
  });

  console.log(`📧 Reset linki göndərildi → ${to}`);
  const previewUrl = usingEthereal ? nodemailer.getTestMessageUrl(info) : null;
  if (previewUrl) console.log(`   Preview: ${previewUrl}`);
  return { previewUrl };
}

/* ---------- University rep invite (email with secret signup link) ---------- */
export async function sendUniInviteLink(to, name, link, universityName) {
  const tr = await getTransporter();
  if (!tr) {
    console.log(`\n🎓 [DEV] University rep invite for ${to} (${universityName || '—'}): ${link}\n`);
    return { previewUrl: null };
  }

  const html = `
    <div style="font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 560px; margin: 0 auto; padding: 32px 24px; color: #1e293b;">
      <div style="text-align: center; margin-bottom: 32px;">
        <div style="display: inline-block; width: 56px; height: 56px; background: linear-gradient(135deg, #4f46e5, #7c3aed); border-radius: 14px; line-height: 56px; color: white; font-size: 28px; font-weight: 800;">E</div>
      </div>
      <h1 style="font-size: 22px; font-weight: 700; color: #0f172a; margin: 0 0 12px;">Universitet təmsilçisi dəvəti</h1>
      <p style="font-size: 15px; line-height: 1.6; color: #475569; margin: 0 0 20px;">
        Salam${name ? ' <strong>' + escapeHtml(name) + '</strong>' : ''},<br>
        EduGate platforması üzərindən ${universityName ? '<strong>' + escapeHtml(universityName) + '</strong>' : 'bir universitet'} təmsilçisi kimi qeydiyyatdan keçmək üçün sizə xüsusi link göndərilir. Bu link <strong>yalnız bir dəfə</strong> istifadə oluna bilər.
      </p>
      <div style="text-align: center; margin: 28px 0;">
        <a href="${link}" style="display: inline-block; background: linear-gradient(135deg, #4f46e5, #7c3aed); color: white; text-decoration: none; padding: 14px 28px; border-radius: 12px; font-weight: 700; font-size: 15px;">
          Qeydiyyatı tamamla
        </a>
      </div>
      <p style="font-size: 12px; color: #94a3b8; line-height: 1.6; word-break: break-all;">
        Link işləmirsə brauzerə yapışdırın:<br>${escapeHtml(link)}
      </p>
      <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 28px 0;">
      <p style="font-size: 12px; color: #94a3b8; text-align: center; margin: 0;">
        EduGate · Linkin müddəti 7 gündür. Bu maili gözləmirdinizsə nəzərə almayın.
      </p>
    </div>
  `;

  const info = await tr.sendMail({
    from: process.env.MAIL_FROM || '"EduGate" <noreply@edugate.local>',
    to, subject: 'EduGate — Universitet təmsilçisi dəvəti', html,
  });

  console.log(`📧 Universitet dəvəti göndərildi → ${to}`);
  const previewUrl = usingEthereal ? nodemailer.getTestMessageUrl(info) : null;
  if (previewUrl) console.log(`   Preview: ${previewUrl}`);
  return { previewUrl };
}

/* ---------- SMS (Twilio in prod, console in dev) ----------
   Configure via .env:
     SMS_PROVIDER=twilio
     TWILIO_ACCOUNT_SID=AC...
     TWILIO_AUTH_TOKEN=...
     TWILIO_FROM=+15551234567
   If SMS_PROVIDER is anything else (or unset) we just log to the server console.
-------------------------------------------------------------- */
let twilioClient = null;
let twilioInitErr = null;

async function getTwilioClient() {
  if (twilioClient || twilioInitErr) return twilioClient;
  if (process.env.SMS_PROVIDER !== 'twilio') return null;
  if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN || !process.env.TWILIO_FROM) {
    twilioInitErr = 'twilio_env_missing';
    console.warn('⚠  Twilio configured but TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / TWILIO_FROM is missing.');
    return null;
  }
  try {
    const { default: Twilio } = await import('twilio');
    twilioClient = Twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
    console.log(`📱 SMS: Twilio (from ${process.env.TWILIO_FROM})`);
    return twilioClient;
  } catch (e) {
    twilioInitErr = e.message;
    console.warn('⚠  Twilio SDK not installed. Run: npm install twilio   |   error:', e.message);
    return null;
  }
}

/** Generic SMS send. Falls back to console.log if no provider is configured. */
export async function sendSms(to, body) {
  if (!to) return { ok: false, error: 'no_recipient' };
  const client = await getTwilioClient();
  if (!client) {
    console.log(`\n📱 [DEV SMS] → ${to}\n   ${body}\n`);
    return { ok: true, dev: true };
  }
  try {
    const msg = await client.messages.create({
      from: process.env.TWILIO_FROM,
      to,
      body,
    });
    console.log(`📱 SMS göndərildi → ${to} (sid: ${msg.sid})`);
    return { ok: true, sid: msg.sid };
  } catch (e) {
    console.error(`SMS send failed (${to}):`, e.message);
    return { ok: false, error: e.message };
  }
}

/** Registration OTP: short body, just the code + a nudge not to share it. */
export async function sendSmsOtp(phone, code) {
  return sendSms(phone, `EduGate: təsdiq kodunuz ${code}. Heç kimlə paylaşmayın.`);
}
