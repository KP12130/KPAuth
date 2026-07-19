const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp-relay.brevo.com',
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

const FROM = `"${process.env.SMTP_FROM_NAME || 'KP Auth'}" <${process.env.SMTP_FROM || 'no-reply@kp.app'}>`;

/**
 * Send email verification link to a new user.
 */
async function sendVerificationEmail(to, name, token) {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const verifyUrl = `${BASE_URL}/verify-email?token=${token}`;

  await transporter.sendMail({
    from: FROM,
    to,
    subject: 'Verify your KP account',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0f; color: #e2e8f0; margin: 0; padding: 0; }
          .wrapper { max-width: 520px; margin: 40px auto; }
          .card { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border: 1px solid rgba(99,102,241,0.3); border-radius: 16px; padding: 40px; }
          .logo { display: flex; align-items: center; gap: 10px; margin-bottom: 32px; }
          .logo-mark { width: 36px; height: 36px; background: linear-gradient(135deg, #6366f1, #8b5cf6); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 16px; color: white; }
          .logo-text { font-size: 20px; font-weight: 700; color: white; }
          h1 { color: white; font-size: 24px; margin: 0 0 12px; }
          p { color: #94a3b8; line-height: 1.6; margin: 0 0 24px; }
          .btn { display: inline-block; background: linear-gradient(135deg, #6366f1, #8b5cf6); color: white !important; text-decoration: none; padding: 14px 32px; border-radius: 10px; font-weight: 600; font-size: 15px; }
          .footer { margin-top: 32px; padding-top: 24px; border-top: 1px solid rgba(255,255,255,0.1); color: #475569; font-size: 13px; }
          .link { color: #6366f1; word-break: break-all; }
        </style>
      </head>
      <body>
        <div class="wrapper">
          <div class="card">
            <div class="logo">
              <div class="logo-mark">KP</div>
              <div class="logo-text">KP Auth</div>
            </div>
            <h1>Verify your email</h1>
            <p>Hi ${name}, thanks for signing up! Click the button below to verify your email address and activate your KP account.</p>
            <a href="${verifyUrl}" class="btn">Verify Email Address</a>
            <div class="footer">
              <p>This link expires in 24 hours. If you didn't create a KP account, you can safely ignore this email.</p>
              <p>Or copy this link: <span class="link">${verifyUrl}</span></p>
            </div>
          </div>
        </div>
      </body>
      </html>
    `,
  });
}

/**
 * Send a password reset email.
 */
async function sendPasswordResetEmail(to, name, token) {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const resetUrl = `${BASE_URL}/reset-password?token=${token}`;

  await transporter.sendMail({
    from: FROM,
    to,
    subject: 'Reset your KP password',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0f; color: #e2e8f0; margin: 0; padding: 0; }
          .wrapper { max-width: 520px; margin: 40px auto; }
          .card { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border: 1px solid rgba(99,102,241,0.3); border-radius: 16px; padding: 40px; }
          .logo { display: flex; align-items: center; gap: 10px; margin-bottom: 32px; }
          .logo-mark { width: 36px; height: 36px; background: linear-gradient(135deg, #6366f1, #8b5cf6); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 16px; color: white; }
          .logo-text { font-size: 20px; font-weight: 700; color: white; }
          h1 { color: white; font-size: 24px; margin: 0 0 12px; }
          p { color: #94a3b8; line-height: 1.6; margin: 0 0 24px; }
          .btn { display: inline-block; background: linear-gradient(135deg, #6366f1, #8b5cf6); color: white !important; text-decoration: none; padding: 14px 32px; border-radius: 10px; font-weight: 600; font-size: 15px; }
          .footer { margin-top: 32px; padding-top: 24px; border-top: 1px solid rgba(255,255,255,0.1); color: #475569; font-size: 13px; }
        </style>
      </head>
      <body>
        <div class="wrapper">
          <div class="card">
            <div class="logo">
              <div class="logo-mark">KP</div>
              <div class="logo-text">KP Auth</div>
            </div>
            <h1>Reset your password</h1>
            <p>Hi ${name}, we received a request to reset your KP account password. Click below to choose a new password.</p>
            <a href="${resetUrl}" class="btn">Reset Password</a>
            <div class="footer">
              <p>This link expires in 1 hour. If you didn't request a password reset, you can safely ignore this email.</p>
            </div>
          </div>
        </div>
      </body>
      </html>
    `,
  });
}

module.exports = { sendVerificationEmail, sendPasswordResetEmail };
