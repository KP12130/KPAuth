const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { User, EmailVerification, OAuthClient, AuthCode, RefreshToken, Session } = require('../db');
const { sendVerificationEmail } = require('../email');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_IN_PRODUCTION';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '15m';
const REFRESH_EXPIRES_DAYS = parseInt(process.env.REFRESH_TOKEN_EXPIRES_DAYS || '30');
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function generateToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

function futureDate(seconds) {
  return new Date(Date.now() + seconds * 1000).toISOString();
}

function makeAccessToken(user, scopes) {
  const claims = {
    sub: user.id,
    email: user.email,
    name: user.name,
    email_verified: user.verified === 1,
    scope: scopes,
    iss: BASE_URL,
    aud: 'kp-auth',
  };
  return jwt.sign(claims, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function makeIdToken(user, clientId, nonce) {
  const claims = {
    sub: user.id,
    email: user.email,
    name: user.name,
    email_verified: user.verified === 1,
    iss: BASE_URL,
    aud: clientId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  };
  if (nonce) claims.nonce = nonce;
  return jwt.sign(claims, JWT_SECRET);
}

function requireSession(req, res, next) {
  const sessionId = req.cookies?.kp_session;
  if (!sessionId) return null;
  const session = Session.find.get(sessionId);
  if (!session) return null;
  const user = User.findById.get(session.user_id);
  if (!user) return null;
  req.sessionId = sessionId;
  req.user = user;
  return user;
}

// ─── /oauth/authorize ─────────────────────────────────────────────────────────
// Step 1: App redirects user here to start the login flow

router.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, nonce, code_challenge, code_challenge_method } = req.query;

  // Validate required params
  if (!client_id || !redirect_uri || response_type !== 'code') {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Missing or invalid parameters' });
  }

  // Validate client
  const client = OAuthClient.findByClientId.get(client_id);
  if (!client) {
    return res.status(400).json({ error: 'invalid_client', error_description: 'Unknown client_id' });
  }

  // Validate redirect_uri
  const allowedUris = JSON.parse(client.redirect_uris);
  if (!allowedUris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'invalid_redirect_uri', error_description: 'redirect_uri not allowed' });
  }

  // Check if user is already logged in via session cookie
  const loggedInUser = requireSession(req, res, null);

  if (loggedInUser) {
    // Show consent screen
    return res.redirect(
      `/consent?client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent(redirect_uri)}&scope=${encodeURIComponent(scope || 'openid email profile')}&state=${encodeURIComponent(state || '')}&nonce=${encodeURIComponent(nonce || '')}&code_challenge=${encodeURIComponent(code_challenge || '')}&code_challenge_method=${encodeURIComponent(code_challenge_method || '')}`
    );
  }

  // Not logged in — redirect to login page, preserving all params
  const loginUrl = `/login?` + new URLSearchParams({
    client_id, redirect_uri, scope: scope || 'openid email profile',
    state: state || '', nonce: nonce || '',
    code_challenge: code_challenge || '', code_challenge_method: code_challenge_method || ''
  }).toString();

  return res.redirect(loginUrl);
});

// ─── /oauth/consent (POST) ────────────────────────────────────────────────────
// User clicked "Allow" on the consent screen

router.post('/oauth/consent', (req, res) => {
  const { client_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, action } = req.body;

  const user = requireSession(req, res, null);
  if (!user) {
    return res.redirect('/login');
  }

  if (action === 'deny') {
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('error', 'access_denied');
    if (state) redirectUrl.searchParams.set('state', state);
    return res.redirect(redirectUrl.toString());
  }

  // Generate authorization code
  const code = generateToken(32);
  const scopes = scope || 'openid email profile';
  AuthCode.create.run(
    code, client_id, user.id, redirect_uri, scopes,
    code_challenge || null, code_challenge_method || null,
    futureDate(300) // 5 minute expiry
  );

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (state) redirectUrl.searchParams.set('state', state);

  return res.redirect(redirectUrl.toString());
});

// ─── /oauth/token ─────────────────────────────────────────────────────────────
// Step 2: App exchanges auth code for tokens

router.post('/oauth/token', express.urlencoded({ extended: false }), express.json(), (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token, code_verifier } = req.body;

  // ── Authorization Code Grant ──
  if (grant_type === 'authorization_code') {
    if (!code || !redirect_uri || !client_id) {
      return res.status(400).json({ error: 'invalid_request' });
    }

    const client = OAuthClient.findByClientId.get(client_id);
    if (!client || client.client_secret !== client_secret) {
      return res.status(401).json({ error: 'invalid_client' });
    }

    const authCode = AuthCode.findByCode.get(code);
    if (!authCode) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Code not found or already used' });
    }

    if (new Date(authCode.expires_at) < new Date()) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Code expired' });
    }

    if (authCode.client_id !== client_id || authCode.redirect_uri !== redirect_uri) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Code mismatch' });
    }

    // PKCE verification
    if (authCode.code_challenge) {
      if (!code_verifier) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'code_verifier required' });
      }
      const verifierHash = crypto.createHash('sha256').update(code_verifier).digest('base64url');
      if (verifierHash !== authCode.code_challenge) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
      }
    }

    AuthCode.markUsed.run(code);

    const user = User.findById.get(authCode.user_id);
    if (!user) return res.status(400).json({ error: 'invalid_grant' });

    const accessToken = makeAccessToken(user, authCode.scopes);
    const idToken = makeIdToken(user, client_id, null);
    const refreshTokenValue = generateToken(48);

    RefreshToken.create.run(
      refreshTokenValue, user.id, client_id, authCode.scopes,
      futureDate(REFRESH_EXPIRES_DAYS * 86400)
    );

    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900,
      refresh_token: refreshTokenValue,
      id_token: idToken,
      scope: authCode.scopes,
    });
  }

  // ── Refresh Token Grant ──
  if (grant_type === 'refresh_token') {
    if (!refresh_token) return res.status(400).json({ error: 'invalid_request' });

    const storedToken = RefreshToken.find.get(refresh_token);
    if (!storedToken) return res.status(400).json({ error: 'invalid_grant', error_description: 'Refresh token invalid or revoked' });

    if (new Date(storedToken.expires_at) < new Date()) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Refresh token expired' });
    }

    const user = User.findById.get(storedToken.user_id);
    if (!user) return res.status(400).json({ error: 'invalid_grant' });

    const accessToken = makeAccessToken(user, storedToken.scopes);
    const newRefreshToken = generateToken(48);

    // Rotate refresh token
    RefreshToken.revoke.run(refresh_token);
    RefreshToken.create.run(
      newRefreshToken, user.id, storedToken.client_id, storedToken.scopes,
      futureDate(REFRESH_EXPIRES_DAYS * 86400)
    );

    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900,
      refresh_token: newRefreshToken,
      scope: storedToken.scopes,
    });
  }

  return res.status(400).json({ error: 'unsupported_grant_type' });
});

// ─── /oauth/userinfo ──────────────────────────────────────────────────────────
// App uses access token to get user profile

router.get('/oauth/userinfo', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  try {
    const decoded = jwt.verify(authHeader.slice(7), JWT_SECRET);
    const user = User.findById.get(decoded.sub);
    if (!user) return res.status(404).json({ error: 'user_not_found' });

    return res.json({
      sub: user.id,
      email: user.email,
      email_verified: user.verified === 1,
      name: user.name,
      picture: user.avatar_url || null,
    });
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
});

// ─── /oauth/revoke ────────────────────────────────────────────────────────────

router.post('/oauth/revoke', express.urlencoded({ extended: false }), (req, res) => {
  const { token } = req.body;
  if (token) RefreshToken.revoke.run(token);
  return res.status(200).json({ success: true });
});

// ─── /.well-known/openid-configuration ───────────────────────────────────────
// OIDC discovery endpoint — lets apps auto-configure

router.get('/.well-known/openid-configuration', (req, res) => {
  return res.json({
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/oauth/authorize`,
    token_endpoint: `${BASE_URL}/oauth/token`,
    userinfo_endpoint: `${BASE_URL}/oauth/userinfo`,
    revocation_endpoint: `${BASE_URL}/oauth/revoke`,
    jwks_uri: `${BASE_URL}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['HS256'],
    scopes_supported: ['openid', 'email', 'profile'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    claims_supported: ['sub', 'email', 'email_verified', 'name', 'picture'],
  });
});

// ─── /api/register ────────────────────────────────────────────────────────────
// Create a new KP user account

router.post('/api/register', express.json(), async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password || !name) {
    return res.status(400).json({ error: 'missing_fields', message: 'Email, password, and name are required' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'weak_password', message: 'Password must be at least 8 characters' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'invalid_email', message: 'Invalid email address' });
  }

  const existing = User.findByEmail.get(email.toLowerCase());
  if (existing) {
    return res.status(409).json({ error: 'email_taken', message: 'An account with this email already exists' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const userId = uuidv4();
    User.create.run(userId, email.toLowerCase(), passwordHash, name.trim());

    // Send verification email
    const verifyToken = generateToken(32);
    EmailVerification.create.run(verifyToken, userId, futureDate(86400)); // 24 hours

    try {
      await sendVerificationEmail(email, name.trim(), verifyToken);
    } catch (emailErr) {
      console.error('[Email] Failed to send verification email:', emailErr.message);
    }

    return res.status(201).json({
      success: true,
      message: 'Account created! Please check your email to verify your account.',
    });
  } catch (err) {
    console.error('[Register]', err);
    return res.status(500).json({ error: 'server_error', message: 'Registration failed' });
  }
});

// ─── /api/login ───────────────────────────────────────────────────────────────
// Login and create a session (used by the login page)

router.post('/api/login', express.json(), async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'missing_fields', message: 'Email and password required' });
  }

  const user = User.findByEmail.get(email.toLowerCase());
  if (!user) {
    return res.status(401).json({ error: 'invalid_credentials', message: 'Invalid email or password' });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ error: 'invalid_credentials', message: 'Invalid email or password' });
  }

  if (!user.verified) {
    return res.status(403).json({ error: 'email_not_verified', message: 'Please verify your email before signing in' });
  }

  // Create session
  const sessionId = generateToken(32);
  Session.create.run(sessionId, user.id, futureDate(30 * 86400));

  res.cookie('kp_session', sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000,
    path: '/',
  });

  return res.json({ success: true, user: { id: user.id, name: user.name, email: user.email } });
});

// ─── /api/logout ──────────────────────────────────────────────────────────────

router.post('/api/logout', (req, res) => {
  const sessionId = req.cookies?.kp_session;
  if (sessionId) {
    Session.delete.run(sessionId);
    res.clearCookie('kp_session');
  }
  return res.json({ success: true });
});

// ─── /verify-email ────────────────────────────────────────────────────────────

router.get('/verify-email', (req, res) => {
  const { token } = req.query;
  if (!token) return res.redirect('/verify?status=invalid');

  const record = EmailVerification.findByToken.get(token);
  if (!record) return res.redirect('/verify?status=invalid');

  if (new Date(record.expires_at) < new Date()) {
    return res.redirect('/verify?status=expired');
  }

  User.verify.run(record.user_id);
  EmailVerification.markUsed.run(token);

  return res.redirect('/verify?status=success');
});

// ─── /api/me ──────────────────────────────────────────────────────────────────
// Returns current session user info

router.get('/api/me', (req, res) => {
  const user = requireSession(req, res, null);
  if (!user) return res.status(401).json({ error: 'not_authenticated' });
  return res.json({ id: user.id, name: user.name, email: user.email, verified: user.verified === 1 });
});

module.exports = router;
