require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const { OAuthClient } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Security Middleware ───────────────────────────────────────────────────────

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'fonts.googleapis.com'],
      styleSrc: ["'self'", "'unsafe-inline'", 'fonts.googleapis.com', 'fonts.gstatic.com'],
      fontSrc: ["'self'", 'fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
    },
  },
}));

// CORS — allow any origin to call /oauth/* and /sdk/* endpoints
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Key'],
}));

app.use(cookieParser());

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'too_many_requests', message: 'Too many attempts. Please wait 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/oauth/token', authLimiter);

// ── Static Files ──────────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, 'public')));
app.use('/sdk', express.static(path.join(__dirname, 'sdk'), {
  setHeaders: (res) => {
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Cache-Control', 'public, max-age=3600');
  }
}));

// ── Page Routes ───────────────────────────────────────────────────────────────

app.get('/', (req, res) => res.redirect('/login'));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/consent', (req, res) => res.sendFile(path.join(__dirname, 'public', 'consent.html')));
app.get('/verify', (req, res) => res.sendFile(path.join(__dirname, 'public', 'verify.html')));

// ── Public client info (for consent screen) ───────────────────────────────────

app.get('/api/client-info', (req, res) => {
  const { client_id } = req.query;
  if (!client_id) return res.status(400).json({ error: 'missing client_id' });

  const client = OAuthClient.findByClientId.get(client_id);
  if (!client) return res.status(404).json({ error: 'client_not_found' });

  // Return only public-safe fields
  return res.json({
    name: client.name,
    description: client.description,
    logo_url: client.logo_url,
    scopes: client.scopes,
  });
});

// ── API + OAuth Routes ────────────────────────────────────────────────────────

app.use('/', authRoutes);
app.use('/', adminRoutes);

// ── 404 Handler ───────────────────────────────────────────────────────────────

app.use((req, res) => {
  if (req.accepts('html')) {
    return res.status(404).redirect('/login');
  }
  return res.status(404).json({ error: 'not_found' });
});

// ── Error Handler ─────────────────────────────────────────────────────────────

app.use((err, req, res, next) => {
  console.error('[Error]', err);
  return res.status(500).json({ error: 'internal_server_error', message: 'Something went wrong' });
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🔐 KP Auth Server running`);
  console.log(`   Local:   http://localhost:${PORT}`);
  console.log(`   Env:     ${process.env.NODE_ENV || 'development'}`);
  console.log(`\n   Endpoints:`);
  console.log(`   ├── GET  /login`);
  console.log(`   ├── GET  /signup`);
  console.log(`   ├── GET  /oauth/authorize`);
  console.log(`   ├── POST /oauth/token`);
  console.log(`   ├── GET  /oauth/userinfo`);
  console.log(`   ├── POST /admin/clients`);
  console.log(`   └── GET  /.well-known/openid-configuration\n`);
});
