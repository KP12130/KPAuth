const express = require('express');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { OAuthClient } = require('../db');

const router = express.Router();

// Simple admin key protection — set ADMIN_KEY in your .env
function requireAdminKey(req, res, next) {
  const adminKey = process.env.ADMIN_KEY;
  if (!adminKey) return next(); // If no key set, allow (dev mode)
  const provided = req.headers['x-admin-key'] || req.query.admin_key;
  if (provided !== adminKey) {
    return res.status(401).json({ error: 'unauthorized', message: 'Invalid admin key' });
  }
  next();
}

// ─── Register a new OAuth client (app) ───────────────────────────────────────

router.post('/admin/clients', requireAdminKey, express.json(), (req, res) => {
  const { name, description, redirect_uris, scopes, logo_url } = req.body;

  if (!name || !redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
    return res.status(400).json({ error: 'invalid_request', message: 'name and redirect_uris[] are required' });
  }

  const clientId = `kp_${crypto.randomBytes(12).toString('hex')}`;
  const clientSecret = `kps_${crypto.randomBytes(24).toString('hex')}`;
  const id = uuidv4();

  OAuthClient.create.run(
    id,
    clientId,
    clientSecret,
    name.trim(),
    description?.trim() || null,
    JSON.stringify(redirect_uris),
    scopes || 'openid email profile',
    logo_url || null
  );

  return res.status(201).json({
    success: true,
    message: `OAuth client "${name}" created.`,
    client: {
      client_id: clientId,
      client_secret: clientSecret,
      name,
      redirect_uris,
      scopes: scopes || 'openid email profile',
    },
    warning: 'Save the client_secret now — it will not be shown again.',
  });
});

// ─── List all clients ─────────────────────────────────────────────────────────

router.get('/admin/clients', requireAdminKey, (req, res) => {
  const clients = OAuthClient.findAll.all().map(c => ({
    ...c,
    redirect_uris: JSON.parse(c.redirect_uris),
  }));
  return res.json({ clients });
});

// ─── Delete a client ──────────────────────────────────────────────────────────

router.delete('/admin/clients/:clientId', requireAdminKey, (req, res) => {
  const { clientId } = req.params;
  const client = OAuthClient.findByClientId.get(clientId);
  if (!client) return res.status(404).json({ error: 'not_found' });

  OAuthClient.delete.run(clientId);
  return res.json({ success: true, message: `Client ${clientId} deleted.` });
});

module.exports = router;
