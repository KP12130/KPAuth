/**
 * KP Auth - Sign in with KP Button SDK
 * 
 * Usage:
 *   <script src="https://your-kp-auth.onrender.com/sdk/signin-button.js"><\/script>
 *   <div
 *     id="kp-signin"
 *     data-client-id="kp_your_client_id"
 *     data-redirect-uri="https://yourapp.com/auth/callback"
 *     data-scope="openid email profile"
 *   ></div>
 */
(function () {
  'use strict';

  // ── Config ─────────────────────────────────────────────────────────────────
  const KP_AUTH_BASE = (function () {
    const scripts = document.querySelectorAll('script[src*="signin-button.js"]');
    if (scripts.length > 0) {
      try {
        const url = new URL(scripts[scripts.length - 1].src);
        return url.origin;
      } catch (_) {}
    }
    return 'https://kp-auth.onrender.com';
  })();

  // ── Styles ─────────────────────────────────────────────────────────────────
  const CSS = `
    .kp-signin-btn {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 11px 20px;
      background: linear-gradient(135deg, #6366f1, #8b5cf6);
      color: #ffffff;
      font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', sans-serif;
      font-size: 14px;
      font-weight: 600;
      border: none;
      border-radius: 10px;
      cursor: pointer;
      text-decoration: none;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      box-shadow: 0 4px 16px rgba(99, 102, 241, 0.35);
      white-space: nowrap;
      user-select: none;
      letter-spacing: -0.1px;
    }

    .kp-signin-btn:hover {
      transform: translateY(-1px);
      box-shadow: 0 6px 24px rgba(99, 102, 241, 0.5);
      filter: brightness(1.07);
    }

    .kp-signin-btn:active {
      transform: translateY(0);
      box-shadow: 0 3px 10px rgba(99, 102, 241, 0.3);
    }

    .kp-signin-btn .kp-logo {
      width: 22px;
      height: 22px;
      background: rgba(255,255,255,0.2);
      border-radius: 5px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 11px;
      letter-spacing: -0.5px;
      flex-shrink: 0;
    }

    .kp-signin-btn .kp-text {
      line-height: 1;
    }

    /* Dark variant */
    .kp-signin-btn.kp-dark {
      background: #0f0f1a;
      border: 1px solid rgba(99,102,241,0.4);
      color: #e2e8f0;
      box-shadow: 0 4px 16px rgba(0,0,0,0.3);
    }

    .kp-signin-btn.kp-dark:hover {
      background: #1a1a2e;
      border-color: rgba(99,102,241,0.7);
      box-shadow: 0 6px 20px rgba(0,0,0,0.4), 0 0 0 1px rgba(99,102,241,0.3);
    }

    /* Light variant */
    .kp-signin-btn.kp-light {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      color: #1e1e3a;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }

    .kp-signin-btn.kp-light .kp-logo {
      background: linear-gradient(135deg, #6366f1, #8b5cf6);
      color: white;
    }

    .kp-signin-btn.kp-light:hover {
      box-shadow: 0 4px 16px rgba(0,0,0,0.12);
      border-color: #c7d2fe;
    }
  `;

  // ── Inject styles ─────────────────────────────────────────────────────────
  if (!document.getElementById('kp-signin-styles')) {
    const style = document.createElement('style');
    style.id = 'kp-signin-styles';
    style.textContent = CSS;
    document.head.appendChild(style);
  }

  // ── PKCE helpers ──────────────────────────────────────────────────────────
  function generateState() {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
  }

  async function generatePKCE() {
    const verifier = generateState() + generateState();
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return { verifier, challenge };
  }

  // ── Render buttons ────────────────────────────────────────────────────────
  async function renderButton(container) {
    const clientId = container.dataset.clientId;
    const redirectUri = container.dataset.redirectUri;
    const scope = container.dataset.scope || 'openid email profile';
    const variant = container.dataset.variant || 'gradient'; // gradient | dark | light
    const label = container.dataset.label || 'Sign in with KP';

    if (!clientId || !redirectUri) {
      console.error('[KP Auth] data-client-id and data-redirect-uri are required.');
      return;
    }

    const btn = document.createElement('button');
    btn.className = `kp-signin-btn${variant === 'dark' ? ' kp-dark' : variant === 'light' ? ' kp-light' : ''}`;
    btn.type = 'button';
    btn.innerHTML = `
      <span class="kp-logo">KP</span>
      <span class="kp-text">${label}</span>
    `;

    btn.addEventListener('click', async () => {
      const state = generateState();
      const { verifier, challenge } = await generatePKCE();

      // Store verifier in sessionStorage for callback page to use
      sessionStorage.setItem('kp_pkce_verifier', verifier);
      sessionStorage.setItem('kp_oauth_state', state);

      const authUrl = new URL(`${KP_AUTH_BASE}/oauth/authorize`);
      authUrl.searchParams.set('client_id', clientId);
      authUrl.searchParams.set('redirect_uri', redirectUri);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('scope', scope);
      authUrl.searchParams.set('state', state);
      authUrl.searchParams.set('code_challenge', challenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      window.location.href = authUrl.toString();
    });

    container.innerHTML = '';
    container.appendChild(btn);
  }

  // ── Auto-init all [data-client-id] containers ─────────────────────────────
  function init() {
    const containers = document.querySelectorAll('[data-client-id][data-redirect-uri]');
    containers.forEach(renderButton);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Expose manual init for SPA frameworks
  window.KPAuth = { init, renderButton };
})();
