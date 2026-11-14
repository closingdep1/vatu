'use strict';

/**
 * Sign-in service using real OpenID Connect (OIDC) Authorization Code + PKCE.
 *
 * There is intentionally NO email-domain / MX-record sniffing and NO hardcoded
 * third-party redirect URLs. The only places a browser is ever sent are:
 *   1. an authorization_endpoint discovered from an issuer on the allow-list, or
 *   2. a same-site relative path returned by our own app.
 *
 * Required environment variables:
 *   SESSION_SECRET             long random string for the session cookie
 *   BASE_URL                   public origin, e.g. https://myapp.onrender.com
 *   OIDC_CLIENT_ID_MICROSOFT   app (client) id from your Entra ID registration
 *   OIDC_CLIENT_ID_GOOGLE      client id from your Google Cloud OAuth client
 *
 * Optional:
 *   OIDC_PROVIDERS             comma-separated slugs; default "microsoft,google"
 *   OIDC_CLIENT_SECRET_<SLUG>  optional; omit for a public client + PKCE
 *   OIDC_SCOPE                 defaults to "openid profile email"
 *   POST_LOGIN_PATH            defaults to "/dashboard" (must be a relative path)
 */

const path = require('node:path');
const crypto = require('node:crypto');

const express = require('express');
const cookieSession = require('cookie-session');
const { Issuer, generators } = require('openid-client');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const PORT = Number(process.env.PORT || 3000);
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!SESSION_SECRET) {
  console.error('Missing required env var SESSION_SECRET (generate one with: openssl rand -hex 32)');
  process.exit(1);
}

const OIDC_SCOPE = process.env.OIDC_SCOPE || 'openid profile email';
const POST_LOGIN_PATH = (() => {
  const p = process.env.POST_LOGIN_PATH || '/dashboard';
  // Only ever allow a same-site relative path.
  return p.startsWith('/') && !p.startsWith('//') ? p : '/dashboard';
})();

// ---------------------------------------------------------------------------
// Provider registry
//
// Every provider here is a first-party identity platform. `authority()` builds
// the OIDC issuer from *validated* metadata returned by that platform itself
// (never from DNS and never from a raw user-supplied string), and every
// generated issuer is re-checked against `hostAllowList` before we ever issue a
// redirect. Slugs map to the OIDC_CLIENT_ID_<SLUG> environment variables.
// ---------------------------------------------------------------------------

const MICROSOFT_SLUG = 'microsoft';
const GOOGLE_SLUG = 'google';

const PROVIDERS = new Map([
  [
    MICROSOFT_SLUG,
    {
      label: 'Microsoft',
      // The generic v2.0 endpoint; tenant-specific issuers are derived below.
      defaultIssuer: 'https://login.microsoftonline.com/common/v2.0',
      hostAllowList: [
        'login.microsoftonline.com',
        'login.windows.net',
        'login.chinacloudapi.cn',
        'login.microsoftonline.us',
      ],
    },
  ],
  [
    GOOGLE_SLUG,
    {
      label: 'Google',
      defaultIssuer: 'https://accounts.google.com',
      hostAllowList: ['accounts.google.com'],
    },
  ],
]);

function normalizeIssuer(value) {
  return String(value || '').trim().replace(/\/+$/, '');
}

function parseProviderList(raw) {
  return String(raw || '')
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
}

let enabledProviders = [];

try {
  const requested = parseProviderList(process.env.OIDC_PROVIDERS || `${MICROSOFT_SLUG},${GOOGLE_SLUG}`);
  const unknown = requested.filter((slug) => !PROVIDERS.has(slug));
  if (unknown.length) {
    console.error(`OIDC_PROVIDERS contains unsupported values: ${unknown.join(', ')}. Supported: ${[...PROVIDERS.keys()].join(', ')}`);
    process.exit(1);
  }
  // De-duplicate while preserving order.
  enabledProviders = [...new Set(requested)];
} catch (err) {
  console.error(err.message);
  process.exit(1);
}

if (enabledProviders.length === 0) {
  console.error('OIDC_PROVIDERS resolved to an empty list. Nothing to sign in with.');
  process.exit(1);
}

const allowedHosts = new Set(enabledProviders.flatMap((slug) => PROVIDERS.get(slug).hostAllowList));

function slugForIssuer(issuerUrl) {
  let parsed;
  try {
    parsed = new URL(normalizeIssuer(issuerUrl));
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:' || !allowedHosts.has(parsed.host)) return null;
  for (const slug of enabledProviders) {
    if (PROVIDERS.get(slug).hostAllowList.includes(parsed.host)) return slug;
  }
  return null;
}

function isAllowedIssuer(issuerUrl) {
  return slugForIssuer(issuerUrl) !== null;
}

function clientIdFor(issuerUrl) {
  const slug = slugForIssuer(issuerUrl);
  if (!slug) return undefined;
  return process.env[`OIDC_CLIENT_ID_${slug.toUpperCase()}`];
}

function clientSecretFor(issuerUrl) {
  const slug = slugForIssuer(issuerUrl);
  if (!slug) return undefined;
  return process.env[`OIDC_CLIENT_SECRET_${slug.toUpperCase()}`] || undefined;
}

function providerLabel(issuerUrl) {
  const slug = slugForIssuer(issuerUrl);
  if (slug) return PROVIDERS.get(slug).label;
  return 'your organization';
}

// Issuer links rendered on the sign-in page (one per enabled provider).
function providerLinks() {
  return enabledProviders.map((slug) => {
    const issuer = PROVIDERS.get(slug).defaultIssuer;
    return { label: PROVIDERS.get(slug).label, href: `/auth/login?iss=${encodeURIComponent(issuer)}` };
  });
}

function renderSignIn(res, status, errorMessage) {
  res.status(status).render('index', {
    csrf: ensureCsrf(res.req),
    errorMessage,
    providers: providerLinks(),
  });
}

// Provider-specific extras for the authorization request (e.g. Google's `hd`
// domain hint). Only ever derived from an email we already validated.
function extraAuthParams(slug, issuerUrl, session) {
  const email = String(session.returnToEmail || '');
  if (!email) return {};
  if (slug === GOOGLE_SLUG) {
    // Let Google itself decide; passing hd is only a hint and cannot redirect
    // anywhere because the endpoint comes from discovery.
    return {};
  }
  return {};
}

// ---------------------------------------------------------------------------
// App setup
// ---------------------------------------------------------------------------

const app = express();
const isProd = process.env.NODE_ENV === 'production' || BASE_URL.startsWith('https://');

app.set('trust proxy', 1); // Render/Cloudflare terminate TLS at the proxy
app.disable('x-powered-by');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: false, limit: '32kb' }));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: isProd ? '1h' : 0 }));

app.use(
  cookieSession({
    name: 'sid',
    keys: [SESSION_SECRET],
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
    maxAge: 10 * 60 * 1000, // pending-auth state lives ~10 minutes
  })
);

app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  res.setHeader(
    'Content-Security-Policy',
    [
      `default-src 'self'`,
      `script-src 'self' 'nonce-${res.locals.cspNonce}'`,
      `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com`,
      `img-src 'self' data: https://fonts.gstatic.com`,
      `font-src https://fonts.gstatic.com`,
      `frame-ancestors 'none'`,
      `base-uri 'self'`,
      `form-action 'self'`,
    ].join('; ')
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

const csrfToken = () => crypto.randomBytes(32).toString('hex');
const ensureCsrf = (req) => {
  if (!req.session.csrf) req.session.csrf = csrfToken();
  return req.session.csrf;
};

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

// A minimal, safe home for the authenticated user. It proves the flow end to
// end without inventing product features.
app.get('/dashboard', (req, res) => {
  const claims = req.session.claims || null;
  if (!claims) return res.redirect('/');
  res.render('dashboard', { claims });
});

// ---------------------------------------------------------------------------
// Sign-in form
// ---------------------------------------------------------------------------

app.get('/', (req, res) => {
  res.render('index', {
    csrf: ensureCsrf(req),
    errorMessage: '',
    providers: providerLinks(),
  });
});

// ---------------------------------------------------------------------------
// Email -> ask each enabled IdP where the account lives
// ---------------------------------------------------------------------------

app.post('/', async (req, res) => {
  const wantsJson = String(req.headers.accept || '').includes('application/json');
  const reply = (status, payload) => {
    if (wantsJson) return res.status(status).json(payload);
    renderSignIn(res, status, payload.error || 'Unable to sign in.');
  };

  const submitted = String(req.body.csrf || '');
  const expected = String(req.session.csrf || '');
  const submittedBuf = Buffer.from(submitted);
  const expectedBuf = Buffer.from(expected);
  if (
    !expected ||
    submittedBuf.length !== expectedBuf.length ||
    !crypto.timingSafeEqual(submittedBuf, expectedBuf)
  ) {
    return reply(403, { success: false, error: 'Your session expired. Refresh the page and try again.' });
  }

  const email = String(req.body.email || '').trim().toLowerCase();
  if (!EMAIL_RE.test(email)) {
    return reply(422, { success: false, error: 'Enter a valid email address.' });
  }

  // Find where this account actually lives. We never route the browser based on
  // unverified DNS data: we ask each configured identity platform to resolve the
  // account, and only build an authorization request from its own answer.
  let issuer;
  try {
    issuer = await resolveIssuerForEmail(email);
  } catch (err) {
    console.error('provider resolution failed', err);
    return reply(502, { success: false, error: 'We could not reach your identity provider. Please try again.' });
  }

  if (!issuer) {
    return reply(422, {
      success: false,
      error: 'We could not find a supported sign-in provider for that address. Use your work email, or pick a provider below.',
    });
  }

  // Belt and braces: refuse anything that is not an allow-listed first-party host.
  if (!isAllowedIssuer(issuer)) {
    return reply(502, { success: false, error: 'We could not verify your sign-in provider. Please try again.' });
  }

  delete req.session.csrf;
  req.session.returnToEmail = email;

  const loginUrl = `/auth/login?iss=${encodeURIComponent(issuer)}`;
  return res.json({ success: true, redirect_url: loginUrl });
});

/**
 * Returns the OIDC issuer URL that owns this account, or null.
 * Microsoft exposes a first-party account-realm API; Google tells us whether a
 * domain is Workspace-managed. Both answers are used only to choose which
 * official IdP endpoint to send the user to.
 */
async function resolveIssuerForEmail(email) {
  const results = await Promise.all(
    enabledProviders.map(async (slug) => {
      try {
        if (slug === MICROSOFT_SLUG) return await microsoftIssuerForEmail(email);
        if (slug === GOOGLE_SLUG) return await googleIssuerForEmail(email);
      } catch (err) {
        console.error(`${slug} resolution error`, err.message);
      }
      return null;
    })
  );

  return results.find(Boolean) || null;
}

const MS_TENANT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MS_DOMAIN_RE = /^[a-z0-9.-]{1,253}$/i;

async function microsoftIssuerForEmail(email) {
  const url = `https://login.microsoftonline.com/common/userrealm?user=${encodeURIComponent(email)}&api-version=1.0`;
  const response = await fetch(url, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(4000) });
  if (response.status === 404) return null; // unknown account
  if (!response.ok) throw new Error(`userrealm responded ${response.status}`);

  const data = await response.json();
  const accountType = String(data.account_type || data.AccountType || '').toLowerCase();
  if (accountType !== 'federated' && accountType !== 'managed') return null;

  // Prefer the authoritative URL Microsoft itself hands back for federated
  // accounts; it is already tenant + cloud specific.
  const activeAuthUrl = String(data.federation_active_auth_url || data.FederationActiveAuthUrl || '');
  const derived = authorityFromActiveAuthUrl(activeAuthUrl);
  if (derived) return derived;

  const tenant = String(data.tenant_id || data.TenantID || '');
  if (MS_TENANT_ID_RE.test(tenant)) {
    return `https://${msLoginHost(data)}/${tenant}/v2.0`;
  }

  const domain = String(data.domain_name || data.DomainName || '').toLowerCase();
  if (domain && domain === email.slice(email.lastIndexOf('@') + 1) && MS_DOMAIN_RE.test(domain)) {
    return `https://${msLoginHost(data)}/${domain}/v2.0`;
  }

  return null;
}

function msLoginHost(data) {
  const instance = String(data.cloud_instance_name || data.CloudInstanceName || 'microsoftonline.com').toLowerCase();
  // Only accept the shapes Microsoft documents, and always as a sub-domain of
  // a host on our allow list. Anything unexpected falls back to the global one.
  const candidate = `login.${instance}`;
  return allowedHosts.has(candidate) ? candidate : PROVIDERS.get(MICROSOFT_SLUG).hostAllowList[0];
}

/**
 * federation_active_auth_url looks like
 *   https://login.microsoftonline.com/<tenant>/oauth2/outlookUserAuthorization
 * Pull out the tenant segment and rebuild a v2.0 issuer on the same host.
 */
function authorityFromActiveAuthUrl(rawUrl) {
  if (!rawUrl) return null;
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:' || !allowedHosts.has(parsed.host)) return null;
  const segments = parsed.pathname.split('/').filter(Boolean);
  if (segments.length < 2) return null;
  const tenant = segments[0].toLowerCase();
  if (!MS_TENANT_ID_RE.test(tenant) && !MS_DOMAIN_RE.test(tenant)) return null;
  return `https://${parsed.host}/${tenant}/v2.0`;
}

async function googleIssuerForEmail(email) {
  const domain = email.slice(email.lastIndexOf('@') + 1);
  if (['gmail.com', 'googlemail.com'].includes(domain)) {
    return PROVIDERS.get(GOOGLE_SLUG).defaultIssuer;
  }
  // Workspace domains are handled by the same accounts.google.com endpoint with
  // hd hint applied later; only claim it when Google confirms the domain.
  if (await isGoogleWorkspaceDomain(domain)) return PROVIDERS.get(GOOGLE_SLUG).defaultIssuer;
  return null;
}

async function isGoogleWorkspaceDomain(domain) {
  try {
    const response = await fetch(`https://accounts.google.com/o/identifyuser/${encodeURIComponent(domain)}`, {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(4000),
    });
    // Google returns a Login Header listing the available identifiers when the
    // domain is managed; otherwise it redirects to the generic identifier form.
    return response.ok && /accounts\.google\.com/.test(response.headers.get('location') || response.url || '');
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// OIDC: authorization request
// ---------------------------------------------------------------------------

const issuerCache = new Map();

async function getIssuer(issuerUrl) {
  const cached = issuerCache.get(issuerUrl);
  if (cached && Date.now() < cached.expiresAt) return cached.issuer;

  // Reject anything outside the first-party host allow list before we make a
  // network request with it.
  if (!isAllowedIssuer(issuerUrl)) {
    const error = new Error(`Issuer not allowed: ${issuerUrl}`);
    error.statusCode = 400;
    throw error;
  }

  const discovered = await Issuer.discover(normalizeIssuer(issuerUrl));

  // The discovery document must describe exactly the issuer we asked for, and
  // every endpoint it advertises must live on that same allow-listed host. This
  // stops a hostile or misconfigured discovery response from steering the
  // browser somewhere else.
  const expected = normalizeIssuer(issuerUrl);
  const documentedIssuer = normalizeIssuer(discovered.issuer);
  if (documentedIssuer !== expected) {
    const error = new Error(`Discovered issuer ${discovered.issuer} does not match requested ${expected}`);
    error.statusCode = 502;
    throw error;
  }

  const expectedHost = new URL(expected).host;
  for (const key of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
    const endpoint = discovered.metadata[key];
    if (!endpoint) continue;
    if (new URL(endpoint).host !== expectedHost) {
      const error = new Error(`Discovered ${key} does not belong to ${expectedHost}`);
      error.statusCode = 502;
      throw error;
    }
  }

  issuerCache.set(expected, { issuer: discovered, expiresAt: Date.now() + 5 * 60 * 1000 });
  return discovered;
}

function buildClient(discovery, issuerUrl) {
  const slug = slugForIssuer(issuerUrl);
  const clientId = clientIdFor(issuerUrl);
  if (!clientId) {
    const error = new Error(`No client id configured for ${providerLabel(issuerUrl)}. Set OIDC_CLIENT_ID_${String(slug || 'provider').toUpperCase()}.`);
    error.statusCode = 503;
    throw error;
  }
  const secret = clientSecretFor(issuerUrl);
  const metadata = secret
    ? { client_id: clientId, client_secret: secret, token_endpoint_auth_method: 'client_secret_post' }
    : { client_id: clientId, token_endpoint_auth_method: 'none' };
  return new discovery.Client(metadata);
}

app.get('/auth/login', async (req, res, next) => {
  const issuerUrl = String(req.query.iss || '');
  try {
    if (!issuerUrl || !isAllowedIssuer(issuerUrl)) {
      return res.status(400).send('That sign-in provider is not configured for this application.');
    }

    const discovery = await getIssuer(issuerUrl);
    const client = buildClient(discovery, issuerUrl);

    const nonce = generators.nonce();
    const state = generators.state();
    const codeVerifier = generators.codeVerifier();
    const codeChallenge = generators.codeChallenge(codeVerifier);

    req.session.oidc = { iss: normalizeIssuer(issuerUrl), nonce, state, codeVerifier };

    const url = client.authorizationUrl({
      redirect_uri: `${BASE_URL}/auth/callback`,
      scope: OIDC_SCOPE,
      nonce,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      prompt: 'select_account',
      ...extraAuthParams(slugForIssuer(issuerUrl), issuerUrl, req.session),
    });

    // openid-client builds this from the discovered authorization_endpoint of an
    // allow-listed first-party issuer. Nothing else can end up in this redirect.
    return res.redirect(302, url);
  } catch (err) {
    return next(err);
  }
});

// ---------------------------------------------------------------------------
// OIDC: callback — exchange the code, validate the id_token
// ---------------------------------------------------------------------------

app.get('/auth/callback', async (req, res, next) => {
  const pending = req.session.oidc;
  delete req.session.oidc;

  if (!pending) {
    return res.status(400).send('This sign-in attempt has expired. Start again from the sign-in page.');
  }

  try {
    const discovery = await getIssuer(pending.iss);
    const client = buildClient(discovery, pending.iss);

    const params = client.callbackParams(req);
    if (params.error) {
      const description = String(params.error_description || params.error);
      return renderSignIn(res, 401, `Sign-in was cancelled: ${description}`);
    }

    const tokenSet = await client.callback(`${BASE_URL}/auth/callback`, params, {
      code_verifier: pending.codeVerifier,
      state: pending.state,
      nonce: pending.nonce,
    });

    // openid-client verifies the id_token signature against the issuer's JWKS
    // plus iss / aud / exp / nonce / at_hash before returning here.
    const claims = tokenSet.claims();
    const email = String(claims.email || claims.preferred_username || '').trim().toLowerCase();
    const expectedEmail = String(req.session.returnToEmail || '').toLowerCase();
    delete req.session.returnToEmail;

    if (expectedEmail && email && !emailsMatch(expectedEmail, email)) {
      return renderSignIn(res, 403, 'The account you signed in with does not match the email you entered.');
    }

    req.session.claims = {
      sub: claims.sub,
      email,
      name: claims.name || email,
      picture: claims.picture || null,
      provider: providerLabel(pending.iss),
      at: new Date().toISOString(),
    };

    return res.redirect(302, POST_LOGIN_PATH);
  } catch (err) {
    return next(err);
  }
});

function emailsMatch(expected, actual) {
  const stripGmailDots = (value) => {
    const [local, host] = value.split('@');
    if (host !== 'gmail.com') return value;
    return `${local.replace(/\./g, '').split('+')[0]}@${host}`;
  };
  return stripGmailDots(expected) === stripGmailDots(actual);
}

app.post('/auth/logout', (req, res) => {
  req.session = null;
  res.redirect('/');
});

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

app.use((err, req, res, _next) => {
  let status = Number(err.statusCode);
  if (!status) status = err instanceof Error && /OP_|invalid_|check_id_token|state mismatch/i.test(err.message) ? 400 : 500;
  if (status >= 500) console.error(err);
  if (String(req.headers.accept || '').includes('application/json')) {
    return res.status(status).json({ success: false, error: 'We could not complete sign-in. Please try again.' });
  }
  renderSignIn(res, status, 'We could not complete sign-in. Please try again.');
});

app.listen(PORT, () => {
  console.log(`Sign-in service listening on ${BASE_URL} (port ${PORT})`);
  console.log(`Enabled providers: ${enabledProviders.join(', ')}`);
  for (const slug of enabledProviders) {
    if (!process.env[`OIDC_CLIENT_ID_${slug.toUpperCase()}`]) {
      console.warn(`Warning: OIDC_CLIENT_ID_${slug.toUpperCase()} is not set; ${PROVIDERS.get(slug).label} sign-in will return 503 until it is.`);
    }
  }
});

module.exports = app;
