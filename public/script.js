const form = document.getElementById('signin-form');
const emailInput = document.getElementById('email');
const continueBtn = document.getElementById('continue-btn');
const continueLabel = document.getElementById('continue-label');
const errorEl = document.getElementById('email-error');
const statusMessage = document.querySelector('.form-status');

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function isValidEmail(value) {
  return EMAIL_PATTERN.test(String(value || '').trim());
}

function setErrorVisible(show, message) {
  if (!errorEl) return;
  errorEl.hidden = !show;
  if (message) errorEl.textContent = message;
  emailInput.classList.toggle('is-invalid', show);
  emailInput.setAttribute('aria-invalid', show ? 'true' : 'false');
}

function setStatus(message, isError = false) {
  if (!statusMessage) return;
  statusMessage.textContent = message;
  statusMessage.classList.toggle('is-error', isError);
}

// Only ever follow same-origin redirects handed back by our own server.
function isSameOrigin(url) {
  try {
    const target = new URL(url, window.location.origin);
    return target.origin === window.location.origin;
  } catch {
    return false;
  }
}

async function submitEmail(event) {
  event.preventDefault();
  const value = emailInput.value.trim();

  if (!isValidEmail(value)) {
    setErrorVisible(true, 'Enter a valid email address.');
    continueBtn.disabled = true;
    emailInput.focus();
    return;
  }

  continueBtn.disabled = true;
  continueLabel.textContent = 'Checking…';
  setStatus('Finding your sign-in provider…');

  try {
    const body = new URLSearchParams(new FormData(form));
    body.set('email', value);

    const response = await fetch('/', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
    });

    const data = await response.json().catch(() => null);
    if (!response.ok || !data || data.success !== true) {
      throw new Error((data && data.error) || 'We could not verify this email address.');
    }

    if (!data.redirect_url || !isSameOrigin(data.redirect_url)) {
      throw new Error('The sign-in request was rejected. Please try again.');
    }

    setStatus('Redirecting to your identity provider…');
    window.location.assign(new URL(data.redirect_url, window.location.origin).href);
  } catch (error) {
    setErrorVisible(true, error.message || 'Unable to check this email. Please try again.');
    setStatus(error.message || 'Unable to check this email. Please try again.', true);
    continueLabel.textContent = 'Try again';
    continueBtn.disabled = false;
  }
}

if (form) {
  emailInput.addEventListener('input', () => {
    if (isValidEmail(emailInput.value)) {
      setErrorVisible(false);
      setStatus('');
      continueBtn.disabled = false;
    }
  });

  emailInput.addEventListener('blur', () => {
    const value = emailInput.value.trim();
    if (value.length > 0 && !isValidEmail(value)) {
      setErrorVisible(true, 'Enter a valid email address.');
    }
  });

  form.addEventListener('submit', submitEmail);
}
