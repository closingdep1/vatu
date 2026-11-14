const form = document.getElementById("signin-form");
const emailInput = document.getElementById("email");
const continueBtn = document.getElementById("continue-btn");
const continueLabel = document.getElementById("continue-label");
const errorEl = document.getElementById("email-error");
const statusMessage = document.querySelector(".form-status");

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function isValidEmail(value) {
  return EMAIL_PATTERN.test(value.trim());
}

function setErrorVisible(show, message) {
  errorEl.hidden = !show;
  if (message) {
    errorEl.textContent = message;
  }
  emailInput.classList.toggle("is-invalid", show);
  emailInput.setAttribute("aria-invalid", show ? "true" : "false");
}

function setStatus(message, isError = false) {
  statusMessage.textContent = message;
  statusMessage.classList.toggle("is-error", isError);
}

function syncButtonState() {
  const valid = isValidEmail(emailInput.value);
  continueBtn.disabled = !valid;

  if (valid) {
    setErrorVisible(false);
    setStatus("");
  }
}

emailInput.addEventListener("input", syncButtonState);

emailInput.addEventListener("blur", () => {
  const value = emailInput.value.trim();
  if (value.length > 0 && !isValidEmail(value)) {
    setErrorVisible(true, "Enter a valid email address.");
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const value = emailInput.value.trim();

  if (!isValidEmail(value)) {
    setErrorVisible(true, "Enter a valid email address.");
    continueBtn.disabled = true;
    emailInput.focus();
    return;
  }

  emailInput.value = value;
  continueBtn.disabled = true;
  continueLabel.textContent = "Checking…";
  setStatus("Checking your organization…");

  try {
    const body = new URLSearchParams(new FormData(form));
    body.set("email", value);
    const response = await fetch(window.location.href, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    });
    const responseText = await response.text();
    if (!responseText.trim()) {
      throw new Error("The server returned an empty response. Make sure the page is running through PHP.");
    }

    let data;
    try {
      data = JSON.parse(responseText);
    } catch {
      throw new Error("The server returned an invalid response. Make sure index.php is being served by PHP.");
    }

    if (!response.ok || !data.success) {
      throw new Error(data.error || "We could not verify this email address.");
    }

    const provider = data.provider === "your organization" ? data.domain : data.provider;
    setStatus(`Organization verified via ${provider}.`);

    if (data.redirect_url) {
      continueLabel.textContent = `Continue to ${data.provider}`;
      window.location.assign(data.redirect_url);
      return;
    }

    setStatus("This organization does not have a redirect configured yet.");
    continueLabel.textContent = "Continue";
  } catch (error) {
    setErrorVisible(true, error.message || "Unable to check this email. Please try again.");
    setStatus(error.message || "Unable to check this email. Please try again.", true);
    continueLabel.textContent = "Try again";
  } finally {
    continueBtn.disabled = !isValidEmail(emailInput.value);
  }
});

syncButtonState();
