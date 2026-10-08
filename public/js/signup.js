const form = document.getElementById('signup-form');
const message = document.getElementById('message');

// Same rules the server enforces; the server check is the authoritative one.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function passwordError(pw) {
  if (pw.length < 8) return 'Password must be at least 8 characters.';
  if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw) || !/[0-9]/.test(pw) || !/[^A-Za-z0-9]/.test(pw)) {
    return 'Password needs uppercase, lowercase, a number and a symbol.';
  }
  if (new TextEncoder().encode(pw).length > 72) return 'Password is too long (max 72 bytes).';
  return null;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = form.email.value.trim();
  const password = form.password.value;
  const confirmPassword = form.confirmPassword.value;

  if (!EMAIL_RE.test(email) || !form.email.checkValidity()) {
    return showMessage(message, 'Please enter a valid email address.', 'error');
  }
  const pwErr = passwordError(password);
  if (pwErr) return showMessage(message, pwErr, 'error');
  if (password !== confirmPassword) return showMessage(message, 'Passwords do not match.', 'error');

  const button = form.querySelector('button');
  button.disabled = true;
  showMessage(message, '');
  const { ok, data } = await api('/api/auth/signup', {
    method: 'POST',
    body: { email, password, confirmPassword },
  }).catch(() => ({ ok: false, data: { error: 'Network error.' } }));
  button.disabled = false;

  if (ok) {
    form.reset();
    showMessage(message, (data.message || 'Account created.') + ' Redirecting to login…', 'ok');
    setTimeout(() => location.assign('/login'), 1500);
  } else {
    showMessage(message, data.error || 'Sign up failed.', 'error');
  }
});
