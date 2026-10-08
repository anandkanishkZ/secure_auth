const form = document.getElementById('login-form');
const message = document.getElementById('message');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = form.email.value.trim();
  const password = form.password.value;

  if (!form.email.checkValidity() || !email) {
    return showMessage(message, 'Please enter a valid email address.', 'error');
  }
  if (!password) return showMessage(message, 'Please enter your password.', 'error');

  const button = form.querySelector('button');
  button.disabled = true;
  showMessage(message, '');
  const { ok, data } = await api('/api/auth/login', {
    method: 'POST',
    body: { email, password },
  }).catch(() => ({ ok: false, data: { error: 'Network error.' } }));
  button.disabled = false;

  if (ok) {
    showMessage(message, 'Login successful. Redirecting…', 'ok');
    location.assign('/dashboard');
  } else {
    form.password.value = '';
    showMessage(message, data.error || 'Login failed.', 'error');
  }
});
