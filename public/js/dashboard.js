(async function loadProfile() {
  const { ok, data } = await api('/api/auth/me');
  if (!ok) return location.replace('/login');

  document.getElementById('email').textContent = data.email;
  document.getElementById('stored-email').textContent = JSON.stringify(data.storedEmail, null, 2);
  document.getElementById('password-storage').textContent = data.passwordStorage;
  document.getElementById('created').textContent = new Date(data.createdAt).toLocaleString();
  document.getElementById('last-login').textContent = data.lastLoginAt
    ? new Date(data.lastLoginAt).toLocaleString()
    : '—';
})();

document.getElementById('logout').addEventListener('click', async () => {
  await api('/api/auth/logout', { method: 'POST' });
  location.replace('/login');
});
