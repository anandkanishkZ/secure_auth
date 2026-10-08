// Shared helpers for all pages.

// Refuse to talk to the API over anything other than HTTPS
if (location.protocol !== 'https:') {
  location.replace('https://' + location.host + location.pathname);
}

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch { /* empty body */ }
  return { ok: res.ok, status: res.status, data };
}

function showMessage(el, text, type) {
  el.textContent = text;
  el.className = 'message ' + (type || '');
}

// Show which TLS version and cipher this page's connection actually negotiated
(async function showTlsInfo() {
  const el = document.getElementById('tls-info');
  if (!el) return;
  try {
    const { data } = await api('/api/tls-info');
    if (data.encrypted) {
      el.textContent = `\u{1F512} ${location.protocol}//${location.host} · ${data.protocol} · ${data.cipher.standardName || data.cipher.name}`;
      el.className = 'tls-info secure';
    } else {
      el.textContent = 'Connection is NOT encrypted';
      el.className = 'tls-info insecure';
    }
  } catch {
    el.textContent = '';
  }
})();
