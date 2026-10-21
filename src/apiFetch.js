let csrfToken = '';

export function setCsrfToken(value) {
  csrfToken = value || '';
}

export function apiFetch(url, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  if (method === 'GET' || method === 'HEAD') return fetch(url, options);
  return fetch(url, {
    ...options,
    headers: { ...options.headers, 'X-CSRF-Token': csrfToken },
  });
}
