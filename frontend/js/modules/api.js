/**
 * api.js — All communication with the Flask backend
 * Every fetch call lives here — no raw fetch() anywhere else
 */
const API = (() => {
  const BASE = '';   // Same origin — Flask serves both frontend and API

  async function post(endpoint, body) {
    const res = await fetch(BASE + endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`API error ${res.status}`);
    return res.json();
  }

  return {
    scan:     (input)   => post('/api/scan',     { input }),
    sanitize: (input)   => post('/api/sanitize', { input }),
    buildCSP: (options) => post('/api/csp',      { options }),
    report:   (results) => post('/api/report',   { scan_results: results }),
    health:   ()        => fetch('/api/health').then(r => r.json()),
  };
})();
