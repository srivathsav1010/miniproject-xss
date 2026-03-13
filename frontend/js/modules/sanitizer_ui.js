/**
 * sanitizer_ui.js — Live sanitizer tab (calls backend API)
 */
const SanitizerUI = (() => {
  let debounceTimer;

  function init() {
    const ta = document.getElementById('san-input');
    if (!ta) return;
    ta.addEventListener('input', () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => run(ta.value), 250);
    });
  }

  async function run(raw) {
    if (!raw.trim()) {
      ['san-encoded', 'san-stripped', 'san-allowlist'].forEach(id => {
        document.getElementById(id).textContent = '—';
      });
      return;
    }
    try {
      const res = await API.sanitize(raw);
      document.getElementById('san-encoded').textContent   = res.encoded   || '(empty)';
      document.getElementById('san-stripped').textContent  = res.stripped  || '(empty)';
      document.getElementById('san-allowlist').textContent = res.allowlist || '(empty)';
    } catch {
      // Fallback: client-side sanitization if API unavailable
      document.getElementById('san-encoded').textContent   = clientEncode(raw);
      document.getElementById('san-stripped').textContent  = clientStrip(raw);
      document.getElementById('san-allowlist').textContent = '(API unavailable)';
    }
  }

  function clientEncode(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
            .replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
  }
  function clientStrip(s) {
    return s.replace(/<[^>]+>/g,'').replace(/javascript:/gi,'').replace(/on\w+=/gi,'');
  }

  return { init };
})();
