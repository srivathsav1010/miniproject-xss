/**
 * prevention_renderer.js — Prevention tab content
 */
const PreventionRenderer = (() => {
  const GENERAL = [
    { q: 'What is the #1 rule?',
      a: 'Context-aware output encoding. HTML context → html.escape(). JS context → JSON.stringify(). URL context → encodeURIComponent(). CSS context → reject or strict allowlist.' },
    { q: 'Blocklist vs allowlist?',
      a: 'Always allowlist. Blocklists are bypassed constantly. An allowlist of known-safe tags/attributes is orders of magnitude more robust.' },
    { q: 'Is CSP enough on its own?',
      a: 'No. CSP is a second layer. You still need input validation and output encoding. But a strict CSP (no unsafe-inline, no unsafe-eval) catches what escapes other defenses.' },
    { q: 'Stored XSS — sanitize on input or output?',
      a: 'BOTH. Sanitize on write (reduces blast radius) AND encode on read (ensures old data is still safe). Never rely on only one.' },
  ];

  function render(findings) {
    const el    = document.getElementById('prev-list');
    const empty = document.getElementById('empty-prev');

    if (!findings || !findings.length) {
      el.innerHTML = '';
      el.style.display = 'none';
      empty.style.display = 'flex';
      return;
    }
    empty.style.display = 'none';
    el.style.display = 'flex';
    el.style.flexDirection = 'column';
    el.style.gap = '12px';

    // General principles
    let html = `<div class="rem-box"><div class="rem-head">🛡 General XSS Prevention Principles</div><div class="rem-body">`;
    GENERAL.forEach(g => {
      html += `<div class="rem-item"><div class="rem-q">${g.q}</div><div class="rem-a">${g.a}</div></div>`;
    });
    html += `</div></div>`;

    // Group by category
    const cats = {};
    findings.forEach(f => { (cats[f.category] = cats[f.category] || []).push(f); });

    Object.entries(cats).forEach(([cat, items]) => {
      html += `<div class="rem-box"><div class="rem-head">⬡ ${esc(cat)} — ${items.length} finding(s)</div><div class="rem-body">`;
      items.forEach(f => {
        html += `<div class="rem-item">
          <div class="rem-q">[${f.severity}] ${esc(f.name)}</div>
          <div class="rem-a">${esc(f.description)}</div>
          <div class="code-label" style="margin-top:8px">Fix</div>
          <pre class="code-block green">${esc(f.fix)}</pre>
        </div>`;
      });
      html += `</div></div>`;
    });

    el.innerHTML = html;
  }

  return { render };
})();
