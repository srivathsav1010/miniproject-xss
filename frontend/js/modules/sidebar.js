/**
 * sidebar.js — Updates sidebar score, stats, category list, history
 */
const Sidebar = (() => {
  const history = [];

  function update(scan) {
    if (!scan) return;
    const score = scan.score || 0;
    const scoreEl = document.getElementById('score-num');
    scoreEl.textContent = score;
    scoreEl.className   = 'score-num ' + (score >= 70 ? 'high' : score >= 40 ? 'med' : 'low');
    document.getElementById('score-label').textContent = (score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW') + ' RISK';
    const fill = document.getElementById('score-fill');
    fill.style.width      = score + '%';
    fill.style.background = score >= 70 ? 'var(--red)' : score >= 40 ? 'var(--amber)' : 'var(--green)';

    document.getElementById('s-crit').textContent = scan.critical || 0;
    document.getElementById('s-high').textContent = scan.high     || 0;
    document.getElementById('s-med').textContent  = scan.medium   || 0;
    document.getElementById('s-info').textContent = scan.info     || 0;

    _renderCategories(scan.findings || []);

    history.unshift({ url: (scan.input || '').substring(0, 42), threats: scan.total, score });
    _renderHistory();
  }

  function _renderCategories(findings) {
    const cats = {};
    findings.forEach(f => { (cats[f.category] = cats[f.category] || []).push(f); });
    const el = document.getElementById('cat-list');
    if (!Object.keys(cats).length) {
      el.innerHTML = `<div class="cat-item clean"><div class="cat-dot" style="background:var(--green)"></div><span class="cat-name">No threats found</span></div>`;
      return;
    }
    el.innerHTML = Object.entries(cats).map(([cat, items]) => {
      const hasCrit = items.some(i => i.severity === 'CRITICAL');
      const hasHigh = items.some(i => i.severity === 'HIGH');
      const cls = hasCrit ? 'threat' : hasHigh ? 'warn' : 'clean';
      const col = hasCrit ? 'var(--red)' : hasHigh ? 'var(--amber)' : 'var(--green)';
      return `<div class="cat-item ${cls}">
        <div class="cat-dot" style="background:${col}"></div>
        <span class="cat-name">${esc(cat)}</span>
        <span class="cat-count">${items.length}</span>
      </div>`;
    }).join('');
  }

  function _renderHistory() {
    document.getElementById('scan-history').innerHTML = history.slice(0, 5).map(h => `
<div style="padding:5px 8px;background:var(--s2);border:1px solid var(--border);border-radius:3px;font-size:.6rem;margin-bottom:5px">
  <div style="color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(h.url)}…</div>
  <div style="color:var(--dim);margin-top:1px">${h.threats} threat(s) · score ${h.score}/100</div>
</div>`).join('');
  }

  return { update };
})();
