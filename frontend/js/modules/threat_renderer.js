/**
 * threat_renderer.js — Renders threat cards in the Threats tab
 */
const ThreatRenderer = (() => {
  const SEV_ICON  = { CRITICAL:'🔴', HIGH:'🟠', MEDIUM:'🟡', LOW:'🔵', INFO:'ℹ️' };
  const SEV_CLASS = { CRITICAL:'crit', HIGH:'high', MEDIUM:'med', LOW:'low', INFO:'low' };
  const SEV_BADGE = { CRITICAL:'sev-crit', HIGH:'sev-high', MEDIUM:'sev-med', LOW:'sev-low', INFO:'sev-low' };

  function render(findings) {
    const list  = document.getElementById('threats-list');
    const empty = document.getElementById('empty-threats');
    const count = document.getElementById('tab-count');

    if (!findings || !findings.length) {
      list.innerHTML = '';
      empty.style.display = 'flex';
      empty.innerHTML = `<div class="empty-icon">✅</div>
        <div class="empty-title">No threats detected</div>
        <div class="empty-sub">Input passed all detection rules. Still apply output encoding as a baseline.</div>`;
      count.textContent = '';
      return;
    }

    empty.style.display = 'none';
    count.textContent = ` (${findings.length})`;
    list.innerHTML = findings.map(f => `
<div class="threat-card">
  <div class="tc-head">
    <div class="tc-icon ${SEV_CLASS[f.severity] || 'low'}">${SEV_ICON[f.severity] || '•'}</div>
    <div class="tc-title">${esc(f.name)}</div>
    <span class="sev ${SEV_BADGE[f.severity] || 'sev-low'}">${f.severity}</span>
    <span class="tc-cat">${esc(f.category)}</span>
  </div>
  <div class="tc-body">
    <div class="tc-desc">${esc(f.description)}</div>
    <div class="tc-ev-label">Evidence / detected payload</div>
    <div class="tc-evidence">${esc(f.evidence)}</div>
    <div class="tc-fix">
      <div class="tc-fix-label">✓ Prevention fix</div>
      <pre class="tc-fix-code">${esc(f.fix)}</pre>
    </div>
  </div>
</div>`).join('');
  }

  return { render };
})();
