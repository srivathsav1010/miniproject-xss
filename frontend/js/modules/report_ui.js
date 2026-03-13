/**
 * report_ui.js — Report tab renderer
 */
const ReportUI = (() => {
  function render(scan) {
    const body  = document.getElementById('report-body');
    const empty = document.getElementById('empty-report');
    if (!scan || !scan.findings) { body.innerHTML = ''; body.style.display='none'; empty.style.display='flex'; return; }
    empty.style.display = 'none';
    body.style.display = 'flex';
    body.style.flexDirection = 'column';
    body.style.gap = '12px';

    const scoreColor = scan.score >= 70 ? 'var(--red)' : scan.score >= 40 ? 'var(--amber)' : 'var(--green)';
    body.innerHTML = `
<div class="report-grid">
  <div class="rcard">
    <div class="rcard-title">Threat Score</div>
    <div class="rcard-big" style="color:${scoreColor}">${scan.score}/100</div>
    <div style="font-size:.63rem;color:var(--dim);margin-top:5px">${scan.risk} RISK</div>
  </div>
  <div class="rcard">
    <div class="rcard-title">Findings</div>
    <div style="font-size:.66rem;line-height:2">
      <span style="color:var(--red)">● Critical: ${scan.critical}</span><br>
      <span style="color:var(--amber)">● High: ${scan.high}</span><br>
      <span style="color:var(--purple)">● Medium: ${scan.medium}</span><br>
      <span style="color:var(--cyan)">● Info/Low: ${scan.info}</span>
    </div>
  </div>
</div>
<div class="rcard">
  <div class="rcard-title">Scanned target</div>
  <div style="font-size:.68rem;color:var(--cyan);word-break:break-all">${esc(scan.input || '')}</div>
</div>
<table class="risk-table">
  <tr><th>Threat</th><th>Severity</th><th>Category</th></tr>
  ${scan.findings.map(f => `<tr>
    <td>${esc(f.name)}</td>
    <td style="color:${f.severity==='CRITICAL'?'var(--red)':f.severity==='HIGH'?'var(--amber)':f.severity==='MEDIUM'?'var(--purple)':'var(--cyan)'}">${f.severity}</td>
    <td style="color:var(--dim)">${esc(f.category)}</td>
  </tr>`).join('')}
</table>`;
  }

  return { render };
})();
