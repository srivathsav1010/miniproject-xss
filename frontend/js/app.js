/**
 * app.js — Main orchestrator
 * Wires all modules together.
 */

function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function initTabs() {
  const TABS = ['threats','prevention','sanitizer','csp','report','log'];
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      const name = btn.dataset.tab;
      document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
      TABS.forEach(n => {
        const el = document.getElementById('tc-' + n);
        if (el) el.classList.toggle('active', n === name);
      });
    });
  });
}

async function runScan() {
  const input = ScannerUI.getInput();
  if (!input) { Logger.warn('No input provided'); return; }

  const STEP_NAMES = ['URL parse','Decode layers','Pattern scan (38 rules)','Parameter analysis','Sensitive data','Context analysis'];

  ScannerUI.setScanning(true);
  ScannerUI.buildStepEls(STEP_NAMES);
  Logger.info('Scanning: ' + input.substring(0, 80));

  let stepIdx = 0;
  const stepTimer = setInterval(() => {
    if (stepIdx < STEP_NAMES.length) {
      ScannerUI.setProgress(STEP_NAMES, stepIdx, ((stepIdx + 1) / STEP_NAMES.length) * 85);
      stepIdx++;
    }
  }, 320);

  try {
    const scan = await API.scan(input);
    clearInterval(stepTimer);
    ScannerUI.setProgress(STEP_NAMES, STEP_NAMES.length, 100);

    ThreatRenderer.render(scan.findings);
    PreventionRenderer.render(scan.findings);
    ReportUI.render(scan);
    Sidebar.update(scan);

    (scan.log || []).forEach(line => {
      if (line.startsWith('[OK]')) Logger.ok(line);
      else if (line.startsWith('[ERR]')) Logger.err(line);
      else Logger.warn(line);
    });

    Logger.ok('Scan complete — ' + scan.total + ' threat(s), score ' + scan.score + '/100');
    document.querySelector('[data-tab="threats"]').click();

  } catch (err) {
    clearInterval(stepTimer);
    Logger.err('Scan failed: ' + err.message);
    Logger.warn('Is Flask running? → python backend/app.py');
  } finally {
    ScannerUI.setScanning(false);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  ScannerUI.initQuickButtons();
  SanitizerUI.init();
  CSPUI.init();

  document.getElementById('scan-btn').addEventListener('click', runScan);
  document.getElementById('url-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') runScan();
  });

  const clockEl = document.getElementById('hdr-clock');
  const tick = () => { clockEl.textContent = new Date().toLocaleTimeString('en-GB'); };
  tick(); setInterval(tick, 1000);

  API.health()
    .then(h => {
      Logger.ok('Backend connected — ' + h.rules + ' rules active');
      document.getElementById('hdr-rules').textContent = h.rules + ' RULES';
    })
    .catch(() => Logger.err('Backend offline → run: python backend/app.py'));

  Logger.info('XSS Shield Pro initialised');
  Logger.dim('Enter a URL or payload and press SCAN NOW');
});
