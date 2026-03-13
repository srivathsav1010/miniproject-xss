/**
 * scanner_ui.js — Scanner input box, progress bar, quick-load buttons
 */
const ScannerUI = (() => {

  function setScanning(on) {
    const btn = document.getElementById('scan-btn');
    btn.disabled = on;
    btn.textContent = on ? '◉ SCANNING...' : '⬡ SCAN NOW';
    btn.classList.toggle('scanning', on);
    document.getElementById('hdr-engine').textContent = on ? 'SCANNING' : 'ENGINE READY';
    document.getElementById('hdr-engine').className   = on ? 'pill pill-red' : 'pill pill-green';
    document.getElementById('progress-zone').style.display = on ? 'block' : 'none';
  }

  function setProgress(steps, currentIdx, pct) {
    document.getElementById('prog-fill').style.width = pct + '%';
    document.querySelectorAll('.prog-step').forEach((el, i) => {
      el.classList.remove('active', 'done', 'fail');
      if (i < currentIdx) el.classList.add('done');
      else if (i === currentIdx) el.classList.add('active');
    });
    if (steps[currentIdx]) {
      document.getElementById('prog-label').textContent =
        `Step ${currentIdx + 1}/${steps.length}: ${steps[currentIdx]}...`;
    }
  }

  function buildStepEls(stepNames) {
    document.getElementById('prog-steps').innerHTML =
      stepNames.map(n => `<div class="prog-step">${n}</div>`).join('');
  }

  function getInput() {
    return document.getElementById('url-input').value.trim();
  }

  function initQuickButtons() {
    document.querySelectorAll('.qbtn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.getElementById('url-input').value = btn.dataset.q;
      });
    });
  }

  return { setScanning, setProgress, buildStepEls, getInput, initQuickButtons };
})();
