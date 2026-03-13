/**
 * logger.js — Writes timestamped messages to the log tab
 */
const Logger = (() => {
  function write(type, msg) {
    const box = document.getElementById('main-log');
    if (!box) return;
    const t = new Date().toLocaleTimeString('en-GB');
    const div = document.createElement('div');
    div.className = 'll';
    div.innerHTML = `<span class="lt">[${t}]</span><span class="lm ${type}">${esc(msg)}</span>`;
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
  }

  return {
    ok:   msg => write('ok',   msg),
    err:  msg => write('err',  msg),
    warn: msg => write('warn', msg),
    info: msg => write('info', msg),
    dim:  msg => write('dim',  msg),
  };
})();
