/**
 * csp_ui.js — CSP Builder tab
 */
const CSPUI = (() => {
  const OPTIONS = [
    { key:'inline',  label:"Block inline scripts (script-src 'self')",    desc:'Prevents inline <script> execution' },
    { key:'eval',    label:"Block eval() (no unsafe-eval)",                desc:'Prevents dynamic code execution' },
    { key:'object',  label:"Block plugins (object-src 'none')",            desc:'Blocks Flash, Java, ActiveX' },
    { key:'form',    label:"Restrict forms (form-action 'self')",          desc:'Prevents form hijacking' },
    { key:'base',    label:"Restrict base URI (base-uri 'self')",          desc:'Prevents base tag hijacking' },
    { key:'connect', label:"Restrict fetch/XHR (connect-src 'self')",      desc:'Blocks data exfiltration' },
    { key:'img',     label:"Restrict images (img-src 'self' https:)",      desc:'Blocks image beacon exfil' },
    { key:'frame',   label:"Block framing (frame-ancestors 'self')",       desc:'Prevents clickjacking' },
    { key:'upgrade', label:'Upgrade insecure requests',                    desc:'Forces HTTPS for all loads' },
    { key:'report',  label:'Enable violation reporting (/csp-report)',     desc:'Logs CSP violations server-side' },
  ];

  const state = { inline:true, eval:true, object:true, form:true, base:true, connect:true, img:true, frame:true, upgrade:false, report:true };

  function init() {
    const el = document.getElementById('csp-toggles');
    if (!el) return;
    el.innerHTML = OPTIONS.map(o => `
<div class="csp-row">
  <label for="csp-${o.key}">${o.label}<br><small>${o.desc}</small></label>
  <button class="toggle ${state[o.key] ? 'on' : ''}" id="csp-${o.key}" data-key="${o.key}"></button>
</div>`).join('');

    el.querySelectorAll('.toggle').forEach(btn => {
      btn.addEventListener('click', () => {
        const k = btn.dataset.key;
        state[k] = !state[k];
        btn.classList.toggle('on', state[k]);
        update();
      });
    });
    update();
  }

  async function update() {
    try {
      const res = await API.buildCSP(state);
      document.getElementById('csp-header').textContent = res.header || '';
      document.getElementById('csp-meta').textContent   = res.meta   || '';
    } catch {
      // Client-side fallback
      const parts = ["script-src 'self'", "default-src 'self'"];
      if (state.object)  parts.push("object-src 'none'");
      if (state.form)    parts.push("form-action 'self'");
      if (state.base)    parts.push("base-uri 'self'");
      if (state.connect) parts.push("connect-src 'self'");
      if (state.img)     parts.push("img-src 'self' https:");
      if (state.frame)   parts.push("frame-ancestors 'self'");
      const val = parts.join('; ') + ';';
      document.getElementById('csp-header').textContent = `Content-Security-Policy: ${val}`;
      document.getElementById('csp-meta').textContent   = `<meta http-equiv="Content-Security-Policy" content="${val}">`;
    }
  }

  return { init };
})();
