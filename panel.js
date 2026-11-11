// Injected into the page with chrome.scripting.executeScript({ func: renderPanel }).
// MUST stay self-contained (no imports or outer references): Chrome serialises the function.
// All dynamic text goes through textContent / Node.append(string), never innerHTML.
export function renderPanel(report) {
  const HOST_ID = '__image_check_panel__';
  const old = document.getElementById(HOST_ID);
  if (old) old.remove();

  const COLOR = { clear: '#1a7f37', notice: '#0969da', warning: '#bf8700', alert: '#cf222e', unknown: '#6e7781', info: '#6e7781' };
  const WORD = { clear: 'Clear', notice: 'Notice', warning: 'Warning', alert: 'Alert', unknown: 'Unknown', info: 'Info' };

  const host = document.createElement('div');
  host.id = HOST_ID;
  host.style.cssText = 'all:initial;position:fixed;top:16px;right:16px;z-index:2147483647;';
  const root = host.attachShadow({ mode: 'open' });

  const style = document.createElement('style');
  style.textContent = `
    :host { all: initial; }
    .p { box-sizing: border-box; width: 370px; max-width: calc(100vw - 32px); max-height: 82vh; overflow: auto;
         font: 13px/1.45 system-ui, -apple-system, Segoe UI, sans-serif; color: #1f2328; background: #fff;
         border: 1px solid #d0d7de; border-radius: 10px; box-shadow: 0 8px 28px rgba(0,0,0,.28); padding: 12px; }
    @media (prefers-color-scheme: dark) { .p { color: #e6edf3; background: #161b22; border-color: #30363d; } }
    .top { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
    h1 { font-size: 15px; margin: 0; }
    .x { border: 0; background: transparent; color: inherit; font-size: 20px; line-height: 1; cursor: pointer; padding: 2px 6px; border-radius: 6px; }
    .x:hover, .btn:hover { background: rgba(128,128,128,.2); }
    .meta { margin: 4px 0 10px; opacity: .75; font-size: 12px; word-break: break-all; }
    details { border-top: 1px solid rgba(128,128,128,.3); padding: 6px 0; }
    summary { cursor: pointer; display: flex; gap: 8px; align-items: baseline; list-style: none; }
    summary::-webkit-details-marker { display: none; }
    .dot { flex: none; width: 9px; height: 9px; border-radius: 50%; transform: translateY(1px); }
    .lab { font-weight: 600; flex: none; }
    .word { flex: none; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .03em; }
    .head { opacity: .9; }
    ul { margin: 6px 0 2px 17px; padding: 0; }
    li { margin: 4px 0; }
    .sev { font-size: 10px; font-weight: 700; text-transform: uppercase; margin-right: 5px; }
    .note { margin: 8px 0 0; font-style: italic; opacity: .85; }
    .foot { margin-top: 8px; font-size: 11.5px; opacity: .75; }
    .row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; align-items: center; }
    .btn, a.btn { border: 1px solid rgba(128,128,128,.5); background: transparent; color: inherit; border-radius: 6px;
                  padding: 4px 9px; font: inherit; cursor: pointer; text-decoration: none; }
  `;

  const el = (tag, attrs = {}, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') n.className = v;
      else n.setAttribute(k, v);
    }
    for (const kid of kids) n.append(kid);
    return n;
  };
  const dot = (level) => { const d = el('span', { class: 'dot' }); d.style.background = COLOR[level] || COLOR.unknown; return d; };
  const word = (level) => { const w = el('span', { class: 'word' }, WORD[level] || level); w.style.color = COLOR[level] || COLOR.unknown; return w; };

  const info = (report && report.info) || {};
  const summary = (report && report.summary) || [];
  let host_ = '';
  try { host_ = new URL(info.url).hostname; } catch (e) { host_ = info.url ? 'embedded image' : ''; }
  const dims = info.dims ? ` ${info.dims.w}x${info.dims.h}` : '';
  const size = info.size != null ? `, ${info.size.toLocaleString()} bytes` : '';
  const metaLine = [host_, info.type ? `${String(info.type).toUpperCase()}${dims}${size}` : 'not downloaded'].filter(Boolean).join(' · ');

  const panel = el('div', { class: 'p', role: 'dialog', 'aria-label': 'Image check results' });
  const close = el('button', { class: 'x', 'aria-label': 'Close' }, '×');
  const onKey = (e) => { if (e.key === 'Escape') dismiss(); };
  const dismiss = () => { host.remove(); document.removeEventListener('keydown', onKey, true); };
  close.addEventListener('click', dismiss);
  document.addEventListener('keydown', onKey, true);
  panel.append(el('div', { class: 'top' }, el('h1', {}, 'Image check'), close), el('div', { class: 'meta' }, metaLine));

  for (const s of summary) {
    const d = el('details');
    if (s.level === 'warning' || s.level === 'alert') d.setAttribute('open', '');
    d.append(el('summary', {}, dot(s.level), el('span', { class: 'lab' }, s.label), word(s.level), el('span', { class: 'head' }, s.headline)));
    if (s.findings && s.findings.length) {
      const ul = el('ul');
      for (const f of s.findings) {
        const sev = el('span', { class: 'sev' }, WORD[f.sev] || f.sev);
        sev.style.color = COLOR[f.sev] || COLOR.unknown;
        ul.append(el('li', {}, sev, f.text));
      }
      d.append(ul);
    }
    panel.append(d);
  }

  const limits = (report && report.limits) || [];
  if (limits.length) {
    const d = el('details', { class: 'limits' });
    d.append(el('summary', {}, el('span', { class: 'lab' }, "What this check can't tell you")));
    const ul = el('ul');
    for (const t of limits) ul.append(el('li', {}, t));
    d.append(ul);
    panel.append(d);
  }

  if (info.note) panel.append(el('p', { class: 'note' }, info.note));

  const row = el('div', { class: 'row' });
  const copy = el('button', { class: 'btn' }, 'Copy report');
  copy.addEventListener('click', async () => {
    const lines = ['Image check report', `URL: ${info.url || ''}`, `File: ${metaLine}`];
    for (const s of summary) {
      lines.push('', `[${s.label}] ${WORD[s.level]}: ${s.headline}`);
      for (const f of s.findings || []) lines.push(`  - ${WORD[f.sev] || f.sev}: ${f.text}`);
    }
    if (limits.length) { lines.push('', "What this check can't tell you:"); for (const t of limits) lines.push(`  - ${t}`); }
    try { await navigator.clipboard.writeText(lines.join('\n')); copy.textContent = 'Copied'; } catch (e) { copy.textContent = 'Copy failed'; }
  });
  row.append(copy);

  // Reverse image search sends the URL to a third party, so only offer it when the URL looks clean.
  const tracking = summary.find((s) => s.key === 'tracking');
  const canSearch = /^https?:/i.test(info.url || '') && tracking && (tracking.level === 'clear' || tracking.level === 'notice');
  if (canSearch) {
    const q = encodeURIComponent(info.url);
    row.append(
      el('a', { class: 'btn', href: `https://lens.google.com/uploadbyurl?url=${q}`, target: '_blank', rel: 'noopener noreferrer' }, 'Search on Google Lens'),
      el('a', { class: 'btn', href: `https://tineye.com/search?url=${q}`, target: '_blank', rel: 'noopener noreferrer' }, 'Search on TinEye'),
    );
  }
  panel.append(row);
  panel.append(el('p', { class: 'foot' },
    canSearch
      ? 'Reverse search sends this image’s address to that service. Nothing is sent unless you click.'
      : 'Reverse search is hidden because the URL may contain identifiers.',
  ), el('p', { class: 'foot' },
    'This is a set of signals, not a verdict. Metadata can be stripped or forged, so "nothing found" does not prove an image is real, safe, or untracked.'));

  root.append(style, panel);
  document.documentElement.append(host);
  close.focus();
}
