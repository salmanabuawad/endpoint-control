/* KEM Endpoint Manager - admin dashboard (vanilla JS, no build step) */
'use strict';

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const view = $('#view');

const state = { me: null, timer: null, devices: [], selected: new Set(), filter: { q: '', status: 'all', group: '' } };

const CMD = {
  block_internet: 'Block internet', unblock_internet: 'Restore internet', install_software: 'Install software',
  uninstall_software: 'Uninstall software', run_script: 'Run script', reboot: 'Reboot', defender_scan: 'Defender scan',
  refresh_inventory: 'Refresh inventory', create_baseline: 'Create baseline', reset_device: 'Reset device',
  uninstall_agent: 'Remove agent', scan_updates: 'Scan for updates', install_updates: 'Install Windows updates',
  set_web_filter: 'Web filter', usb_storage: 'USB storage', list_processes: 'List processes', kill_process: 'End process',
  list_services: 'List services', service_action: 'Service control', send_message: 'Message user', lock_session: 'Lock / sign out',
  update_agent: 'Update agent',
};
const USB_LABEL = { allow: 'Allowed', read_only: 'Read-only', block: 'Blocked' };
const WEB_PRESETS = [
  ['Social media', ['facebook.com', 'fb.com', 'messenger.com', 'instagram.com', 'tiktok.com', 'tiktokv.com', 'twitter.com', 'x.com', 'snapchat.com', 'pinterest.com', 'reddit.com', 'threads.net']],
  ['Video & music', ['youtube.com', 'youtu.be', 'googlevideo.com', 'netflix.com', 'twitch.tv', 'disneyplus.com', 'primevideo.com', 'vimeo.com', 'dailymotion.com', 'spotify.com', 'soundcloud.com']],
  ['Games', ['roblox.com', 'rbxcdn.com', 'epicgames.com', 'fortnite.com', 'steampowered.com', 'steamcommunity.com', 'minecraft.net', 'battle.net', 'ea.com', 'miniclip.com', 'poki.com', 'crazygames.com', 'friv.com']],
  ['Gambling', ['bet365.com', 'pokerstars.com', '888.com', '888casino.com', 'betfair.com', 'williamhill.com', 'stake.com', 'roobet.com']],
  ['File sharing', ['wetransfer.com', 'mega.nz', 'mega.io', 'mediafire.com', '4shared.com', 'sendspace.com', 'file.io', 'gofile.io']],
  ['AI chatbots', ['chatgpt.com', 'chat.openai.com', 'gemini.google.com', 'claude.ai', 'copilot.microsoft.com', 'perplexity.ai', 'chat.deepseek.com', 'deepseek.com']],
];
const RESET_LABEL = { restore_baseline: 'Restore baseline snapshot', factory_reset: 'Factory reset (wipe all)', factory_reset_keep_data: 'Factory reset (keep user files)' };
const CATALOG = [
  ['Google Chrome', 'Google.Chrome'], ['Mozilla Firefox', 'Mozilla.Firefox'], ['7-Zip', '7zip.7zip'],
  ['Adobe Acrobat Reader', 'Adobe.Acrobat.Reader.64-bit'], ['Microsoft Teams', 'Microsoft.Teams'], ['Zoom', 'Zoom.Zoom'],
  ['Microsoft 365 Apps', 'Microsoft.Office'], ['LibreOffice', 'TheDocumentFoundation.LibreOffice'], ['VLC', 'VideoLAN.VLC'],
  ['Notepad++', 'Notepad++.Notepad++'], ['AnyDesk', 'AnyDeskSoftwareGmbH.AnyDesk'], ['TeamViewer', 'TeamViewer.TeamViewer'],
  ['Google Drive', 'Google.GoogleDrive'], ['Dropbox', 'Dropbox.Dropbox'], ['WinRAR', 'RARLab.WinRAR'], ['Slack', 'SlackTechnologies.Slack'],
];

const ROLE_LABEL = { superadmin: 'Platform owner', municipality_admin: 'Municipality admin', school_manager: 'School manager', teacher: 'Teacher' };
const cap = (k) => !!(state.me && state.me.capabilities && state.me.capabilities[k]);
const isAdmin = () => ['superadmin', 'municipality_admin'].includes(state.me && state.me.role);
const roleLabel = (r) => ROLE_LABEL[r] || r;
const placeText = (d) => (d.place && d.place.lab ? `${d.place.school ? d.place.school + ' · ' : ''}${d.place.lab}` : '');

// ------------------------------------------------------------------ utils
async function api(path, opts = {}) {
  const o = { method: opts.method || 'GET', headers: { 'X-KEM': '1' }, credentials: 'same-origin' };
  if (opts.body !== undefined) { o.headers['Content-Type'] = 'application/json'; o.body = JSON.stringify(opts.body); }
  const r = await fetch(path, o);
  let data = null;
  try { data = await r.json(); } catch { /* empty body */ }
  if (r.status === 401 && path !== '/api/login') { showLogin(); throw new Error('Please sign in'); }
  if (!r.ok) {
    const d = data && data.detail;
    throw new Error(typeof d === 'string' ? d : Array.isArray(d) ? d.map((x) => x.msg).join(', ') : r.statusText);
  }
  return data;
}

function toast(msg, err = false) {
  const t = document.createElement('div');
  t.className = 'toast' + (err ? ' err' : '');
  t.textContent = msg;
  $('#toasts').append(t);
  setTimeout(() => t.remove(), err ? 6000 : 3500);
}

function ago(ts) {
  if (!ts) return 'never';
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
const fmtDate = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : '—');
const dash = (v) => (v === null || v === undefined || v === '' ? '—' : esc(v));

function meter(v) {
  if (v === null || v === undefined) return '<span class="mval">—</span>';
  const cls = v >= 90 ? 'crit' : v >= 75 ? 'hi' : '';
  return `<span class="meter ${cls}"><span style="width:${Math.min(100, v)}%"></span></span><span class="mval">${Math.round(v)}%</span>`;
}

function statusPill(s) {
  const cls = { success: 'ok', failed: 'crit', running: 'blue', sent: 'info', queued: '', cancelled: '' }[s] ?? '';
  return `<span class="pill ${cls}">${esc(s)}</span>`;
}

function deviceIcon(chassis) { return chassis === 'laptop' ? '💻' : chassis === 'desktop' ? '🖥️' : '▣'; }

function cmdSummary(c) {
  const p = c.params || {};
  switch (c.type) {
    case 'install_software': return p.method === 'winget' ? `winget: ${p.package_id}` : p.url;
    case 'uninstall_software': return `winget: ${p.package_id}`;
    case 'block_internet': return p.allow_lan ? 'LAN still allowed' : 'Management server only';
    case 'run_script': return (p.script || '').split('\n')[0].slice(0, 80);
    case 'reboot': return `in ${p.delay}s${p.message ? ' · ' + p.message : ''}`;
    case 'defender_scan': return `${p.scan_type} scan`;
    case 'reset_device': return RESET_LABEL[p.mode] || p.mode;
    case 'install_updates': return `${p.scope === 'selected' ? `${(p.update_ids || []).length} selected` : p.scope === 'all' ? 'all updates' : 'security updates'} · reboot ${p.reboot === 'never' ? 'never' : 'if needed'}`;
    case 'set_web_filter': return (p.domains || []).length ? `${p.domains.length} blocked: ${p.domains.slice(0, 5).join(', ')}${p.domains.length > 5 ? '…' : ''}` : 'filter removed';
    case 'usb_storage': return USB_LABEL[p.mode] || p.mode;
    case 'kill_process': return p.pid ? `PID ${p.pid}` : p.name;
    case 'service_action': return `${p.name}: ${[p.action !== 'none' ? p.action : '', p.startup ? 'startup ' + p.startup : ''].filter(Boolean).join(', ')}`;
    case 'send_message': return `${p.title}: ${p.text}`.slice(0, 100);
    case 'lock_session': return p.action === 'logoff' ? 'Sign out user' : 'Lock screen';
    default: return '';
  }
}

// Queue a command for one device and wait for its result (the device page puts the agent in 3 s "live" mode).
async function runAndWait(deviceId, type, params = {}, onWait = () => {}, timeoutMs = 180000) {
  const r = await api('/api/commands', { method: 'POST', body: { device_ids: [deviceId], type, params } });
  const id = r.created[0];
  const t0 = Date.now();
  for (;;) {
    await new Promise((res) => setTimeout(res, 1500));
    const c = await api(`/api/commands/${id}`);
    if (['success', 'failed', 'cancelled'].includes(c.status)) return c;
    onWait(c);
    if (Date.now() - t0 > timeoutMs) throw new Error('The device did not answer in time. It may be offline — the request stays queued.');
  }
}

const fmtMB = (mb) => (mb == null ? '—' : mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${Math.round(mb)} MB`);

// ------------------------------------------------------------------ modal
function modal({ title, body, submit = 'Confirm', danger = false, onSubmit, wide = false }) {
  const root = $('#modal-root');
  root.innerHTML = `<div class="overlay"><form class="modal" ${wide ? 'style="max-width:720px"' : ''}>
    <header><h3>${esc(title)}</h3><button type="button" class="x" aria-label="Close">×</button></header>
    <div class="body">${body}</div>
    <footer><button type="button" class="btn" data-close>Cancel</button>
    <button type="submit" class="btn ${danger ? 'danger' : 'primary'}">${esc(submit)}</button></footer></form></div>`;
  const form = $('form', root);
  const close = () => { root.innerHTML = ''; };
  $('.x', root).onclick = close;
  $('[data-close]', root).onclick = close;
  $('.overlay', root).addEventListener('mousedown', (e) => { if (e.target.classList.contains('overlay')) close(); });
  form.onsubmit = async (e) => {
    e.preventDefault();
    const btn = $('button[type=submit]', form);
    btn.disabled = true;
    try { if ((await onSubmit(form)) !== false) close(); } catch (err) { toast(err.message, true); } finally { btn.disabled = false; }
  };
  const first = $('input:not([type=hidden]):not([type=radio]):not([type=checkbox]), textarea', form);
  if (first) first.focus();
  return form;
}

async function queue(ids, type, params = {}, confirm = '') {
  const r = await api('/api/commands', { method: 'POST', body: { device_ids: ids, type, params, confirm } });
  toast(`${CMD[type]} queued for ${r.created.length} device${r.created.length > 1 ? 's' : ''}`);
  refreshCurrent();
}

function hostnamesOf(ids) {
  return ids.map((id) => state.devices.find((d) => d.id === id)?.hostname || id);
}

function targetLine(ids) {
  const names = hostnamesOf(ids);
  const shown = names.slice(0, 4).map((n) => `<b>${esc(n)}</b>`).join(', ');
  return `<p class="muted" style="margin:0">Target: ${shown}${names.length > 4 ? ` and ${names.length - 4} more` : ''}</p>`;
}

// ------------------------------------------------------------------ actions
const ACTIONS = {
  block_internet(ids) {
    modal({
      title: 'Block internet access', submit: 'Block internet', danger: true,
      body: `${targetLine(ids)}
        <p class="note">The device keeps talking to this management server (so you can restore access later),
        plus DNS, DHCP and time sync. Every other outbound connection is blocked by Windows Firewall rules that
        the agent re-applies if someone removes them.</p>
        <label class="check"><input type="checkbox" name="allow_lan"> <div>Keep local network access<br><span class="muted small">Printers, file shares and other devices on the office LAN stay reachable.</span></div></label>`,
      onSubmit: (f) => queue(ids, 'block_internet', { allow_lan: f.allow_lan.checked }),
    });
  },
  unblock_internet(ids) {
    modal({ title: 'Restore internet access', submit: 'Restore access', body: `${targetLine(ids)}<p class="note">Removes the KEM isolation firewall rules.</p>`, onSubmit: () => queue(ids, 'unblock_internet') });
  },
  install_software(ids) {
    const form = modal({
      title: 'Install software', submit: 'Install', wide: true,
      body: `${targetLine(ids)}
        <div class="seg"><button type="button" class="on" data-m="winget">Software catalog (winget)</button><button type="button" data-m="url">Installer from URL</button></div>
        <div data-pane="winget">
          <div class="chips" style="margin-bottom:12px">${CATALOG.map(([n, id]) => `<button type="button" class="chip" data-id="${esc(id)}">${esc(n)}</button>`).join('')}</div>
          <label>winget package ID<input name="package_id" placeholder="e.g. Google.Chrome" class="mono"></label>
          <p class="note" style="margin-top:10px">Any package from the Windows Package Manager catalog. Find IDs with <code>winget search name</code> or at winget.run. Installs silently for all users.</p>
        </div>
        <div data-pane="url" class="hidden" style="display:flex;flex-direction:column;gap:12px">
          <label>Installer URL (.msi or .exe)<input name="url" placeholder="https://example.com/setup.msi"></label>
          <label>Silent install arguments<input name="args" class="mono" placeholder="MSI: none needed · EXE: e.g. /S or /quiet /norestart"></label>
          <label>SHA-256 checksum (optional, recommended)<input name="sha256" class="mono" placeholder="64 hex characters"></label>
          <p class="note">MSI files run with <code>msiexec /i … /qn /norestart</code>. For EXE installers you must supply the vendor's silent switch.</p>
        </div>`,
      onSubmit: (f) => {
        const method = $('.seg .on', f).dataset.m;
        if (method === 'winget') return queue(ids, 'install_software', { method, package_id: f.package_id.value.trim() });
        return queue(ids, 'install_software', { method, url: f.url.value.trim(), args: f.args.value.trim(), sha256: f.sha256.value.trim() });
      },
    });
    $$('.seg button', form).forEach((b) => (b.onclick = () => {
      $$('.seg button', form).forEach((x) => x.classList.toggle('on', x === b));
      $$('[data-pane]', form).forEach((p) => p.classList.toggle('hidden', p.dataset.pane !== b.dataset.m));
    }));
    $$('.chip', form).forEach((c) => (c.onclick = () => {
      $$('.chip', form).forEach((x) => x.classList.toggle('on', x === c));
      form.package_id.value = c.dataset.id;
    }));
  },
  uninstall_software(ids) {
    modal({
      title: 'Uninstall software', submit: 'Uninstall', danger: true,
      body: `${targetLine(ids)}<label>winget package ID<input name="package_id" class="mono" placeholder="e.g. Zoom.Zoom" required></label>`,
      onSubmit: (f) => queue(ids, 'uninstall_software', { package_id: f.package_id.value.trim() }),
    });
  },
  run_script(ids) {
    modal({
      title: 'Run PowerShell script', submit: 'Run', wide: true,
      body: `${targetLine(ids)}
        <textarea name="script" spellcheck="false" placeholder="Get-Service | Where-Object Status -eq 'Running' | Select-Object -First 10"></textarea>
        <div class="row"><label style="width:180px">Timeout (seconds)<input name="timeout" type="number" value="600" min="10" max="7200"></label>
        <p class="note warn grow">Runs as <b>SYSTEM</b> (full control of the machine). Output is returned to the activity log.</p></div>`,
      onSubmit: (f) => queue(ids, 'run_script', { script: f.script.value, timeout: +f.timeout.value }),
    });
  },
  reboot(ids) {
    modal({
      title: 'Reboot', submit: 'Reboot', danger: true,
      body: `${targetLine(ids)}
        <div class="row"><label style="width:160px">Delay (seconds)<input name="delay" type="number" value="60" min="0" max="3600"></label>
        <label class="grow">Message shown to the user<input name="message" maxlength="200" placeholder="IT maintenance: your computer will restart"></label></div>`,
      onSubmit: (f) => queue(ids, 'reboot', { delay: +f.delay.value, message: f.message.value }),
    });
  },
  defender_scan(ids) {
    modal({
      title: 'Microsoft Defender scan', submit: 'Start scan',
      body: `${targetLine(ids)}<label>Scan type<select name="scan_type"><option value="quick">Quick scan</option><option value="full">Full scan (can take hours)</option></select></label>`,
      onSubmit: (f) => queue(ids, 'defender_scan', { scan_type: f.scan_type.value }),
    });
  },
  refresh_inventory: (ids) => queue(ids, 'refresh_inventory').catch((e) => toast(e.message, true)),
  create_baseline(ids) {
    modal({
      title: 'Create baseline snapshot', submit: 'Create baseline',
      body: `${targetLine(ids)}<p class="note">Takes a Windows System Restore point named "KEM Baseline" and makes it the target for
        <b>Reset → Restore baseline</b>. Do this when the machine is in a known-good state (all standard software installed).
        It replaces the previous baseline.</p>`,
      onSubmit: () => queue(ids, 'create_baseline'),
    });
  },
  reset_device(ids) {
    const d = state.devices.find((x) => x.id === ids[0]) || { hostname: '' };
    modal({
      title: `Reset ${d.hostname}`, submit: 'Reset device', danger: true,
      body: `<label class="option"><input type="radio" name="mode" value="restore_baseline" checked><div><b>Restore baseline snapshot</b>
          <span>Rolls Windows, installed programs, drivers and settings back to the baseline restore point, then reboots. User documents are kept. Fast (10–20 min).</span></div></label>
        <label class="option"><input type="radio" name="mode" value="factory_reset_keep_data"><div><b>Factory reset — keep user files</b>
          <span>Reinstalls Windows from the recovery image. Removes all apps and settings, keeps files in user folders. Agent is removed; re-enroll afterwards.</span></div></label>
        <label class="option"><input type="radio" name="mode" value="factory_reset"><div><b>Factory reset — wipe everything</b>
          <span>Reinstalls Windows and erases all data. Equivalent to a fresh install. Cannot be undone. Agent is removed; re-enroll afterwards.</span></div></label>
        <label><span>Type <b class="mono">${esc(d.hostname)}</b> to confirm</span><input name="confirm" autocomplete="off" required></label>`,
      onSubmit: (f) => queue(ids, 'reset_device', { mode: f.mode.value }, f.confirm.value),
    });
  },
  uninstall_agent(ids) {
    const d = state.devices.find((x) => x.id === ids[0]) || { hostname: '' };
    modal({
      title: 'Remove agent', submit: 'Remove agent', danger: true,
      body: `<p class="note">Lifts any internet block, web filter and USB restriction, then deletes the KEM scheduled task and files from <b>${esc(d.hostname)}</b>. The device will stop reporting.</p>
        <label><span>Type <b class="mono">${esc(d.hostname)}</b> to confirm</span><input name="confirm" autocomplete="off" required></label>`,
      onSubmit: (f) => queue(ids, 'uninstall_agent', {}, f.confirm.value),
    });
  },
  scan_updates: (ids) => queue(ids, 'scan_updates').catch((e) => toast(e.message, true)),
  install_updates(ids, preset = {}) {
    const selected = preset.update_ids || [];
    modal({
      title: 'Install Windows updates', submit: 'Install updates',
      body: `${targetLine(ids)}
        ${selected.length ? `<input type="hidden" name="scope" value="selected"><p class="note"><b>${selected.length}</b> selected update${selected.length > 1 ? 's' : ''} will be downloaded and installed.</p>` : `
        <label class="option"><input type="radio" name="scope" value="security" checked><div><b>Security &amp; critical updates</b><span>Monthly security patches and critical fixes. Recommended.</span></div></label>
        <label class="option"><input type="radio" name="scope" value="all"><div><b>All updates</b><span>Security, quality and optional updates. Feature upgrades (e.g. a new Windows version) are never installed this way.</span></div></label>
        <label class="check"><input type="checkbox" name="include_drivers"> Include driver updates</label>`}
        <label>If a restart is needed<select name="reboot">
          <option value="if_needed">Restart automatically — warn the user first</option><option value="never">Don't restart (finish at the next restart)</option></select></label>
        <label>Warning time before restart<select name="reboot_delay"><option value="300">5 minutes</option><option value="600" selected>10 minutes</option><option value="1800">30 minutes</option><option value="3600">1 hour</option></select></label>
        <p class="note">Runs in the background on the device — downloads can take a while. The device's update list refreshes when it finishes.</p>`,
      onSubmit: (f) => queue(ids, 'install_updates', {
        scope: f.scope.value || (f.querySelector('[name=scope]:checked') || {}).value, update_ids: selected,
        include_drivers: !!(f.include_drivers && f.include_drivers.checked), reboot: f.reboot.value, reboot_delay: +f.reboot_delay.value,
      }),
    });
  },
  async set_web_filter(ids) {
    let current = [];
    if (ids.length === 1) {
      try { current = ((await api(`/api/devices/${ids[0]}`)).inventory || {}).web_filter || []; } catch (e) { toast(e.message, true); return; }
    }
    const form = modal({
      title: 'Web filter — block websites', submit: 'Apply filter', wide: true,
      body: `${targetLine(ids)}
        <div><div class="muted small" style="margin-bottom:6px">Quick add</div><div class="chips">${WEB_PRESETS.map(([n], i) => `<button type="button" class="chip" data-p="${i}">${esc(n)}</button>`).join('')}</div></div>
        <label>Blocked domains — one per line (sub-domains <span class="mono">www.</span> and <span class="mono">m.</span> are included)
          <textarea name="domains" spellcheck="false" style="min-height:200px" placeholder="facebook.com&#10;youtube.com">${esc(current.join('\n'))}</textarea></label>
        <p class="note">${ids.length > 1 ? '<b>Replaces</b> the current list on every selected device. ' : ''}Leave empty to remove the filter. Microsoft sites can't be blocked this way (Windows Defender restores them).
          Works in every browser (their DNS-over-HTTPS is turned off by policy). Users with a VPN can get around it — combine with <b>Block internet</b> for full lockdown.</p>`,
      onSubmit: (f) => queue(ids, 'set_web_filter', { domains: f.domains.value.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean) }),
    });
    const lines = () => form.domains.value.split(/[\s,;]+/).map((x) => x.trim().toLowerCase()).filter(Boolean);
    const sync = () => $$('[data-p]', form).forEach((c) => { const l = new Set(lines()); c.classList.toggle('on', WEB_PRESETS[c.dataset.p][1].every((x) => l.has(x))); });
    $$('[data-p]', form).forEach((c) => (c.onclick = () => {
      const set = WEB_PRESETS[c.dataset.p][1];
      const cur = lines();
      form.domains.value = (c.classList.contains('on') ? cur.filter((x) => !set.includes(x)) : [...cur, ...set.filter((x) => !cur.includes(x))]).join('\n');
      sync();
    }));
    form.domains.oninput = sync;
    sync();
  },
  usb_storage(ids) {
    const d = ids.length === 1 ? state.devices.find((x) => x.id === ids[0]) : null;
    const cur = (d && d.usb) || 'allow';
    const opt = (v, t, s) => `<label class="option"><input type="radio" name="mode" value="${v}" ${cur === v ? 'checked' : ''}><div><b>${t}</b><span>${s}</span></div></label>`;
    modal({
      title: 'USB storage', submit: 'Apply',
      body: `${targetLine(ids)}
        ${opt('allow', 'Allow', 'Flash drives and external disks work normally.')}
        ${opt('read_only', 'Read-only', 'Users can open files from a drive but cannot copy anything to it (stops data leaving on USB).')}
        ${opt('block', 'Block', 'USB flash drives, external disks and phones in storage mode are blocked. Keyboards, mice, printers and webcams keep working.')}
        <p class="note">Applies to newly connected drives; a drive that is already plugged in must be re-connected. The agent re-applies the setting if someone changes it.</p>`,
      onSubmit: (f) => queue(ids, 'usb_storage', { mode: f.querySelector('[name=mode]:checked').value }),
    });
  },
  send_message(ids) {
    modal({
      title: 'Send a message to the user', submit: 'Send message',
      body: `${targetLine(ids)}
        <label>Title<input name="title" maxlength="80" value="Message from IT" dir="auto"></label>
        <label>Message<textarea name="text" maxlength="1000" required dir="auto" style="min-height:110px;font-family:inherit;font-size:14px" placeholder="Please save your work — the computer will restart at 18:00."></textarea></label>
        <p class="note">Pops up on top of every window on the signed-in user's screen until they click OK. Nothing is shown if nobody is signed in.</p>`,
      onSubmit: (f) => queue(ids, 'send_message', { title: f.title.value, text: f.text.value }),
    });
  },
  lock_session(ids) {
    modal({
      title: 'Lock or sign out', submit: 'Apply', danger: true,
      body: `${targetLine(ids)}
        <label class="option"><input type="radio" name="action" value="lock" checked><div><b>Lock the screen</b><span>The user must enter their password to continue. Open programs keep running.</span></div></label>
        <label class="option"><input type="radio" name="action" value="logoff"><div><b>Sign the user out</b><span>Closes all programs — <b>unsaved work is lost</b>.</span></div></label>`,
      onSubmit: (f) => queue(ids, 'lock_session', { action: f.querySelector('[name=action]:checked').value }),
    });
  },
  update_agent: (ids) => queue(ids, 'update_agent').catch((e) => toast(e.message, true)),
};

// ------------------------------------------------------------------ router
function setNav(name) { $$('.side nav a').forEach((a) => a.classList.toggle('active', a.dataset.nav === name)); }
let refreshCurrent = () => {};

function route() {
  clearInterval(state.timer);
  $('#modal-root').innerHTML = '';
  const [, name = 'devices', arg] = (location.hash || '#/devices').split('/');
  setNav(name === 'device' ? 'devices' : name);
  const views = { devices: viewDevices, device: () => viewDevice(arg), enroll: viewEnroll, activity: viewActivity,
    audit: viewAudit, settings: viewSettings, org: viewOrg, users: viewUsers, gateways: viewGateways, licensing: viewLicensing, incidents: viewIncidents };
  const needs = { org: 'manage_org', users: 'manage_users', gateways: 'manage_gateways', enroll: 'manage_tokens', audit: 'view_audit', licensing: 'view_licensing', incidents: 'view_incidents' };
  if (needs[name] && !cap(needs[name])) { location.hash = '#/devices'; return; }
  (views[name] || viewDevices)();
}

function every(fn, ms) { refreshCurrent = fn; state.timer = setInterval(() => { if (!document.hidden) fn(); }, ms); }

// ------------------------------------------------------------------ devices list
async function viewDevices() {
  view.innerHTML = `
    <div class="page-head"><div><h1>Devices</h1><p class="sub">${state.me.role === 'teacher' ? 'Your lab' : 'Stations managed by this server'}${state.me.scope_label && state.me.role !== 'superadmin' ? ' · ' + esc(state.me.scope_label) : ''}</p></div>
      ${cap('manage_tokens') ? '<a class="btn primary" href="#/enroll">＋ Add devices</a>' : ''}</div>
    <div id="classbar"></div>
    <div id="exambar"></div>
    <section class="tiles" id="tiles"></section>
    <div class="toolbar">
      <input id="q" type="search" placeholder="Search hostname, user, IP, OS, model…" value="${esc(state.filter.q)}">
      <select id="fgroup"></select>
    </div>
    <div class="bulkbar hidden" id="bulk">
      <b id="bulkcount"></b>
      <button class="btn small" data-act="block_internet">⛔ Block internet</button>
      <button class="btn small" data-act="unblock_internet">🌐 Restore internet</button>
      <button class="btn small" data-act="install_software">⬇ Install software</button>
      <button class="btn small" data-act="install_updates">⟳ Windows updates</button>
      <button class="btn small" data-act="set_web_filter">🚫 Web filter</button>
      <button class="btn small" data-act="usb_storage">🔌 USB</button>
      <button class="btn small" data-act="send_message">💬 Message</button>
      <button class="btn small" data-act="lock_session">🔒 Lock</button>
      <button class="btn small" data-act="run_script">›_ Run script</button>
      <button class="btn small" data-act="defender_scan">🛡 Scan</button>
      <button class="btn small" data-act="reboot">↻ Reboot</button>
      <button class="link small" id="bulkclear" style="margin-left:auto">Clear selection</button>
    </div>
    <div class="card table-wrap"><table class="grid">
      <thead><tr><th style="width:32px"><input type="checkbox" id="selall" aria-label="Select all"></th><th>Device</th><th>User</th><th>OS</th><th>IP</th>
      <th>CPU</th><th>RAM</th><th>Disk</th><th class="nowrap">Last seen</th><th>Status</th></tr></thead>
      <tbody id="rows"><tr><td colspan="10" class="empty">Loading…</td></tr></tbody></table></div>`;

  $('#q').oninput = (e) => { state.filter.q = e.target.value; renderDevices(); };
  $('#fgroup').onchange = (e) => { state.filter.group = e.target.value; renderDevices(); };
  $('#selall').onchange = (e) => { filtered().forEach((d) => (e.target.checked ? state.selected.add(d.id) : state.selected.delete(d.id))); renderDevices(); };
  $('#bulkclear').onclick = () => { state.selected.clear(); renderDevices(); };
  const allowedCmds = new Set(state.me.capabilities.commands || []);
  $$('#bulk [data-act]').forEach((b) => { if (!allowedCmds.has(b.dataset.act)) b.remove(); else b.onclick = () => ACTIONS[b.dataset.act]([...state.selected]); });
  if (state.me.role === 'teacher') renderClassBar();
  if (cap('manage_exams')) renderExamBar();
  $('#rows').addEventListener('click', (e) => {
    const cb = e.target.closest('input[type=checkbox]');
    const tr = e.target.closest('tr[data-id]');
    if (!tr) return;
    if (cb) { cb.checked ? state.selected.add(tr.dataset.id) : state.selected.delete(tr.dataset.id); renderDevices(); return; }
    if (e.target.closest('td.sel')) return;
    location.hash = `#/device/${tr.dataset.id}`;
  });

  const load = async () => { state.devices = await api('/api/devices'); renderDevices(); };
  await load().catch((e) => toast(e.message, true));
  every(load, 10000);
}

function filtered() {
  const { q, status, group } = state.filter;
  const needle = q.trim().toLowerCase();
  return state.devices.filter((d) => {
    if (group && d.group !== group) return false;
    if (status === 'online' && !d.online) return false;
    if (status === 'offline' && d.online) return false;
    if (status === 'isolated' && !d.isolated) return false;
    if (status === 'alerts' && !d.alerts.some((a) => a.level !== 'info')) return false;
    if (status === 'updates' && !(d.updates && d.updates.security)) return false;
    if (!needle) return true;
    return [d.hostname, d.user, d.os, d.model, d.group, d.public_ip, ...(d.ips || [])].join(' ').toLowerCase().includes(needle);
  });
}

function renderDevices() {
  const all = state.devices;
  const known = new Set(all.map((d) => d.id));
  [...state.selected].forEach((id) => { if (!known.has(id)) state.selected.delete(id); });
  const counts = {
    all: all.length, online: all.filter((d) => d.online).length, offline: all.filter((d) => !d.online).length,
    isolated: all.filter((d) => d.isolated).length, alerts: all.filter((d) => d.alerts.some((a) => a.level !== 'info')).length,
    updates: all.filter((d) => d.updates && d.updates.security).length,
  };
  const tiles = [['all', 'Total devices', ''], ['online', 'Online', '<span class="dot on"></span>'], ['offline', 'Offline', '<span class="dot"></span>'],
    ['isolated', 'Internet blocked', '⛔'], ['updates', 'Missing security updates', '⟳'], ['alerts', 'Need attention', '⚠']];
  $('#tiles').innerHTML = tiles.map(([k, l, ic]) => `<button class="tile ${state.filter.status === k ? 'on' : ''}" data-k="${k}"><div class="l">${ic}${l}</div><div class="n">${counts[k]}</div></button>`).join('');
  $$('#tiles .tile').forEach((t) => (t.onclick = () => { state.filter.status = state.filter.status === t.dataset.k ? 'all' : t.dataset.k; renderDevices(); }));

  const groups = [...new Set(all.map((d) => d.group).filter(Boolean))].sort();
  const gsel = $('#fgroup');
  gsel.innerHTML = `<option value="">All groups</option>` + groups.map((g) => `<option ${g === state.filter.group ? 'selected' : ''}>${esc(g)}</option>`).join('');
  gsel.classList.toggle('hidden', !groups.length);

  const list = filtered();
  $('#selall').checked = list.length > 0 && list.every((d) => state.selected.has(d.id));
  $('#bulk').classList.toggle('hidden', !state.selected.size);
  $('#bulkcount').textContent = `${state.selected.size} selected`;

  if (!all.length) {
    $('#rows').innerHTML = `<tr><td colspan="10" class="empty">No devices yet. <a href="#/enroll">Create a registration token</a> and install the agent on a laptop or desktop.</td></tr>`;
    return;
  }
  if (!list.length) { $('#rows').innerHTML = `<tr><td colspan="10" class="empty">No devices match this filter.</td></tr>`; return; }
  $('#rows').innerHTML = list.map((d) => `
    <tr class="click" data-id="${esc(d.id)}">
      <td class="sel"><input type="checkbox" ${state.selected.has(d.id) ? 'checked' : ''} aria-label="Select ${esc(d.hostname)}"></td>
      <td><div class="row" style="flex-wrap:nowrap"><span class="dot ${d.online ? 'on' : ''}" title="${d.online ? 'Online' : 'Offline'}"></span>
        <span class="host"><b>${deviceIcon(d.chassis)} ${esc(d.hostname)}</b><small>${esc(d.model || '')}${placeText(d) ? ' · ' + esc(placeText(d)) : ''}${d.group ? ' · ' + esc(d.group) : ''}</small></span></div></td>
      <td>${dash((d.user || '').split('\\').pop())}</td>
      <td class="small">${dash(d.os.replace('Microsoft ', ''))}${d.os_version ? ` <span class="muted">${esc(d.os_version)}</span>` : ''}</td>
      <td class="mono small">${dash((d.ips || [])[0])}</td>
      <td class="nowrap">${meter(d.online ? d.cpu : null)}</td><td class="nowrap">${meter(d.online ? d.mem : null)}</td><td class="nowrap">${meter(d.disk)}</td>
      <td class="nowrap small muted">${ago(d.last_seen)}</td>
      <td><div class="flags">${d.isolated ? '<span class="pill crit">⛔ Blocked</span>' : ''}${d.busy ? '<span class="pill blue">Working…</span>' : ''}
        ${d.web_filter ? `<span class="pill" title="Web filter: ${d.web_filter} domains blocked">🚫 Filter</span>` : ''}
        ${d.usb && d.usb !== 'allow' ? `<span class="pill" title="USB storage ${esc(USB_LABEL[d.usb])}">🔌 USB ${d.usb === 'block' ? 'off' : 'RO'}</span>` : ''}
        ${d.alerts.filter((a) => a.level !== 'info').slice(0, 2).map((a) => `<span class="pill ${a.level}" title="${esc(a.text)}">${esc(a.text)}</span>`).join('')}
        ${!d.isolated && !d.alerts.some((a) => a.level !== 'info') ? '<span class="pill ok">Healthy</span>' : ''}</div></td>
    </tr>`).join('');
}

async function renderClassBar() {
  const bar = $('#classbar');
  if (!bar) return;
  let info;
  try { info = await api('/api/class/active'); } catch { return; }
  const active = info.active;
  bar.innerHTML = `<div class="classbar ${active ? 'on' : ''}">
    <span>${active ? `<b>Class in session</b> — classroom controls are enabled${active.note ? ' · ' + esc(active.note) : ''}` : 'Start a class session to control the computers in your lab.'}</span>
    <button class="btn ${active ? '' : 'primary'} small" id="classtoggle">${active ? 'End class' : 'Start class'}</button></div>`;
  $('#classtoggle').onclick = async () => {
    try {
      if (active) await api('/api/class/stop', { method: 'POST' });
      else await api('/api/class/start', { method: 'POST', body: {} });
      toast(active ? 'Class ended' : 'Class started');
      renderClassBar();
    } catch (e) { toast(e.message, true); }
  };
}

const EXAM_LOCKS = (e) => [e.lock_internet ? 'internet blocked' : null, e.lock_usb ? 'USB blocked' : null,
  (e.web_filter && e.web_filter.length) ? `${e.web_filter.length} sites filtered` : null].filter(Boolean).join(' · ') || 'no restrictions';

// Examination mode: lock every station in a lab into a controlled state, and lift it again.
async function renderExamBar() {
  const bar = $('#exambar');
  if (!bar) return;
  let exams;
  try { exams = await api('/api/exams'); } catch { return; }
  const active = exams.filter((e) => e.active);
  const isTeacher = state.me.role === 'teacher';

  // Labs the operator can target, taken from the devices already loaded (a non-teacher picker).
  const labs = new Map();
  (state.devices || []).forEach((d) => { if (d.lab_id && d.place && d.place.lab) labs.set(d.lab_id, placeText(d)); });
  const canStart = isTeacher || labs.size > 0;

  const activeHtml = active.map((e) => `
    <div class="classbar exam on">
      <span>🔒 <b>Exam: ${esc(e.name)}</b> — ${esc(e.lab_name)} · ${e.stations} station${e.stations === 1 ? '' : 's'}
        · ${EXAM_LOCKS(e)} · by ${esc(e.started_by)} ${ago(e.started)}</span>
      <button class="btn small" data-stop="${esc(e.id)}">End exam</button>
    </div>`).join('');

  const labPicker = isTeacher ? '' :
    `<select name="lab_id" required>${[...labs].map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join('')}</select>`;
  const startHtml = canStart ? `
    <form class="classbar exam" id="examstart">
      <span>🎓 <b>Exam mode</b> — lock a lab's stations for a test${isTeacher ? ' (needs an active class)' : ''}:</span>
      ${labPicker}
      <input name="name" placeholder="Exam name" maxlength="120" style="flex:1;min-width:120px">
      <label class="chk"><input type="checkbox" name="li" checked> internet</label>
      <label class="chk"><input type="checkbox" name="lu" checked> USB</label>
      <button class="btn primary small" type="submit">Start exam</button>
    </form>` :
    (active.length ? '' : `<div class="classbar exam"><span class="muted">No labs with stations to run an exam on yet.</span></div>`);

  bar.innerHTML = activeHtml + startHtml;

  bar.querySelectorAll('[data-stop]').forEach((b) => (b.onclick = async () => {
    b.disabled = true;
    try { const r = await api(`/api/exams/${b.dataset.stop}/stop`, { method: 'POST' }); toast(`Exam ended · ${r.commands} commands queued`); renderExamBar(); }
    catch (e) { toast(e.message, true); b.disabled = false; }
  }));
  const form = $('#examstart');
  if (form) form.onsubmit = async (ev) => {
    ev.preventDefault();
    const body = { name: form.name.value.trim(), lock_internet: form.li.checked, lock_usb: form.lu.checked };
    if (!isTeacher) body.lab_id = form.lab_id.value;
    try { const r = await api('/api/exams/start', { method: 'POST', body }); toast(`Exam started · ${r.stations} stations · ${r.commands} commands queued`); renderExamBar(); }
    catch (e) { toast(e.message, true); }
  };
}

// ------------------------------------------------------------------ device page
async function viewDevice(id) {
  const TABS = [['commands', 'Activity'], ['updates', 'Windows updates'], ['software', 'Installed software'], ['processes', 'Processes'], ['services', 'Services']];
  const ui = { tab: 'commands', softQ: '', softAt: null, updSig: null, open: new Set(), loaded: {}, busy: {}, sel: new Set(),
    procQ: '', procSort: 'mem', procs: null, procAt: null, svcQ: '', svcFilter: 'all', svcs: null, svcAt: null };
  view.innerHTML = `<p><a href="#/devices">← All devices</a></p><div id="dhead"></div><div id="dbanner"></div><div class="cards" id="dcards"></div>
    <div class="card" style="margin-bottom:16px"><div class="tabs">${TABS.map(([k, l], i) => `<button data-t="${k}" class="${i ? '' : 'on'}">${l}<span class="tcount" id="tc-${k}"></span></button>`).join('')}</div>
      ${TABS.map(([k], i) => `<div id="tab-${k}" class="${i ? 'hidden' : ''}"></div>`).join('')}
    </div>
    <div class="card pad danger-zone" id="danger"></div>`;
  $('#tab-software').innerHTML = `<div class="toolbar tabbar"><input type="search" id="softq" placeholder="Filter software…"><span id="softmeta" class="muted small"></span></div><div class="table-wrap" id="softlist"></div>`;
  $('#tab-processes').innerHTML = `<div class="toolbar tabbar"><input type="search" id="procq" placeholder="Filter by name, user or path…">
      <select id="procsort"><option value="mem">Sort by memory</option><option value="cpu">Sort by CPU</option><option value="name">Sort by name</option></select>
      <button class="btn" id="procrefresh">⟳ Refresh</button><span id="procmeta" class="muted small"></span></div><div class="table-wrap" id="proclist"></div>`;
  $('#tab-services').innerHTML = `<div class="toolbar tabbar"><input type="search" id="svcq" placeholder="Filter services…">
      <select id="svcfilter"><option value="all">All services</option><option value="running">Running</option><option value="stopped">Stopped</option><option value="autostopped">Automatic but stopped</option></select>
      <button class="btn" id="svcrefresh">⟳ Refresh</button><span id="svcmeta" class="muted small"></span></div><div class="table-wrap" id="svclist"></div>`;

  const showTab = (k) => {
    ui.tab = k;
    $$('.tabs button').forEach((x) => x.classList.toggle('on', x.dataset.t === k));
    TABS.forEach(([t]) => $(`#tab-${t}`).classList.toggle('hidden', t !== k));
    if (!ui.loaded[k] && dev) { ui.loaded[k] = true; firstOpen(k); }
  };
  $$('.tabs button').forEach((b) => (b.onclick = () => showTab(b.dataset.t)));
  $('#softq').oninput = (e) => { ui.softQ = e.target.value.toLowerCase(); renderSoftware(); };
  $('#procq').oninput = (e) => { ui.procQ = e.target.value.toLowerCase(); renderProcesses(); };
  $('#procsort').onchange = (e) => { ui.procSort = e.target.value; renderProcesses(); };
  $('#svcq').oninput = (e) => { ui.svcQ = e.target.value.toLowerCase(); renderServices(); };
  $('#svcfilter').onchange = (e) => { ui.svcFilter = e.target.value; renderServices(); };
  $('#procrefresh').onclick = () => fetchList('processes');
  $('#svcrefresh').onclick = () => fetchList('services');
  let dev = null;

  const KIND = { processes: 'list_processes', services: 'list_services' };
  const latestWithData = (type) => (dev.commands || []).find((c) => c.type === type && c.has_data);

  async function firstOpen(k) {
    if (!KIND[k]) return;
    const prev = latestWithData(KIND[k]);
    if (prev) {
      try {
        const c = await api(`/api/commands/${prev.id}`);
        if (k === 'processes') { ui.procs = c.data || []; ui.procAt = c.finished; renderProcesses(); }
        if (k === 'services') { ui.svcs = c.data || []; ui.svcAt = c.finished; renderServices(); }
      } catch (e) { toast(e.message, true); }
    }
    // Lists are cheap: refresh them when they are older than a minute.
    if ((k === 'processes' || k === 'services') && (!prev || Date.now() / 1000 - (prev.finished || 0) > 60)) fetchList(k);
  }

  const alive = () => view.contains($('#dhead'));  // false once we navigate away from this device page
  function setBusy(k, msg) {
    ui.busy[k] = !!msg;
    const btn = $({ processes: '#procrefresh', services: '#svcrefresh' }[k]);
    const meta = $({ processes: '#procmeta', services: '#svcmeta' }[k]);
    if (btn) btn.disabled = !!msg;
    if (meta && msg) meta.innerHTML = `<span class="spin"></span> ${esc(msg)}`;
  }
  const waitMsg = () => (dev.online ? 'Waiting for the device…' : 'Device is offline — the request will run when it is back');

  async function fetchList(k) {
    if (ui.busy[k]) return;
    setBusy(k, waitMsg());
    try {
      const c = await runAndWait(id, KIND[k], {}, (x) => setBusy(k, x.status === 'running' || x.status === 'sent' ? 'Collecting…' : waitMsg()));
      if (c.status !== 'success') throw new Error(c.output || `Failed (${c.status})`);
      if (k === 'processes') { ui.procs = c.data || []; ui.procAt = c.finished; }
      else { ui.svcs = c.data || []; ui.svcAt = c.finished; }
    } catch (e) { if (alive()) toast(e.message, true); }
    if (!alive()) return;   // user navigated away while we waited
    setBusy(k, null);
    k === 'processes' ? renderProcesses() : renderServices();
  }

  function renderProcesses() {
    const box = $('#proclist');
    if (!box || ui.busy.processes) return;
    if (!ui.procs) { box.innerHTML = '<div class="empty">Loading…</div>'; return; }
    $('#procmeta').textContent = `${ui.procs.length} processes · ${ago(ui.procAt)}`;
    const key = ui.procSort;
    const rows = ui.procs.filter((p) => !ui.procQ || `${p.name} ${p.user} ${p.path} ${p.pid}`.toLowerCase().includes(ui.procQ))
      .sort((a, b) => (key === 'name' ? a.name.localeCompare(b.name) : (b[key === 'cpu' ? 'cpu' : 'mem_mb'] || 0) - (a[key === 'cpu' ? 'cpu' : 'mem_mb'] || 0)));
    $('#proclist').innerHTML = `<table class="grid"><thead><tr><th>Process</th><th>PID</th><th>CPU</th><th>Memory</th><th>User</th><th>Path</th><th></th></tr></thead><tbody>${
      rows.map((p) => `<tr><td><b>${esc(p.name)}</b></td><td class="mono small">${p.pid}</td>
        <td class="nowrap small">${p.cpu == null ? '—' : p.cpu + '%'}</td><td class="nowrap small">${fmtMB(p.mem_mb)}</td>
        <td class="small">${dash((p.user || '').split('\\').pop())}</td>
        <td class="small muted ellip" title="${esc(p.path)}">${dash(p.path)}</td>
        <td><button class="link small danger-link" data-kill="${p.pid}" data-name="${esc(p.name)}">End</button></td></tr>`).join('')
      || '<tr><td colspan="7" class="empty">Nothing matches</td></tr>'}</tbody></table>`;
    $$('[data-kill]', $('#proclist')).forEach((b) => (b.onclick = () => killDialog(+b.dataset.kill, b.dataset.name)));
  }

  function killDialog(pid, name) {
    modal({
      title: `End ${name}`, submit: 'End process', danger: true,
      body: `<label class="option"><input type="radio" name="scope" value="pid" checked><div><b>Only this process</b><span>${esc(name)} · PID ${pid}</span></div></label>
        <label class="option"><input type="radio" name="scope" value="name"><div><b>Every process named ${esc(name)}</b><span>e.g. all browser windows and helpers</span></div></label>
        <p class="note">The program closes immediately — unsaved work in it is lost.</p>`,
      onSubmit: async (f) => {
        const byName = f.querySelector('[name=scope]:checked').value === 'name';
        runAndWait(id, 'kill_process', byName ? { name } : { pid }).then((c) => {
          toast(c.status === 'success' ? c.output : `Failed: ${c.output}`, c.status !== 'success');
          fetchList('processes');
        }).catch((e) => toast(e.message, true));
        toast('Ending process…');
      },
    });
  }

  function renderServices() {
    const box = $('#svclist');
    if (!box || ui.busy.services) return;
    if (!ui.svcs) { box.innerHTML = '<div class="empty">Loading…</div>'; return; }
    $('#svcmeta').textContent = `${ui.svcs.length} services · ${ago(ui.svcAt)}`;
    const f = ui.svcFilter;
    const rows = ui.svcs.filter((s) => (!ui.svcQ || `${s.display} ${s.name} ${s.description}`.toLowerCase().includes(ui.svcQ))
      && (f === 'all' || (f === 'running' && s.state === 'Running') || (f === 'stopped' && s.state !== 'Running') || (f === 'autostopped' && s.start === 'Auto' && s.state !== 'Running')));
    const startSel = (s) => `<select class="mini" data-start="${esc(s.name)}">${['Auto', 'Manual', 'Disabled'].map((m) => `<option value="${m}" ${s.start === m ? 'selected' : ''}>${m === 'Auto' ? 'Automatic' : m}</option>`).join('')}</select>`;
    $('#svclist').innerHTML = `<table class="grid"><thead><tr><th>Service</th><th>Status</th><th>Startup</th><th>Log on as</th><th></th></tr></thead><tbody>${
      rows.map((s) => `<tr><td><b>${esc(s.display)}</b><div class="mono small muted">${esc(s.name)}</div></td>
        <td>${s.state === 'Running' ? '<span class="pill ok">Running</span>' : `<span class="pill ${s.start === 'Auto' ? 'warn' : ''}">${esc(s.state)}</span>`}</td>
        <td>${startSel(s)}</td><td class="small muted">${dash(s.account)}</td>
        <td class="nowrap">${s.state === 'Running'
          ? `<button class="link small" data-svc="restart" data-n="${esc(s.name)}">Restart</button> · <button class="link small danger-link" data-svc="stop" data-n="${esc(s.name)}">Stop</button>`
          : `<button class="link small" data-svc="start" data-n="${esc(s.name)}">Start</button>`}</td></tr>`).join('')
      || '<tr><td colspan="5" class="empty">Nothing matches</td></tr>'}</tbody></table>`;
    $$('[data-svc]', $('#svclist')).forEach((b) => (b.onclick = () => serviceAction(b.dataset.n, b.dataset.svc, '')));
    $$('[data-start]', $('#svclist')).forEach((s) => (s.onchange = () => serviceAction(s.dataset.start, 'none', { Auto: 'automatic', Manual: 'manual', Disabled: 'disabled' }[s.value])));
  }

  async function serviceAction(name, action, startup) {
    const run = async () => {
      toast(`${action !== 'none' ? action[0].toUpperCase() + action.slice(1) + 'ing' : 'Changing'} ${name}…`);
      try {
        const c = await runAndWait(id, 'service_action', { name, action, startup });
        toast(c.status === 'success' ? c.output : `Failed: ${c.output}`, c.status !== 'success');
      } catch (e) { toast(e.message, true); }
      fetchList('services');
    };
    if (action === 'stop' || startup === 'disabled') {
      modal({ title: `${action === 'stop' ? 'Stop' : 'Disable'} ${name}?`, submit: action === 'stop' ? 'Stop service' : 'Disable', danger: true,
        body: `<p class="note">Programs that depend on this service may stop working until it is started again.</p>`, onSubmit: () => { run(); } });
    } else run();
  }

  function renderSoftware() {
    const sw = (dev.software || []).filter((s) => !ui.softQ || `${s.name} ${s.publisher}`.toLowerCase().includes(ui.softQ));
    $('#softmeta').textContent = dev.software_at ? `${dev.software.length} programs · collected ${ago(dev.software_at)}` : 'Not collected yet';
    $('#softlist').innerHTML = `<table class="grid"><thead><tr><th>Name</th><th>Version</th><th>Publisher</th><th>Installed</th></tr></thead><tbody>${
      sw.map((s) => `<tr><td>${esc(s.name)}${s.scope === 'user' ? ' <span class="pill">per-user</span>' : ''}</td><td class="mono small">${dash(s.version)}</td><td class="small">${dash(s.publisher)}</td><td class="small muted">${dash(s.installed)}</td></tr>`).join('')
      || '<tr><td colspan="4" class="empty">Nothing to show</td></tr>'}</tbody></table>`;
  }

  function renderUpdates(pending) {
    const u = dev.updates || {};
    const list = dev.update_list || [];
    const ids = new Set(list.map((x) => x.id));
    [...ui.sel].forEach((x) => { if (!ids.has(x)) ui.sel.delete(x); });
    const old = dev.agent_version && dev.agent_outdated && !u.at;
    const summary = !u.at ? (pending ? 'Scanning for the first time…' : 'Not scanned yet')
      : `${u.total} update${u.total === 1 ? '' : 's'} available · <b>${u.security}</b> security · scanned ${ago(u.at)}`;
    const sorted = [...list].sort((a, b) => (b.security - a.security) || (a.driver - b.driver) || String(b.date).localeCompare(String(a.date)));
    $('#tab-updates').innerHTML = `<div class="toolbar tabbar">
        <span class="grow small">${pending ? `<span class="spin"></span> ${esc(pending)} · ` : ''}${summary}${u.reboot_required ? ' <span class="pill warn">Restart needed to finish updates</span>' : ''}</span>
        <button class="btn" data-u="scan" ${pending ? 'disabled' : ''}>⟳ Scan now</button>
        <button class="btn" data-u="selected" ${ui.sel.size ? '' : 'disabled'}>Install selected${ui.sel.size ? ` (${ui.sel.size})` : ''}</button>
        <button class="btn primary" data-u="install" ${list.length ? '' : 'disabled'}>Install updates…</button></div>
      ${old ? '<p class="note" style="margin:0 12px 12px">This device runs an older agent without update management. Update the agent from the Controls card.</p>' : ''}
      <div class="table-wrap"><table class="grid"><thead><tr><th style="width:32px"><input type="checkbox" id="updall" ${list.length && ui.sel.size === list.length ? 'checked' : ''}></th><th>Update</th><th>Type</th><th>Size</th><th>Released</th></tr></thead><tbody>${
      sorted.map((x) => `<tr><td><input type="checkbox" data-uid="${esc(x.id)}" ${ui.sel.has(x.id) ? 'checked' : ''}></td>
        <td>${esc(x.title)}${x.kb ? `<div class="mono small muted">${esc(x.kb)}</div>` : ''}</td>
        <td>${x.security ? `<span class="pill crit">Security${x.severity ? ' · ' + esc(x.severity) : ''}</span>` : x.driver ? '<span class="pill">Driver</span>' : x.upgrade ? '<span class="pill info">Feature upgrade</span>' : `<span class="pill">${esc((x.categories || 'Update').split(',')[0])}</span>`}${x.reboot ? ' <span class="pill" title="Needs a restart">↻</span>' : ''}</td>
        <td class="small nowrap">${x.size_mb ? fmtMB(x.size_mb) : '—'}</td><td class="small muted nowrap">${dash(x.date)}</td></tr>`).join('')
      || `<tr><td colspan="5" class="empty">${u.at ? '✓ Windows is up to date' : 'No scan results yet'}</td></tr>`}</tbody></table></div>`;
    const tab = $('#tab-updates');
    $('[data-u=scan]', tab).onclick = () => queue([id], 'scan_updates').catch((e) => toast(e.message, true));
    $('[data-u=install]', tab).onclick = () => ACTIONS.install_updates([id]);
    $('[data-u=selected]', tab).onclick = () => ACTIONS.install_updates([id], { update_ids: [...ui.sel] });
    $('#updall').onchange = (e) => { list.forEach((x) => (e.target.checked ? ui.sel.add(x.id) : ui.sel.delete(x.id))); renderUpdates(pending); };
    $$('[data-uid]', tab).forEach((c) => (c.onchange = () => { c.checked ? ui.sel.add(c.dataset.uid) : ui.sel.delete(c.dataset.uid); renderUpdates(pending); }));
  }

  async function load() {
    try { dev = await api(`/api/devices/${id}`); } catch (e) { view.innerHTML = `<p><a href="#/devices">← All devices</a></p><div class="card empty">${esc(e.message)}</div>`; clearInterval(state.timer); return; }
    if (!state.devices.find((d) => d.id === dev.id)) state.devices.push(dev);
    else state.devices = state.devices.map((d) => (d.id === dev.id ? dev : d));
    const inv = dev.inventory || {}, tel = dev.telemetry || {}, av = inv.defender || {}, upd = dev.updates || {};
    const ids = [dev.id];

    $('#dhead').innerHTML = `<div class="dev-head">
      <div class="dev-title"><div class="icon">${deviceIcon(dev.chassis)}</div><div>
        <h1>${esc(dev.hostname)}</h1>
        <div class="row small" style="margin-top:4px">
          <span class="pill ${dev.online ? 'ok' : ''}"><span class="dot ${dev.online ? 'on' : ''}"></span>${dev.online ? 'Online' : 'Offline · ' + ago(dev.last_seen)}</span>
          ${dev.isolated ? '<span class="pill crit">⛔ Internet blocked</span>' : '<span class="pill">🌐 Internet allowed</span>'}
          ${dev.group ? `<span class="pill blue">${esc(dev.group)}</span>` : ''}
          ${dev.place && dev.place.lab ? `<span class="pill">🏫 ${esc((dev.place.school ? dev.place.school + ' · ' : '') + dev.place.lab)}</span>` : (isAdmin() ? '<span class="pill warn">Unplaced</span>' : '')}
          ${dev.user ? `<span class="pill">👤 ${esc(dev.user.split('\\').pop())}</span>` : ''}
          <button class="link small" id="edit">Edit group / notes</button>
          ${isAdmin() ? '<button class="link small" id="placelab">Assign lab</button>' : ''}
        </div></div></div>
      <div class="actions">
        ${dev.isolated ? '<button class="btn" data-act="unblock_internet">🌐 Restore internet</button>' : '<button class="btn ghost-danger" data-act="block_internet">⛔ Block internet</button>'}
        <button class="btn primary" data-act="install_software">⬇ Install software</button>
        <button class="btn" data-act="send_message">💬 Message</button>
        <button class="btn" data-act="lock_session">🔒 Lock</button>
        <button class="btn" data-act="run_script">›_ Script</button>
        <button class="btn" data-act="defender_scan">🛡 Scan</button>
        <button class="btn" data-act="reboot">↻ Reboot</button>
        <button class="btn" data-act="refresh_inventory" title="Collect hardware & software inventory now">⟳</button>
      </div></div>`;
    $('#edit').onclick = () => modal({
      title: 'Edit device', submit: 'Save',
      body: `<label>Group<input name="group" value="${esc(dev.group)}" placeholder="e.g. Office, Sales, Warehouse"></label><label>Notes<textarea name="notes" style="min-height:90px;font-family:inherit">${esc(dev.notes)}</textarea></label>`,
      onSubmit: async (f) => { await api(`/api/devices/${id}`, { method: 'PATCH', body: { group: f.group.value, notes: f.notes.value } }); load(); },
    });
    if ($('#placelab')) $('#placelab').onclick = async () => {
      let org; try { org = await api('/api/org'); } catch (e) { toast(e.message, true); return; }
      const { labs } = orgFlat(org);
      const canUnassign = state.me.role === 'superadmin' || (state.me.role === 'municipality_admin' && state.me.scope_type === 'global');
      if (!labs.length && !canUnassign) { toast('Create a lab in Organization first', true); return; }
      modal({
        title: 'Assign to a lab', submit: 'Save',
        body: `<label>Lab<select name="lab_id">${labs.map(([v, l]) => `<option value="${v}" ${dev.lab_id === v ? 'selected' : ''}>${esc(l)}</option>`).join('')}${canUnassign ? `<option value="" ${!dev.lab_id ? 'selected' : ''}>— Unplaced —</option>` : ''}</select></label>`,
        onSubmit: async (f) => { await api(`/api/devices/${id}`, { method: 'PATCH', body: { group: dev.group, notes: dev.notes, lab_id: f.lab_id.value } }); toast('Device placed'); load(); },
      });
    };

    const alerts = dev.alerts.filter((a) => a.level !== 'info');
    $('#dbanner').innerHTML = alerts.map((a) => `<div class="banner ${a.level}">⚠ ${esc(a.text)}</div>`).join('');

    const disks = (tel.disks || []).map((d) => {
      const used = d.size_gb ? Math.round(100 * (d.size_gb - d.free_gb) / d.size_gb) : 0;
      return `<div class="disk"><div class="row"><b>${esc(d.drive)}</b><span class="muted">${d.free_gb} GB free of ${d.size_gb} GB</span></div><div class="bar"><span style="width:${used}%;${used > 90 ? 'background:var(--crit)' : ''}"></span></div></div>`;
    }).join('') || '<p class="muted">No data yet</p>';
    const bl = inv.bitlocker;
    const fw = (inv.firewall || []).map((p) => `${esc(p.name)}: ${p.enabled ? 'on' : '<b style="color:var(--crit)">off</b>'}`).join(' · ');
    const base = inv.baseline;
    const updLine = !upd.at ? '<span class="muted">Not scanned yet</span>'
      : upd.security ? `<span class="pill warn">${upd.security} security missing</span> <span class="muted small">${upd.total} total</span>`
        : upd.total ? `${upd.total} optional` : '<span class="pill ok">Up to date</span>';
    const ctl = (title, value, btn) => `<div class="ctl"><div><b>${title}</b><span>${value}</span></div>${btn}</div>`;

    $('#dcards').innerHTML = `
      <div class="card pad"><h2>System</h2><dl class="kv">
        <dt>OS</dt><dd>${dash(inv.os_name)} ${inv.display_version ? esc(inv.display_version) : ''}</dd>
        <dt>Build</dt><dd>${dash(inv.os_build)} · ${dash(inv.arch)}</dd>
        <dt>Model</dt><dd>${dash(dev.model)}</dd><dt>Serial</dt><dd class="mono">${dash(inv.serial)}</dd>
        <dt>CPU</dt><dd>${dash(inv.cpu_name)}${inv.cores ? ` (${inv.cores} cores)` : ''}</dd>
        <dt>Memory</dt><dd>${inv.ram_gb ? inv.ram_gb + ' GB' : '—'}</dd>
        <dt>Logged-in user</dt><dd>${dash(dev.user)}</dd><dt>Domain</dt><dd>${dash(inv.domain)}</dd>
        <dt>Uptime since</dt><dd>${fmtDate(tel.boot_time)}</dd>
        ${inv.battery_pct != null ? `<dt>Battery</dt><dd>${inv.battery_pct}%</dd>` : ''}
      </dl><h2 style="margin-top:16px">Storage</h2>${disks}</div>
      <div class="card pad"><h2>Security</h2><dl class="kv">
        <dt>Antivirus</dt><dd>${av.antivirus_enabled === undefined ? '—' : av.antivirus_enabled ? '<span class="pill ok">Defender on</span>' : '<span class="pill crit">Off / 3rd-party</span>'}</dd>
        <dt>Real-time</dt><dd>${av.realtime === undefined ? '—' : av.realtime ? 'Enabled' : '<b style="color:var(--crit)">Disabled</b>'}</dd>
        <dt>Signatures</dt><dd>${av.signature_age_days != null ? `${av.signature_age_days} day(s) old` : '—'}</dd>
        <dt>Last quick scan</dt><dd>${av.quick_scan_age_days != null ? `${av.quick_scan_age_days} day(s) ago` : '—'}</dd>
        <dt>Firewall</dt><dd>${fw || '—'}</dd>
        <dt>BitLocker (${esc(tel.system_drive || 'C:')})</dt><dd>${bl ? esc(bl) : '—'}</dd>
        <dt>Windows updates</dt><dd>${updLine}</dd>
        <dt>Last installed</dt><dd>${inv.last_hotfix ? `${esc(inv.last_hotfix.id)} · ${esc(inv.last_hotfix.date || '')}` : '—'}</dd>
        <dt>Reboot pending</dt><dd>${inv.pending_reboot || upd.reboot_required ? '<span class="pill warn">Yes</span>' : 'No'}</dd>
      </dl></div>
      <div class="card pad"><h2>Network</h2><dl class="kv">
        <dt>Local IPs</dt><dd class="mono">${(tel.ips || []).map(esc).join('<br>') || '—'}</dd>
        <dt>Public IP</dt><dd class="mono">${dash(dev.public_ip)}</dd>
        <dt>Adapters</dt><dd class="small">${(inv.adapters || []).map((a) => `${esc(a.name)} <span class="mono muted">${esc(a.mac)}</span>`).join('<br>') || '—'}</dd>
        <dt>Enrolled</dt><dd>${fmtDate(dev.enrolled)}</dd>
        <dt>Inventory</dt><dd>${ago(dev.inventory_at)}</dd>
      </dl></div>
      <div class="card pad"><h2>Controls</h2>
        ${ctl('Internet', dev.isolated ? `<span class="pill crit">Blocked</span>${tel.allow_lan ? ' LAN allowed' : ''}` : 'Allowed',
          dev.isolated ? '<button class="btn small" data-act="unblock_internet">Restore</button>' : '<button class="btn small ghost-danger" data-act="block_internet">Block</button>')}
        ${ctl('Web filter', dev.web_filter ? `<span class="pill warn">${dev.web_filter} site${dev.web_filter > 1 ? 's' : ''} blocked</span>` : 'Off', '<button class="btn small" data-act="set_web_filter">Edit</button>')}
        ${ctl('USB storage', dev.usb && dev.usb !== 'allow' ? `<span class="pill warn">${esc(USB_LABEL[dev.usb])}</span>` : 'Allowed', '<button class="btn small" data-act="usb_storage">Change</button>')}
        ${ctl('Agent', `v${dash(dev.agent_version)}${dev.agent_outdated ? ' <span class="pill info">update available</span>' : ' · up to date'}`,
          dev.agent_outdated ? '<button class="btn small" data-act="update_agent">Update</button>' : '')}
      </div>
      <div class="card pad span2"><h2>Performance · last 24h</h2>${chart(dev.metrics)}</div>`;

    $('#danger').innerHTML = `<h2>Reset &amp; removal</h2>
      <div class="danger-item"><div><b>Baseline snapshot</b><p>${base ? `"${esc(base.description)}" · created ${fmtDate(base.created)}` : 'No baseline yet. Create one while the device is in a known-good state.'}</p></div>
        <button class="btn" data-act="create_baseline">${base ? 'Replace baseline' : 'Create baseline'}</button></div>
      <div class="danger-item"><div><b>Reset device</b><p>Restore the baseline snapshot, or factory-reset Windows from its recovery image.</p></div><button class="btn danger" data-act="reset_device">Reset…</button></div>
      <div class="danger-item"><div><b>Uninstall software</b><p>Remove a program using its winget ID.</p></div><button class="btn" data-act="uninstall_software">Uninstall…</button></div>
      <div class="danger-item"><div><b>Remove agent</b><p>Uninstalls KEM from the device and lifts internet block, web filter and USB restrictions.</p></div><button class="btn ghost-danger" data-act="uninstall_agent">Remove agent</button></div>
      <div class="danger-item"><div><b>Forget device</b><p>Deletes this device and its history from the server only (use after a factory reset or if the PC is gone).</p></div><button class="btn ghost-danger" id="forget">Forget</button></div>`;
    const allowedCmds = new Set(state.me.capabilities.commands || []);
    $$('[data-act]', view).forEach((b) => { if (!allowedCmds.has(b.dataset.act)) b.remove(); else b.onclick = () => ACTIONS[b.dataset.act](ids); });
    $('#forget').onclick = () => modal({
      title: 'Forget device', submit: 'Forget', danger: true,
      body: `<p class="note">Removes <b>${esc(dev.hostname)}</b> and all its history from the server. If the agent is still installed it will stop being accepted.</p>`,
      onSubmit: async () => { await api(`/api/devices/${id}`, { method: 'DELETE' }); toast('Device forgotten'); location.hash = '#/devices'; },
    });

    $$('#tab-commands details[open]').forEach((d) => ui.open.add(d.dataset.id));
    $('#tab-commands').innerHTML = commandTable(dev.commands, false, ui.open);
    bindCancel($('#tab-commands'));
    if (ui.softAt !== dev.software_at) { ui.softAt = dev.software_at; renderSoftware(); }
    const pendingUpd = (dev.commands || []).find((c) => UPDATE_TYPES.has(c.type) && ['queued', 'sent', 'running'].includes(c.status));
    const pendingText = pendingUpd ? (pendingUpd.type === 'install_updates' ? 'Installing updates' : 'Scanning') + (pendingUpd.status === 'queued' ? ' (queued)' : '…') : '';
    const sig = `${upd.at}|${pendingText}`;
    if (ui.updSig !== sig) { ui.updSig = sig; renderUpdates(pendingText); }
    $('#tc-updates').textContent = upd.at ? (upd.security ? ` ${upd.security}` : upd.total ? ` ${upd.total}` : '') : '';
    $('#tc-updates').className = 'tcount' + (upd.security ? ' warn' : '');
    $('#tc-software').textContent = dev.software && dev.software.length ? ` ${dev.software.length}` : '';
    if (!ui.loaded[ui.tab]) { ui.loaded[ui.tab] = true; firstOpen(ui.tab); }
  }

  await load();
  every(load, 5000);
}
const UPDATE_TYPES = new Set(['scan_updates', 'install_updates']);

function chart(metrics) {
  if (!metrics || metrics.length < 2) return '<p class="muted">Collecting data — the chart appears after a few minutes.</p>';
  const W = 600, H = 140, t0 = metrics[0].ts, t1 = metrics[metrics.length - 1].ts, span = Math.max(1, t1 - t0);
  const line = (key) => metrics.filter((m) => m[key] != null).map((m) => `${((m.ts - t0) / span * W).toFixed(1)},${(H - (m[key] / 100) * H).toFixed(1)}`).join(' ');
  const grid = [25, 50, 75].map((p) => `<line x1="0" x2="${W}" y1="${H - p / 100 * H}" y2="${H - p / 100 * H}" stroke="var(--line)" stroke-dasharray="3 4" vector-effect="non-scaling-stroke"/>`).join('');
  const last = metrics[metrics.length - 1];
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${grid}
    <polyline fill="none" stroke="#2563eb" stroke-width="2" points="${line('cpu')}" vector-effect="non-scaling-stroke"/>
    <polyline fill="none" stroke="#a855f7" stroke-width="2" points="${line('mem')}" vector-effect="non-scaling-stroke"/></svg>
    <div class="legend"><span><i style="background:#2563eb"></i>CPU ${last.cpu != null ? Math.round(last.cpu) + '%' : ''}</span><span><i style="background:#a855f7"></i>Memory ${last.mem != null ? Math.round(last.mem) + '%' : ''}</span>
    <span style="margin-left:auto">${new Date(t0 * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} – now</span></div>`;
}

function commandTable(cmds, withHost, open = new Set()) {
  if (!cmds.length) return '<div class="empty">No commands yet.</div>';
  return `<div class="table-wrap"><table class="grid"><thead><tr>${withHost ? '<th>Device</th>' : ''}<th>Action</th><th>Status</th><th>By</th><th class="nowrap">Created</th><th class="nowrap">Finished</th></tr></thead><tbody>${
    cmds.map((c) => `<tr class="cmd-row">
      ${withHost ? `<td><a href="#/device/${esc(c.device_id)}">${dash(c.hostname)}</a></td>` : ''}
      <td><b>${esc(CMD[c.type] || c.type)}</b><div class="muted small mono" style="max-width:520px;overflow:hidden;text-overflow:ellipsis">${esc(cmdSummary(c))}</div>
        ${c.output ? `<details data-id="${c.id}" ${open.has(String(c.id)) ? 'open' : ''}><summary>Output${c.exit_code != null ? ` (exit ${c.exit_code})` : ''}</summary><pre>${esc(c.output)}</pre></details>` : ''}</td>
      <td>${statusPill(c.status)} ${c.status === 'queued' ? `<button class="link small" data-cancel="${c.id}">cancel</button>` : ''}</td>
      <td class="small">${esc(c.created_by)}</td>
      <td class="small muted nowrap" title="${fmtDate(c.created)}">${ago(c.created)}</td>
      <td class="small muted nowrap">${c.finished ? ago(c.finished) : ''}</td></tr>`).join('')}</tbody></table></div>`;
}

function bindCancel(root) {
  $$('[data-cancel]', root).forEach((b) => (b.onclick = async () => {
    try { await api(`/api/commands/${b.dataset.cancel}/cancel`, { method: 'POST' }); toast('Cancelled'); refreshCurrent(); } catch (e) { toast(e.message, true); }
  }));
}

// ------------------------------------------------------------------ activity / audit
async function viewActivity() {
  view.innerHTML = `<div class="page-head"><div><h1>Activity</h1><p class="sub">Every command sent to every device, newest first</p></div></div><div class="card" id="acts"><div class="empty">Loading…</div></div>`;
  const open = new Set();
  const load = async () => {
    $$('#acts details[open]').forEach((d) => open.add(d.dataset.id));
    const cmds = await api('/api/commands?limit=300');
    $('#acts').innerHTML = commandTable(cmds, true, open);
    bindCancel($('#acts'));
  };
  await load().catch((e) => toast(e.message, true));
  every(load, 8000);
}

async function viewAudit() {
  view.innerHTML = `<div class="page-head"><div><h1>Audit log</h1><p class="sub">Sign-ins, enrollments and every admin action</p></div></div><div class="card" id="aud"><div class="empty">Loading…</div></div>`;
  const rows = await api('/api/audit?limit=500');
  $('#aud').innerHTML = rows.length ? `<div class="table-wrap"><table class="grid"><thead><tr><th class="nowrap">Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th><th>IP</th></tr></thead><tbody>${
    rows.map((r) => `<tr><td class="small nowrap">${fmtDate(r.ts)}</td><td>${esc(r.actor)}</td><td><span class="pill ${/fail|reject/.test(r.action) ? 'crit' : ''}">${esc(r.action)}</span></td><td>${esc(r.target)}</td><td class="small mono muted">${esc(r.details)}</td><td class="small mono">${esc(r.ip)}</td></tr>`).join('')
  }</tbody></table></div>` : '<div class="empty">Nothing yet</div>';
}

// ------------------------------------------------------------------ enrollment
function installCommand(token) {
  const origin = location.origin;
  return `[Net.ServicePointManager]::SecurityProtocol='Tls12'; iwr -UseBasicParsing '${origin}/agent/install.ps1' -OutFile "$env:TEMP\\kem-install.ps1"; powershell -ExecutionPolicy Bypass -File "$env:TEMP\\kem-install.ps1" -Server '${origin}' -Token '${token}'`;
}

async function viewEnroll() {
  let org = { municipalities: [] };
  try { org = await api('/api/org'); } catch { /* non-fatal */ }
  const { labs } = orgFlat(org);
  const global = state.me.role === 'superadmin' || (state.me.role === 'municipality_admin' && state.me.scope_type === 'global');
  const labOptions = (labs.length ? labs.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join('') : '')
    + (global ? '<option value="">Any lab (place the device later)</option>' : '');
  view.innerHTML = `<div class="page-head"><div><h1>Add devices</h1><p class="sub">Create a registration token, then run the install command on each machine</p></div></div>
    <div class="card pad" style="margin-bottom:16px"><h2>New registration token</h2>
      <form id="tokform" class="form-grid">
        <label>Type<select name="kind"><option value="device">Student / device agent</option><option value="gateway">Teacher gateway</option></select></label>
        <label>Lab<select name="lab_id">${labOptions || '<option value="">(create a lab in Organization first)</option>'}</select></label>
        <label>Label<input name="label" placeholder="e.g. Lab 1 rollout"></label>
        <label>Valid for<select name="hours"><option value="1">1 hour</option><option value="24">1 day</option><option value="72" selected>3 days</option><option value="168">1 week</option><option value="720">30 days</option><option value="0">No expiry</option></select></label>
        <label>Max uses<input name="max_uses" type="number" min="0" value="0" title="0 = unlimited"></label>
        <button class="btn primary">Generate token</button>
      </form>
      <p class="note" style="margin-top:10px">A <b>device</b> token enrolls a student station into its lab. A <b>gateway</b> token enrolls a Teacher Gateway for that lab — install it with <code>gateway/install-gateway.ps1</code>.</p></div>
    <div class="card pad" style="margin-bottom:16px"><h2>How to install a student agent</h2><ol class="steps">
      <li>On the Windows 10/11 computer, open <b>PowerShell as Administrator</b>.</li>
      <li>Paste the install command of an active <b>device</b> token below and press Enter. In a gateway lab, swap the server URL for the gateway's (<code>http://&lt;gateway-host&gt;:8171</code>).</li>
      <li>The device appears under <a href="#/devices">Devices</a> within ~15 seconds, placed in its lab.</li></ol>
      <p class="note" style="margin-top:12px">The agent runs as a SYSTEM scheduled task, lives in <code>C:\\Program Files\\KEM</code> and keeps its credentials in <code>C:\\ProgramData\\KEM</code>. Use HTTPS in production — the device secret travels with every check-in.</p></div>
    <div class="card" id="toks"></div>`;
  $('#tokform').onsubmit = async (e) => {
    e.preventDefault();
    const f = e.target;
    try {
      await api('/api/tokens', { method: 'POST', body: { kind: f.kind.value, lab_id: f.lab_id.value, label: f.label.value, hours: +f.hours.value, max_uses: +f.max_uses.value } });
      toast('Token created'); loadTokens();
    } catch (err) { toast(err.message, true); }
  };
  loadTokens();
}

function gatewayCommand(token) {
  return `.\\install-gateway.ps1 -Server '${location.origin}' -Token '${token}'`;
}

async function loadTokens() {
  const toks = await api('/api/tokens');
  const cmdFor = (t) => (t.kind === 'gateway' ? gatewayCommand(t.token) : installCommand(t.token));
  $('#toks').innerHTML = toks.length ? `<div class="table-wrap"><table class="grid"><thead><tr><th>Token</th><th>Type / lab</th><th>Used</th><th>Expires</th><th>Install command</th><th></th></tr></thead><tbody>${
    toks.map((t) => `<tr>
      <td><span class="token">${esc(t.token)}</span><br>${t.active ? '<span class="pill ok">active</span>' : `<span class="pill">${t.revoked ? 'revoked' : 'expired'}</span>`}</td>
      <td><span class="pill ${t.kind === 'gateway' ? 'blue' : ''}">${t.kind === 'gateway' ? 'gateway' : 'device'}</span>${t.lab_name ? `<br><span class="small muted">${esc(t.lab_name)}</span>` : (t.label ? '' : '<br><span class="small muted">any lab</span>')}${t.label ? `<br>${esc(t.label)}` : ''}</td>
      <td>${t.uses}${t.max_uses ? ' / ' + t.max_uses : ''}</td>
      <td class="small nowrap">${t.expires ? fmtDate(t.expires) : 'never'}</td>
      <td style="max-width:420px">${t.active ? `<div class="cmdbox"><code>${esc(cmdFor(t))}</code><button class="btn small" data-copy="${t.id}">Copy</button></div>` : ''}</td>
      <td>${!t.revoked ? `<button class="link small" data-revoke="${t.id}" style="color:var(--crit)">Revoke</button>` : ''}</td></tr>`).join('')
  }</tbody></table></div>` : '<div class="empty">No tokens yet.</div>';
  const byId = Object.fromEntries(toks.map((t) => [t.id, t]));
  $$('[data-copy]').forEach((b) => (b.onclick = async () => {
    const t = byId[b.dataset.copy];
    try { await navigator.clipboard.writeText(t.kind === 'gateway' ? gatewayCommand(t.token) : installCommand(t.token)); toast('Install command copied'); } catch { toast('Copy failed — select the text manually', true); }
  }));
  $$('[data-revoke]').forEach((b) => (b.onclick = async () => { await api(`/api/tokens/${b.dataset.revoke}`, { method: 'DELETE' }); toast('Token revoked'); loadTokens(); }));
}

// ------------------------------------------------------------------ settings
async function viewSettings() {
  const pwCard = `<div class="card pad"><h2>Change your password</h2>
      <form id="pw" class="stack">
        <label>Current password<input type="password" name="current" required autocomplete="current-password"></label>
        <label>New password (10+ characters)<input type="password" name="new" required minlength="10" autocomplete="new-password"></label>
        <button class="btn primary" style="align-self:flex-start">Update password</button></form></div>`;
  const wirePw = () => { $('#pw').onsubmit = async (e) => {
    e.preventDefault();
    try { await api('/api/password', { method: 'POST', body: { current: e.target.current.value, new: e.target.new.value } }); e.target.reset(); toast('Password updated'); } catch (err) { toast(err.message, true); }
  }; };
  if (!isAdmin()) {
    view.innerHTML = `<div class="page-head"><div><h1>Settings</h1><p class="sub">${esc(roleLabel(state.me.role))}${state.me.scope_label ? ' · ' + esc(state.me.scope_label) : ''}</p></div></div>
      <div class="settings-grid"><div class="stack">${pwCard}</div></div>`;
    wirePw();
    return;
  }
  view.innerHTML = `<div class="page-head"><div><h1>Settings</h1><p class="sub">KEM v${esc(state.me?.version)} · agents check in every ${state.me?.interval}s</p></div></div>
    <div class="settings-grid">
      <form class="card pad" id="notif"><h2>Notifications</h2><div class="empty">Loading…</div></form>
      <div class="stack">
        <form class="card pad" id="auto"><h2>Automation</h2></form>
        <div class="card pad"><h2>Change admin password</h2>
          <form id="pw" class="stack">
            <label>Current password<input type="password" name="current" required autocomplete="current-password"></label>
            <label>New password (10+ characters)<input type="password" name="new" required minlength="10" autocomplete="new-password"></label>
            <button class="btn primary" style="align-self:flex-start">Update password</button></form></div>
      </div>
    </div>
    <div class="card" style="margin-top:16px"><div class="pad-h"><h2>Recent notifications</h2></div><div id="notiflog"></div></div>`;
  $('#pw').onsubmit = async (e) => {
    e.preventDefault();
    try { await api('/api/password', { method: 'POST', body: { current: e.target.current.value, new: e.target.new.value } }); e.target.reset(); toast('Password updated'); } catch (err) { toast(err.message, true); }
  };
  let s;
  try { s = await api('/api/settings'); } catch (e) { toast(e.message, true); return; }

  const render = () => {
    $('#notif').innerHTML = `<h2>Notifications</h2>
      <p class="note">Get told when something needs attention. Use a chat webhook, e-mail, or both.</p>
      <label>Webhook URL<input name="notify_webhook" value="${esc(s.notify_webhook)}" placeholder="https://hooks.slack.com/services/…" spellcheck="false"></label>
      <details class="help"><summary>Which webhook URLs work?</summary><ul>
        <li><b>Slack</b>, <b>Mattermost</b>, <b>Google Chat</b> — incoming-webhook URL</li>
        <li><b>Microsoft Teams</b> — a <i>Workflows</i> "post to a channel when a webhook request is received" URL</li>
        <li><b>Discord</b> — channel webhook URL</li>
        <li><b>Telegram</b> — <span class="mono">https://api.telegram.org/bot&lt;TOKEN&gt;/sendMessage?chat_id=&lt;CHAT_ID&gt;</span></li>
        <li>Anything else receives JSON <span class="mono">{"text": "…"}</span></li></ul></details>
      <label>E-mail to (comma separated)<input name="notify_email" value="${esc(s.notify_email)}" placeholder="it@company.com"></label>
      <div class="form-2">
        <label>SMTP server<input name="smtp_host" value="${esc(s.smtp_host)}" placeholder="smtp.gmail.com"></label>
        <label>Port<input name="smtp_port" type="number" value="${esc(s.smtp_port)}" min="1" max="65535"></label>
        <label>Security<select name="smtp_security">${[['starttls', 'STARTTLS (587)'], ['ssl', 'SSL/TLS (465)'], ['none', 'None']].map(([v, l]) => `<option value="${v}" ${s.smtp_security === v ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
        <label>From address<input name="smtp_from" value="${esc(s.smtp_from)}" placeholder="kem@company.com"></label>
        <label>SMTP user<input name="smtp_user" value="${esc(s.smtp_user)}" autocomplete="off"></label>
        <label>SMTP password<input name="smtp_pass" type="password" autocomplete="new-password" placeholder="${s.smtp_pass_set ? '•••••• (saved — leave blank to keep)' : ''}"></label>
      </div>
      <div><div class="muted small" style="margin-bottom:6px;font-weight:500">Notify me when</div>
        ${Object.entries(s.event_names).map(([k, l]) => `<label class="check"><input type="checkbox" name="ev" value="${k}" ${s.notify_events.includes(k) ? 'checked' : ''}> ${esc(l)}</label>`).join('')}</div>
      <label style="max-width:260px">Offline threshold (hours, 0 = off)<input name="notify_offline_hours" type="number" min="0" max="720" value="${esc(s.notify_offline_hours)}"></label>
      <div class="row"><button class="btn primary">Save</button><button type="button" class="btn" id="testn">Send test</button></div>`;
    $('#auto').innerHTML = `<h2>Automation</h2>
      <label class="check"><input type="checkbox" name="auto_update_scan" ${s.auto_update_scan === '1' ? 'checked' : ''}><div>Scan every device for missing Windows updates once a day</div></label>
      <label class="check"><input type="checkbox" name="auto_update_agent" ${s.auto_update_agent === '1' ? 'checked' : ''}><div>Keep agents up to date automatically<br><span class="muted small">Devices switch to agent v${esc(s.agent_version)} (the version on this server) on their next check-in.</span></div></label>
      <button class="btn primary" style="align-self:flex-start">Save</button>`;
    $('#testn').onclick = async () => {
      const b = $('#testn'); b.disabled = true;
      try { await save(false); await api('/api/settings/test-notification', { method: 'POST' }); toast('Test notification sent'); } catch (e) { toast(e.message, true); } finally { b.disabled = false; }
    };
  };
  const collect = () => {
    const n = $('#notif'), a = $('#auto');
    return {
      notify_webhook: n.notify_webhook.value.trim(), notify_email: n.notify_email.value.trim(), smtp_host: n.smtp_host.value.trim(),
      smtp_port: +n.smtp_port.value || 587, smtp_security: n.smtp_security.value, smtp_from: n.smtp_from.value.trim(), smtp_user: n.smtp_user.value.trim(),
      smtp_pass: n.smtp_pass.value, notify_events: $$('[name=ev]:checked', n).map((x) => x.value), notify_offline_hours: +n.notify_offline_hours.value || 0,
      auto_update_scan: a.auto_update_scan.checked, auto_update_agent: a.auto_update_agent.checked,
    };
  };
  const save = async (announce = true) => { s = await api('/api/settings', { method: 'PUT', body: collect() }); render(); if (announce) toast('Settings saved'); };
  render();
  $('#notif').onsubmit = (e) => { e.preventDefault(); save().catch((err) => toast(err.message, true)); };
  $('#auto').onsubmit = (e) => { e.preventDefault(); save().catch((err) => toast(err.message, true)); };

  const loadLog = async () => {
    const rows = await api('/api/notifications');
    $('#notiflog').innerHTML = rows.length ? `<div class="table-wrap"><table class="grid"><thead><tr><th class="nowrap">Time</th><th>Device</th><th>Event</th><th>Message</th><th>Delivery</th></tr></thead><tbody>${
      rows.map((r) => `<tr><td class="small nowrap">${fmtDate(r.ts)}</td><td>${r.device_id ? `<a href="#/device/${esc(r.device_id)}">${esc(r.hostname)}</a>` : esc(r.hostname)}</td>
        <td><span class="pill">${esc(r.event.replace('_', ' '))}</span></td><td class="small">${esc(r.text)}</td>
        <td>${statusPill(r.status)}${r.error ? `<div class="small muted">${esc(r.error)}</div>` : ''}</td></tr>`).join('')}</tbody></table></div>`
      : '<div class="empty">Nothing sent yet.</div>';
  };
  loadLog().catch(() => {});
  every(() => loadLog().catch(() => {}), 15000);
}

// ------------------------------------------------------------------ organization
function orgFlat(org) {
  const munis = [], schools = [], labs = [];
  (org.municipalities || []).forEach((m) => {
    munis.push([m.id, m.name]);
    (m.schools || []).forEach((s) => {
      schools.push([s.id, `${m.name} · ${s.name}`]);
      (s.labs || []).forEach((l) => labs.push([l.id, `${s.name} · ${l.name}`]));
    });
  });
  return { munis, schools, labs };
}

async function viewOrg() {
  view.innerHTML = `<div class="page-head"><div><h1>Organization</h1><p class="sub">Municipalities, schools and computer labs</p></div></div>
    <div id="orgwrap" class="card"><div class="empty">Loading…</div></div>`;
  let org;
  try { org = await api('/api/org'); } catch (e) { toast(e.message, true); return; }
  const reload = () => viewOrg();
  const canEdit = org.can_edit;
  const labRow = (l) => `<div class="orgl orgrow"><span>▸ ${esc(l.name)} <span class="muted small">${l.devices} device${l.devices === 1 ? '' : 's'}${l.gateways ? ` · ${l.gateways} gateway` : ''}</span></span>${canEdit ? `<button class="link small danger-link" data-dellab="${l.id}">delete</button>` : ''}</div>`;
  const schoolRow = (s) => `<div class="orgs"><div class="orgrow"><span><b>${esc(s.name)}</b></span>${canEdit ? `<span class="orgacts"><button class="link small" data-addlab="${s.id}">+ lab</button> <button class="link small danger-link" data-dels="${s.id}">delete</button></span>` : ''}</div>${(s.labs || []).map(labRow).join('') || '<div class="orgl muted small">no labs yet</div>'}</div>`;
  const muniRow = (m) => `<div class="orgm"><div class="orgrow"><span><b style="font-size:16px">${esc(m.name)}</b></span>${canEdit ? `<span class="orgacts"><button class="link small" data-addschool="${m.id}">+ school</button> ${state.me.role === 'superadmin' ? `<button class="link small danger-link" data-delm="${m.id}">delete</button>` : ''}</span>` : ''}</div>${(m.schools || []).map(schoolRow).join('') || '<div class="orgs muted small">no schools yet</div>'}</div>`;
  const tree = (org.municipalities || []).map(muniRow).join('') || '<div class="empty">No municipalities yet.</div>';
  $('#orgwrap').innerHTML = `<div class="pad">${state.me.role === 'superadmin' ? '<button class="btn small" id="addmuni">＋ Add municipality</button>' : ''}${org.unassigned_devices ? `<span class="pill" style="margin-left:10px">${org.unassigned_devices} unplaced device${org.unassigned_devices === 1 ? '' : 's'} — assign on each device page</span>` : ''}</div><div class="orgtree">${tree}</div>`;
  const ask = (label, url, extra) => async () => { const name = prompt(label); if (!name) return; try { await api(url, { method: 'POST', body: { name, ...extra } }); toast('Added'); reload(); } catch (e) { toast(e.message, true); } };
  const del = (url, msg) => async () => { if (!confirm(msg)) return; try { await api(url, { method: 'DELETE' }); toast('Deleted'); reload(); } catch (e) { toast(e.message, true); } };
  if ($('#addmuni')) $('#addmuni').onclick = ask('New municipality name:', '/api/municipalities', {});
  $$('[data-addschool]').forEach((b) => (b.onclick = ask('New school name:', '/api/schools', { municipality_id: b.dataset.addschool })));
  $$('[data-addlab]').forEach((b) => (b.onclick = ask('New lab name:', '/api/labs', { school_id: b.dataset.addlab })));
  $$('[data-delm]').forEach((b) => (b.onclick = del(`/api/municipalities/${b.dataset.delm}`, 'Delete this municipality? It must be empty.')));
  $$('[data-dels]').forEach((b) => (b.onclick = del(`/api/schools/${b.dataset.dels}`, 'Delete this school? It must be empty.')));
  $$('[data-dellab]').forEach((b) => (b.onclick = del(`/api/labs/${b.dataset.dellab}`, 'Delete this lab? Move its devices out first.')));
}

// ------------------------------------------------------------------ users
async function viewUsers() {
  view.innerHTML = `<div class="page-head"><div><h1>Users</h1><p class="sub">Administrators, school managers and teachers</p></div>
      <button class="btn primary" id="adduser">＋ Add user</button></div>
    <div class="card pad hidden" id="userform"></div>
    <div class="card" id="userlist"><div class="empty">Loading…</div></div>`;
  $('#adduser').onclick = () => userForm().catch((e) => toast(e.message, true));
  await loadUsers();
}

async function userForm() {
  const box = $('#userform');
  if (!box.classList.contains('hidden')) { box.classList.add('hidden'); return; }
  const org = await api('/api/org');
  const { munis, schools, labs } = orgFlat(org);
  const roles = state.me.role === 'superadmin'
    ? [['municipality_admin', 'Municipality admin'], ['school_manager', 'School manager'], ['teacher', 'Teacher']]
    : [['school_manager', 'School manager'], ['teacher', 'Teacher']];
  const opts = (arr) => arr.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join('');
  box.classList.remove('hidden');
  box.innerHTML = `<h2>New user</h2><form id="uform" class="form-grid">
    <label>Username<input name="username" required autocomplete="off"></label>
    <label>Display name<input name="display_name" placeholder="optional"></label>
    <label>Password (10+ characters)<input name="password" type="password" required minlength="10" autocomplete="new-password"></label>
    <label>Role<select name="role">${opts(roles)}</select></label>
    <label id="scopewrap">Scope<select name="scope_id"></select></label>
    <div class="row" style="grid-column:1/-1"><button class="btn primary">Create user</button><button type="button" class="btn" id="ucancel">Cancel</button></div></form>`;
  const scopeSel = box.querySelector('[name=scope_id]');
  const syncScope = () => {
    const role = box.querySelector('[name=role]').value;
    const src = role === 'municipality_admin' ? munis : role === 'school_manager' ? schools : labs;
    scopeSel.innerHTML = src.length ? src.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join('') : '<option value="">(create one in Organization first)</option>';
  };
  box.querySelector('[name=role]').onchange = syncScope; syncScope();
  $('#ucancel').onclick = () => box.classList.add('hidden');
  $('#uform').onsubmit = async (e) => {
    e.preventDefault();
    const f = e.target;
    try {
      await api('/api/users', { method: 'POST', body: { username: f.username.value, display_name: f.display_name.value, password: f.password.value, role: f.role.value, scope_id: f.scope_id.value } });
      toast('User created'); box.classList.add('hidden'); loadUsers();
    } catch (err) { toast(err.message, true); }
  };
}

async function loadUsers() {
  const users = await api('/api/users');
  $('#userlist').innerHTML = users.length ? `<div class="table-wrap"><table class="grid"><thead><tr><th>User</th><th>Role</th><th>Scope</th><th class="nowrap">Last login</th><th>Status</th><th></th></tr></thead><tbody>${
    users.map((u) => `<tr>
      <td><b>${esc(u.username)}</b>${u.display_name ? `<br><span class="small muted">${esc(u.display_name)}</span>` : ''}</td>
      <td><span class="pill">${esc(roleLabel(u.role))}</span></td>
      <td>${esc(u.scope_label || '—')}</td>
      <td class="small nowrap">${u.last_login ? ago(u.last_login) : 'never'}</td>
      <td>${u.disabled ? '<span class="pill">disabled</span>' : '<span class="pill ok">active</span>'}</td>
      <td class="nowrap">${u.role === 'superadmin' ? '' : `<button class="link small" data-pw="${u.id}">password</button>
        <button class="link small" data-toggle="${u.id}" data-dis="${u.disabled ? 0 : 1}">${u.disabled ? 'enable' : 'disable'}</button>
        <button class="link small danger-link" data-deluser="${u.id}">delete</button>`}</td></tr>`).join('')
  }</tbody></table></div>` : '<div class="empty">No users.</div>';
  $$('[data-deluser]').forEach((b) => (b.onclick = async () => { if (!confirm('Delete this user?')) return; try { await api(`/api/users/${b.dataset.deluser}`, { method: 'DELETE' }); toast('User deleted'); loadUsers(); } catch (e) { toast(e.message, true); } }));
  $$('[data-toggle]').forEach((b) => (b.onclick = async () => { try { await api(`/api/users/${b.dataset.toggle}`, { method: 'PATCH', body: { disabled: !!+b.dataset.dis } }); loadUsers(); } catch (e) { toast(e.message, true); } }));
  $$('[data-pw]').forEach((b) => (b.onclick = async () => { const p = prompt('New password (10+ characters):'); if (!p) return; try { await api(`/api/users/${b.dataset.pw}`, { method: 'PATCH', body: { password: p } }); toast('Password reset'); } catch (e) { toast(e.message, true); } }));
}

// ------------------------------------------------------------------ gateways
async function viewGateways() {
  view.innerHTML = `<div class="page-head"><div><h1>Teacher Gateways</h1><p class="sub">Lab relays between student stations and this server</p></div>
      <a class="btn" href="#/enroll">Create gateway token</a></div>
    <div class="card pad" style="margin-bottom:16px"><h2>How a gateway works</h2>
      <p class="note">Students connect to the gateway on their lab PC; the gateway forwards to this server and never lets students reach it directly.</p>
      <ol class="steps"><li>Create a <b>gateway token</b> for a lab under <a href="#/enroll">Add devices</a>.</li>
        <li>On the lab's teacher PC (Python 3.8+), run elevated from the <code>gateway/</code> folder:
          <div class="cmdbox"><code>.\\install-gateway.ps1 -Server ${esc(location.origin)} -Token &lt;gateway-token&gt;</code></div></li>
        <li>Enroll that lab's student agents against <code>http://&lt;gateway-host&gt;:8171</code> with a <b>device</b> token for the same lab.</li></ol></div>
    <div class="card" id="gwlist"><div class="empty">Loading…</div></div>`;
  const load = async () => {
    const gws = await api('/api/gateways');
    $('#gwlist').innerHTML = gws.length ? `<div class="table-wrap"><table class="grid"><thead><tr><th>Gateway</th><th>Lab</th><th>Devices</th><th>Version</th><th class="nowrap">Last seen</th><th>Status</th><th></th></tr></thead><tbody>${
      gws.map((g) => `<tr><td><b>${esc(g.hostname)}</b><br><span class="small mono muted">${esc(g.public_ip || '')}</span></td>
        <td>${esc(g.place.lab || '—')}${g.place.school ? `<br><span class="small muted">${esc(g.place.school)}</span>` : ''}</td>
        <td>${g.devices}</td><td class="small">${dash(g.agent_version)}</td>
        <td class="small nowrap">${g.last_seen ? ago(g.last_seen) : 'never'}</td>
        <td>${g.online ? '<span class="pill ok">online</span>' : '<span class="pill">offline</span>'}</td>
        <td><button class="link small danger-link" data-delgw="${g.id}">remove</button></td></tr>`).join('')
    }</tbody></table></div>` : '<div class="empty">No gateways enrolled yet.</div>';
    $$('[data-delgw]').forEach((b) => (b.onclick = async () => { if (!confirm('Remove this gateway? Its devices stay enrolled but lose the relay link.')) return; try { await api(`/api/gateways/${b.dataset.delgw}`, { method: 'DELETE' }); toast('Gateway removed'); load(); } catch (e) { toast(e.message, true); } }));
  };
  await load().catch((e) => toast(e.message, true));
  every(load, 10000);
}

// ------------------------------------------------------------------ licensing
const FINDING_META = {
  confirmed_issue: ['crit', 'Confirmed issue'], potential_gap: ['warn', 'Potential gap'],
  verification_required: ['blue', 'Verification required'], compliant: ['ok', 'Compliant'],
  not_applicable: ['', 'Not applicable'],
};
async function viewLicensing() {
  view.innerHTML = `<div class="page-head"><div><h1>Software licensing</h1><p class="sub">Installed commercial software vs recorded entitlements</p></div>
      ${cap('manage_licensing') ? '<button class="btn primary" id="addent">＋ Add entitlement</button>' : ''}</div>
    <section class="tiles" id="lictiles"></section>
    <div class="card" id="findings"><div class="empty">Loading…</div></div>
    <div class="card pad hidden" id="entform"></div>
    <h2 style="margin:20px 0 10px">Entitlements</h2>
    <div class="card" id="entlist"><div class="empty">Loading…</div></div>`;
  if ($('#addent')) $('#addent').onclick = () => entForm().catch((e) => toast(e.message, true));
  const load = async () => {
    const [res, ents] = await Promise.all([api('/api/license/findings'), api('/api/entitlements')]);
    const sum = res.summary || {};
    const tiles = [['confirmed_issue', 'Confirmed issues'], ['potential_gap', 'Potential gaps'], ['verification_required', 'Verify'], ['compliant', 'Compliant']];
    $('#lictiles').innerHTML = tiles.map(([k, l]) => `<div class="tile"><div class="l">${FINDING_META[k][1]}</div><div class="n">${sum[k] || 0}</div></div>`).join('');
    $('#findings').innerHTML = res.findings.length ? `<div class="table-wrap"><table class="grid"><thead><tr><th>Product</th><th>Installs</th><th>Licence</th><th>Status</th><th>Detail</th></tr></thead><tbody>${
      res.findings.map((f) => { const [cls, lbl] = FINDING_META[f.category] || ['', f.category]; return `<tr>
        <td><b>${esc(f.label)}</b><br><span class="small muted">${esc(f.type)}</span></td>
        <td>${f.installs}</td>
        <td>${f.site ? 'site' : (f.seats ? f.seats + ' seats' : '—')}</td>
        <td><span class="pill ${cls}">${esc(lbl)}</span></td>
        <td class="small">${esc(f.message)}${f.samples && f.samples.length ? `<br><span class="muted">${esc(f.samples.slice(0, 4).map((s) => s.host).join(', '))}${f.installs > 4 ? ' …' : ''}</span>` : ''}</td></tr>`; }).join('')
    }</tbody></table></div>` : '<div class="empty">No commercial software detected in scope yet.</div>';
    $('#entlist').innerHTML = ents.length ? `<div class="table-wrap"><table class="grid"><thead><tr><th>Name</th><th>Product</th><th>Type</th><th>Seats</th><th>Scope</th><th>Expires</th><th></th></tr></thead><tbody>${
      ents.map((e) => `<tr><td><b>${esc(e.name)}</b>${e.notes ? `<br><span class="small muted">${esc(e.notes)}</span>` : ''}</td>
        <td>${esc(e.product_label || e.product || '—')}</td><td class="small">${esc(e.license_type)}</td>
        <td>${e.seats || '<span class="muted">site</span>'}</td><td class="small">${esc(e.scope_name)}</td>
        <td class="small nowrap ${e.expires && e.expires * 1000 < Date.now() ? 'crit-text' : ''}">${e.expires ? fmtDate(e.expires).split(',')[0] : '—'}</td>
        <td>${cap('manage_licensing') ? `<button class="link small" data-editent="${e.id}">edit</button> <button class="link small danger-link" data-delent="${e.id}">delete</button>` : ''}</td></tr>`).join('')
    }</tbody></table></div>` : '<div class="empty">No entitlements recorded. Add what the school owns to turn "potential gaps" into compliance.</div>';
    $$('[data-delent]').forEach((b) => (b.onclick = async () => { if (!confirm('Delete this entitlement?')) return; try { await api(`/api/entitlements/${b.dataset.delent}`, { method: 'DELETE' }); toast('Deleted'); load(); } catch (e) { toast(e.message, true); } }));
    $$('[data-editent]').forEach((b) => (b.onclick = async () => {
      const e = ents.find((x) => x.id === b.dataset.editent);
      const seats = prompt(`Seats for "${e.name}" (0 = site/unlimited):`, e.seats); if (seats === null) return;
      const expires = prompt('Expiry date YYYY-MM-DD (blank = none):', e.expires ? fmtDate(e.expires).split(',')[0].split('/').reverse().join('-') : '');
      if (expires === null) return;
      try { await api(`/api/entitlements/${e.id}`, { method: 'PATCH', body: { seats: +seats || 0, expires } }); toast('Updated'); load(); } catch (err) { toast(err.message, true); }
    }));
  };
  await load().catch((e) => toast(e.message, true));
}

async function entForm() {
  const box = $('#entform');
  if (!box.classList.contains('hidden')) { box.classList.add('hidden'); return; }
  const [cat, org] = await Promise.all([api('/api/license/catalog'), api('/api/org')]);
  const { munis, schools, labs } = orgFlat(org);
  const global = state.me.role === 'superadmin' || (state.me.role === 'municipality_admin' && state.me.scope_type === 'global');
  box.classList.remove('hidden');
  box.innerHTML = `<h2>New entitlement</h2><form id="eform" class="form-grid">
    <label>Name<input name="name" required placeholder="e.g. Office 365 A3 (district)"></label>
    <label>Product<select name="product"><option value="">— Other / none —</option>${cat.products.map((p) => `<option value="${p.key}">${esc(p.label)}</option>`).join('')}</select></label>
    <label>Licence type<select name="license_type">${cat.license_types.map((t) => `<option value="${t}">${esc(t)}</option>`).join('')}</select></label>
    <label>Seats (0 = site / unlimited)<input name="seats" type="number" min="0" value="0"></label>
    <label>Covers<select name="scope_type"><option value="lab">A lab</option><option value="school">A school</option><option value="municipality">A municipality</option>${global ? '<option value="global">All (global)</option>' : ''}</select></label>
    <label id="escope">Which<select name="scope_id"></select></label>
    <label>Expires (optional)<input name="expires" type="date"></label>
    <label>Notes<input name="notes" placeholder="PO number, contract…"></label>
    <div class="row" style="grid-column:1/-1"><button class="btn primary">Create entitlement</button><button type="button" class="btn" id="ecancel">Cancel</button></div></form>`;
  const sel = box.querySelector('[name=scope_id]');
  const sync = () => {
    const st = box.querySelector('[name=scope_type]').value;
    box.querySelector('#escope').style.display = st === 'global' ? 'none' : '';
    const src = st === 'municipality' ? munis : st === 'school' ? schools : labs;
    sel.innerHTML = src.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join('') || '<option value="">(none yet)</option>';
  };
  box.querySelector('[name=scope_type]').onchange = sync; sync();
  $('#ecancel').onclick = () => box.classList.add('hidden');
  $('#eform').onsubmit = async (e) => {
    e.preventDefault(); const f = e.target;
    try {
      await api('/api/entitlements', { method: 'POST', body: { name: f.name.value, product: f.product.value, license_type: f.license_type.value, seats: +f.seats.value || 0, scope_type: f.scope_type.value, scope_id: f.scope_id.value, expires: f.expires.value, notes: f.notes.value } });
      toast('Entitlement added'); box.classList.add('hidden'); viewLicensing();
    } catch (err) { toast(err.message, true); }
  };
}

// ------------------------------------------------------------------ auth bootstrap
function showLogin() {
  clearInterval(state.timer);
  $('#app').classList.add('hidden');
  $('#login').classList.remove('hidden');
  $('#login-form').password.focus();
}

$('#login-form').onsubmit = async (e) => {
  e.preventDefault();
  const f = e.target;
  $('#login-err').textContent = '';
  try {
    await api('/api/login', { method: 'POST', body: { username: f.username.value, password: f.password.value } });
    f.password.value = '';
    boot();
  } catch (err) { $('#login-err').textContent = err.message; }
};

$('#logout').onclick = async () => { await api('/api/logout', { method: 'POST' }).catch(() => {}); showLogin(); };

// ------------------------------------------------------------------ incidents
const INC_SEV = { critical: ['crit', 'Critical'], warning: ['warn', 'Warning'], info: ['info', 'Info'] };
const INC_STATUS = { open: ['crit', 'Open'], acknowledged: ['blue', 'Acknowledged'], resolved: ['ok', 'Resolved'] };
const INC_SEG = { unresolved: 'Unresolved', open: 'Open', acknowledged: 'Acknowledged', resolved: 'Resolved', '': 'All' };

async function viewIncidents() {
  const manage = cap('manage_incidents');
  if (state.incFilter == null) state.incFilter = 'unresolved';
  view.innerHTML = `
    <div class="page-head"><div><h1>Incidents</h1><p class="sub">Health alerts and issues to track${state.me.scope_label && state.me.role !== 'superadmin' ? ' · ' + esc(state.me.scope_label) : ''}</p></div>
      <div class="row">${manage ? '<button class="btn" id="incscan">⟳ Scan now</button> <button class="btn primary" id="incnew">＋ New incident</button>' : ''}</div></div>
    <div class="toolbar"><div class="seg" id="incseg" style="max-width:520px">
      ${Object.entries(INC_SEG).map(([s, l]) => `<button data-s="${s}" class="${state.incFilter === s ? 'on' : ''}">${l}</button>`).join('')}
    </div></div>
    <div class="card table-wrap"><table class="grid">
      <thead><tr><th>Severity</th><th>Issue</th><th>Device / lab</th><th>Status</th><th>Assignee</th><th class="nowrap">Opened</th>${manage ? '<th></th>' : ''}</tr></thead>
      <tbody id="incrows"><tr><td colspan="7" class="empty">Loading…</td></tr></tbody></table></div>`;

  const load = async () => {
    let rows;
    try { rows = await api(`/api/incidents?status=${encodeURIComponent(state.incFilter)}`); } catch (e) { toast(e.message, true); return; }
    const body = $('#incrows');
    if (!rows.length) { body.innerHTML = `<tr><td colspan="7" class="empty">Nothing here — no ${state.incFilter ? esc(INC_SEG[state.incFilter].toLowerCase()) : ''} incidents.</td></tr>`; refreshIncidentBadge(); return; }
    body.innerHTML = rows.map(renderIncRow).join('');
    if (manage) {
      body.querySelectorAll('[data-act]').forEach((b) => (b.onclick = () => incAction(b.dataset.id, b.dataset.act, load)));
      body.querySelectorAll('[data-edit]').forEach((b) => (b.onclick = () => incEdit(rows.find((r) => r.id === b.dataset.edit), load)));
    }
    refreshIncidentBadge();
  };
  $$('#incseg button').forEach((b) => (b.onclick = () => { state.incFilter = b.dataset.s; $$('#incseg button').forEach((x) => x.classList.toggle('on', x === b)); load(); }));
  if (manage) {
    $('#incscan').onclick = async () => { try { const s = await api('/api/incidents/scan', { method: 'POST' }); toast(`Scanned · ${s.total} unresolved`); load(); } catch (e) { toast(e.message, true); } };
    $('#incnew').onclick = () => incForm(load);
  }
  every(load, 15000);
  await load();
}

function renderIncRow(i) {
  const manage = cap('manage_incidents');
  const [sc, sl] = INC_SEV[i.severity] || ['', i.severity];
  const [stc, stl] = INC_STATUS[i.status] || ['', i.status];
  const acts = [];
  if (manage) {
    if (i.status === 'open') acts.push(`<button class="btn small" data-act="acknowledge" data-id="${i.id}">Ack</button>`);
    if (i.status !== 'resolved') acts.push(`<button class="btn small" data-act="resolve" data-id="${i.id}">Resolve</button>`);
    if (i.status === 'resolved') acts.push(`<button class="btn small" data-act="reopen" data-id="${i.id}">Reopen</button>`);
    acts.push(`<button class="link small" data-edit="${i.id}">Assign / note</button>`);
  }
  return `<tr>
    <td><span class="pill ${sc}">${esc(sl)}</span></td>
    <td><b>${esc(i.title)}</b>${i.detail ? `<br><small class="muted">${esc(i.detail)}</small>` : ''}${i.note ? `<br><small class="muted">📝 ${esc(i.note)}</small>` : ''}</td>
    <td class="small">${i.device_hostname ? esc(i.device_hostname) : '<span class="muted">—</span>'}${i.lab_name ? `<br><span class="muted">${esc(i.lab_name)}</span>` : ''}</td>
    <td><span class="pill ${stc}">${esc(stl)}</span>${i.auto_resolved ? ' <small class="muted">auto</small>' : ''}</td>
    <td class="small">${i.assignee ? esc(i.assignee) : '<span class="muted">—</span>'}</td>
    <td class="nowrap small muted">${ago(i.created)}</td>
    ${manage ? `<td class="nowrap">${acts.join(' ')}</td>` : ''}</tr>`;
}

async function incAction(id, action, done) {
  try { await api(`/api/incidents/${id}`, { method: 'PATCH', body: { action } }); toast(`Incident ${action === 'acknowledge' ? 'acknowledged' : action === 'reopen' ? 'reopened' : action + 'd'}`); done(); }
  catch (e) { toast(e.message, true); }
}

function incEdit(i, done) {
  modal({
    title: 'Assign / add a note', submit: 'Save',
    body: `<p class="note">${esc(i.title)}</p>
      <label>Assignee<input name="assignee" maxlength="64" value="${esc(i.assignee || '')}" placeholder="who owns this"></label>
      <label>Note<textarea name="note" maxlength="1000" dir="auto" style="min-height:80px;font-family:inherit;font-size:14px">${esc(i.note || '')}</textarea></label>`,
    onSubmit: async (f) => { await api(`/api/incidents/${i.id}`, { method: 'PATCH', body: { action: 'assign', assignee: f.assignee.value, note: f.note.value } }); toast('Incident updated'); done(); },
  });
}

async function incForm(done) {
  let devs = [];
  try { devs = await api('/api/devices'); } catch { /* none */ }
  const mgr = state.me.role === 'school_manager';
  modal({
    title: 'New incident', submit: 'Create incident',
    body: `<label>Title<input name="title" maxlength="200" required dir="auto" placeholder="e.g. Projector PC will not boot"></label>
      <label>Severity<select name="severity"><option value="warning">Warning</option><option value="critical">Critical</option><option value="info">Info</option></select></label>
      <label>Device${mgr ? '' : ' (optional)'}<select name="device_id" ${mgr ? 'required' : ''}>
        ${mgr ? '' : '<option value="">— Not tied to a device —</option>'}
        ${devs.map((d) => `<option value="${esc(d.id)}">${esc(d.hostname)}${placeText(d) ? ' · ' + esc(placeText(d)) : ''}</option>`).join('')}</select></label>
      <label>Detail<textarea name="detail" maxlength="1000" dir="auto" style="min-height:80px;font-family:inherit;font-size:14px"></textarea></label>`,
    onSubmit: async (f) => { await api('/api/incidents', { method: 'POST', body: { title: f.title.value, severity: f.severity.value, device_id: f.device_id.value, detail: f.detail.value } }); toast('Incident created'); done(); },
  });
}

async function boot() {
  try { state.me = await api('/api/me'); } catch { return; }
  $('#login').classList.add('hidden');
  $('#app').classList.remove('hidden');
  const m = state.me;
  $('#me').innerHTML = `${esc(m.display_name || m.user)}<br><small class="muted">${esc(roleLabel(m.role))}${m.scope_label ? ' · ' + esc(m.scope_label) : ''}</small>`;
  $$('.side nav a[data-cap]').forEach((a) => a.classList.toggle('hidden', !cap(a.dataset.cap)));
  if (location.hash.startsWith('#/class') && m.role !== 'teacher') location.hash = '#/devices';
  route();
  if (cap('view_incidents')) { refreshIncidentBadge(); setInterval(() => { if (!document.hidden) refreshIncidentBadge(); }, 30000); }
}

async function refreshIncidentBadge() {
  const el = $('#inc-badge');
  if (!el) return;
  try {
    const s = await api('/api/incidents/summary');
    el.textContent = s.total || '';
    el.classList.toggle('hidden', !s.total);
    el.classList.toggle('crit', s.critical > 0);
  } catch { /* leave as is */ }
}

window.addEventListener('hashchange', route);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') $('#modal-root').innerHTML = ''; });
boot();
