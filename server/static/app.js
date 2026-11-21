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
  update_agent: 'Update agent', distribute_file: 'Distribute file', set_app_policy: 'Application allowlist',
  launch_app: 'Launch app', set_hostname: 'Rename computer', set_local_admin_password: 'Set admin password',
  request_screenshot: 'Screen capture', lock_input: 'Input lock',
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
const allowedHas = (c) => !!(state.me && state.me.capabilities && (state.me.capabilities.commands || []).includes(c));
// ---- AG Grid helpers (lists use ag-grid-community, vendored under /static/vendor) ----
const gridHtml = (fn) => (p) => { const d = document.createElement('div'); d.style.cssText = 'display:flex;align-items:center;gap:6px;width:100%;overflow:hidden'; d.innerHTML = (p.data ? fn(p.data, p) : '') || ''; return d; };
function makeGrid(el, opts) {
  el.classList.add('ag-theme-quartz');
  return agGrid.createGrid(el, {
    rowData: opts.rowData || [],
    columnDefs: opts.columnDefs,
    enableRtl: (typeof LANG !== 'undefined' && LANG === 'he'),
    defaultColDef: { sortable: true, filter: true, resizable: true, minWidth: 80, flex: 1 },
    suppressCellFocus: true, animateRows: false, rowHeight: opts.rowHeight || 44,
    getRowId: opts.getRowId, rowSelection: opts.rowSelection,
    suppressRowClickSelection: !!opts.rowSelection,
    onSelectionChanged: opts.onSelectionChanged, onRowClicked: opts.onRowClicked,
    overlayNoRowsTemplate: opts.noRows || `<span class="muted">${t('common.loading')}</span>`,
  });
}
const isAdmin = () => ['superadmin', 'municipality_admin'].includes(state.me && state.me.role);
const roleLabel = (r) => (I18N.en['role.' + r] ? t('role.' + r) : (ROLE_LABEL[r] || r));
const placeText = (d) => (d.place && d.place.lab ? `${d.place.school ? d.place.school + ' · ' : ''}${d.place.lab}` : '');

// ------------------------------------------------------------------ i18n (English + Hebrew/RTL)
const I18N = {
  en: {
    'app.title': 'KEM Endpoint Manager',
    'nav.devices': 'Devices', 'nav.activity': 'Activity', 'nav.incidents': 'Incidents', 'nav.org': 'Organization',
    'nav.gateways': 'Gateways', 'nav.users': 'Users', 'nav.licensing': 'Licensing', 'nav.reports': 'Reports',
    'nav.enroll': 'Add devices', 'nav.audit': 'Audit log', 'nav.settings': 'Settings', 'nav.images': 'Images',
    'login.username': 'Username', 'login.password': 'Password', 'login.signin': 'Sign in', 'sidebar.signout': 'Sign out',
    'devices.title': 'Devices', 'devices.sub.server': 'Stations managed by this server', 'devices.sub.lab': 'Your lab',
    'devices.add': '＋ Add devices', 'devices.search': 'Search hostname, user, IP, OS, model…', 'devices.allgroups': 'All groups',
    'tile.all': 'Total devices', 'tile.online': 'Online', 'tile.offline': 'Offline', 'tile.isolated': 'Internet blocked',
    'tile.updates': 'Missing security updates', 'tile.alerts': 'Need attention',
    'col.device': 'Device', 'col.user': 'User', 'col.os': 'OS', 'col.ip': 'IP', 'col.cpu': 'CPU', 'col.ram': 'RAM',
    'col.disk': 'Disk', 'col.lastseen': 'Last seen', 'col.status': 'Status',
    'bulk.selected': 'selected', 'bulk.clear': 'Clear selection',
    'act.block_internet': '⛔ Block internet', 'act.unblock_internet': '🌐 Restore internet', 'act.install_software': '⬇ Install software',
    'act.distribute_file': '📄 Distribute file', 'act.install_updates': '⟳ Windows updates', 'act.set_web_filter': '🚫 Web filter',
    'act.usb_storage': '🔌 USB', 'act.set_app_policy': '🛡 Allowlist', 'act.launch_app': '▶ Launch app', 'act.send_message': '💬 Message',
    'act.lock_session': '🔒 Lock', 'act.run_script': '›_ Run script', 'act.defender_scan': '🛡 Scan', 'act.reboot': '↻ Reboot',
    'dev.rename': 'Rename computer', 'dev.rename.title': 'Rename {host}', 'dev.rename.label': 'New computer name',
    'dev.rename.help': '1–15 letters, digits or hyphens (not all digits). The station reboots to apply the new name.',
    'dev.rename.reboot': 'Reboot now to apply the new name', 'dev.rename.submit': 'Rename & reboot',
    'dev.rename.confirm': 'Type the current name ', 'dev.rename.bad': 'Invalid computer name.', 'dev.rename.one': 'Rename one station at a time.',
    'dev.setpw': 'Set admin password', 'dev.setpw.title': 'Set local admin password', 'dev.setpw.acct': 'Account',
    'dev.setpw.acctdefault': 'KEM managed admin (kemadmin)', 'dev.setpw.acctother': 'Another local account…', 'dev.setpw.acctname': 'Account name',
    'dev.setpw.pw': 'New password', 'dev.setpw.pw2': 'Confirm password', 'dev.setpw.gen': 'Generate strong password',
    'dev.setpw.help': 'Sets the password of a managed local administrator. The account stays in Administrators and is denied interactive/RDP logon. The password is sent once over TLS and never shown again.',
    'dev.setpw.mismatch': 'Passwords do not match.', 'dev.setpw.short': 'Password must be at least 8 characters.',
    'dev.setpw.submit': 'Set password', 'dev.setpw.t.queued': 'Password change queued',
    'pill.blocked': '⛔ Blocked', 'pill.working': 'Working…', 'pill.filter': '🚫 Filter', 'pill.healthy': 'Healthy',
    'devices.none': 'No devices yet.', 'devices.nomatch': 'No devices match this filter.', 'common.loading': 'Loading…',
    'common.cancel': 'Cancel',
    'role.superadmin': 'Platform owner', 'role.municipality_admin': 'Municipality admin', 'role.school_manager': 'School manager', 'role.teacher': 'Teacher',
    'page.activity.title': 'Activity', 'page.activity.sub': 'Every command sent to every device, newest first',
    'page.audit.title': 'Audit log', 'page.audit.sub': 'Sign-ins, enrollments and every admin action',
    'page.enroll.title': 'Add devices', 'page.enroll.sub': 'Create a registration token, then run the install command on each machine',
    'page.settings.title': 'Settings', 'page.settings.sub': 'Server settings, notifications and automation',
    'page.org.title': 'Organization', 'page.org.sub': 'Municipalities, schools and computer labs',
    'page.users.title': 'Users', 'page.users.sub': 'Administrators, school managers and teachers',
    'page.gateways.title': 'Teacher Gateways', 'page.gateways.sub': 'Lab relays between student stations and this server',
    'page.licensing.title': 'Software licensing', 'page.licensing.sub': 'Installed commercial software vs recorded entitlements',
    'page.incidents.title': 'Incidents', 'page.incidents.sub': 'Health alerts and issues to track',
    'page.reports.title': 'Reports', 'page.reports.sub': "Export your scope's data — CSV opens in Excel, the HTML view prints to PDF",
    'page.images.title': 'Image repository', 'page.images.sub': 'Golden OS images referenced by location + checksum, and the image each lab should run.',
    'page.images.note': 'Distribution & reimaging need boot media and are not built yet.',
    'inc.scan': '⟳ Scan now', 'inc.new': '＋ New incident',
    'inc.seg.unresolved': 'Unresolved', 'inc.seg.open': 'Open', 'inc.seg.acknowledged': 'Acknowledged', 'inc.seg.resolved': 'Resolved', 'inc.seg.all': 'All',
    'inc.col.severity': 'Severity', 'inc.col.issue': 'Issue', 'inc.col.device': 'Device / lab', 'inc.col.status': 'Status', 'inc.col.assignee': 'Assignee', 'inc.col.opened': 'Opened',
    'sev.critical': 'Critical', 'sev.warning': 'Warning', 'sev.info': 'Info',
    'ist.open': 'Open', 'ist.acknowledged': 'Acknowledged', 'ist.resolved': 'Resolved',
    'inc.auto': 'auto-detected', 'inc.autores': 'auto',
    'inc.ack': 'Ack', 'inc.resolve': 'Resolve', 'inc.reopen': 'Reopen', 'inc.assignnote': 'Assign / note',
    'inc.empty': 'Nothing here.', 'inc.none': '—',
    'inc.edit.title': 'Assign / add a note', 'inc.assignee': 'Assignee', 'inc.note': 'Note', 'inc.assignee.ph': 'who owns this',
    'inc.new.title': 'New incident', 'inc.create': 'Create incident', 'inc.title': 'Title', 'inc.severity': 'Severity', 'inc.device': 'Device', 'inc.detail': 'Detail',
    'inc.t.created': 'Incident created', 'inc.t.updated': 'Incident updated', 'inc.t.acknowledged': 'Incident acknowledged', 'inc.t.resolved': 'Incident resolved', 'inc.t.reopened': 'Incident reopened', 'inc.t.scanned': 'Scan complete',
    'common.save': 'Save', 'common.delete': 'Delete', 'common.notied': '— Not tied to a device —',
    'report.devices': 'Device inventory', 'report.licensing': 'Software licence compliance', 'report.incidents': 'Incidents',
    'rep.desc.devices': 'Every station in your scope — placement, OS, health, controls and current alerts.',
    'rep.desc.licensing': 'Installed commercial software vs. the licences on record: seats, expiry and findings.',
    'rep.desc.incidents': 'All incidents in your scope with severity, status, assignee and timestamps.',
    'rep.open': 'Open (print / PDF)', 'rep.csv': 'Download CSV', 'rep.nocards': 'No reports available for your role.',
    'rep.sched': 'Scheduled reports', 'rep.newsched': '＋ New schedule', 'rep.runs': 'Recent runs',
    'rep.col.report': 'Report', 'rep.col.cadence': 'Cadence', 'rep.col.next': 'Next run', 'rep.col.delivery': 'Delivery',
    'rep.col.status': 'Status', 'rep.col.when': 'When', 'rep.col.scope': 'Scope', 'rep.col.rows': 'Rows',
    'rep.hist': 'history only', 'rep.webhook': 'webhook', 'rep.on': 'On', 'rep.off': 'Off',
    'rep.runnow': 'Run now', 'rep.enable': 'Enable', 'rep.disable': 'Disable', 'rep.last': 'last',
    'rep.noruns': 'No reports generated yet.', 'rep.nosched': 'No schedules yet. Create one to generate reports automatically.',
    'rep.del.title': 'Delete schedule', 'rep.del.body': 'Remove this schedule and its stored report history?',
    'rep.new.title': 'New scheduled report', 'rep.create': 'Create schedule',
    'rep.f.hour': 'Hour (0–23)', 'rep.f.weekday': 'Day of week', 'rep.f.monthday': 'Day of month (1–28)',
    'rep.f.recipients': 'E-mail recipients (optional, comma separated)', 'rep.f.webhook': 'Also post a summary to the configured webhook',
    'rep.f.note': 'Each run is saved here for download. E-mail attaches the CSV; both need the matching channel set up in Settings.',
    'rep.t.created': 'Schedule created', 'rep.t.deleted': 'Schedule deleted', 'rep.t.generated': 'Generated',
    'cad.daily': 'Daily', 'cad.weekly': 'Weekly', 'cad.monthly': 'Monthly', 'cad.at': 'at',
    'cad.weekly.on': 'Weekly on', 'cad.weekly.suffix': 's', 'cad.monthly.on': 'Monthly on day',
    'weekday.0': 'Monday', 'weekday.1': 'Tuesday', 'weekday.2': 'Wednesday', 'weekday.3': 'Thursday', 'weekday.4': 'Friday', 'weekday.5': 'Saturday', 'weekday.6': 'Sunday',
    'usr.add': '＋ Add user', 'usr.new': 'New user', 'usr.username': 'Username', 'usr.display': 'Display name', 'usr.display.ph': 'optional',
    'usr.password': 'Password (10+ characters)', 'usr.role': 'Role', 'usr.scope': 'Scope', 'usr.create': 'Create user', 'usr.scope.none': '(create one in Organization first)',
    'usr.col.user': 'User', 'usr.col.role': 'Role', 'usr.col.scope': 'Scope', 'usr.col.last': 'Last login', 'usr.col.status': 'Status',
    'usr.never': 'never', 'usr.active': 'active', 'usr.disabled': 'disabled', 'usr.pw': 'password', 'usr.enable': 'enable', 'usr.disable': 'disable', 'usr.none': 'No users.',
    'usr.t.created': 'User created', 'usr.t.deleted': 'User deleted', 'usr.t.pwreset': 'Password reset', 'usr.confirm.del': 'Delete this user?', 'usr.prompt.pw': 'New password (10+ characters):',
    'org.addmuni': '＋ Add municipality', 'org.addschool': '+ school', 'org.addlab': '+ lab', 'org.del': 'delete',
    'org.nolabs': 'no labs yet', 'org.noschools': 'no schools yet', 'org.nomunis': 'No municipalities yet.', 'org.devices': 'devices', 'org.gateways': 'gateways',
    'org.unplaced': 'unplaced devices — assign on each device page',
    'org.p.muni': 'New municipality name:', 'org.p.school': 'New school name:', 'org.p.lab': 'New lab name:',
    'org.c.muni': 'Delete this municipality? It must be empty.', 'org.c.school': 'Delete this school? It must be empty.', 'org.c.lab': 'Delete this lab? Move its devices out first.',
    'org.t.added': 'Added', 'org.t.deleted': 'Deleted',
    'gw.token': 'Create gateway token', 'gw.col.gateway': 'Gateway', 'gw.col.lab': 'Lab', 'gw.col.devices': 'Devices', 'gw.col.version': 'Version', 'gw.col.last': 'Last seen', 'gw.col.status': 'Status',
    'gw.online': 'online', 'gw.offline': 'offline', 'gw.remove': 'remove', 'gw.none': 'No gateways enrolled yet.', 'gw.never': 'never',
    'gw.confirm.remove': 'Remove this gateway? Its devices stay enrolled but lose the relay link.', 'gw.t.removed': 'Gateway removed',
    'fnd.confirmed_issue': 'Confirmed issue', 'fnd.potential_gap': 'Potential gap', 'fnd.verification_required': 'Verification required', 'fnd.compliant': 'Compliant', 'fnd.not_applicable': 'Not applicable',
    'lic.addent': '＋ Add entitlement', 'lic.ents': 'Entitlements',
    'lic.col.product': 'Product', 'lic.col.installs': 'Installs', 'lic.col.licence': 'Licence', 'lic.col.status': 'Status', 'lic.col.detail': 'Detail',
    'lic.site': 'site', 'lic.seats': 'seats', 'lic.nofindings': 'No commercial software detected in scope yet.',
    'lic.col.name': 'Name', 'lic.col.type': 'Type', 'lic.col.seats': 'Seats', 'lic.col.scope': 'Scope', 'lic.col.expires': 'Expires',
    'lic.edit': 'edit', 'lic.noents': 'No entitlements recorded. Add what the school owns to turn "potential gaps" into compliance.',
    'lic.confirm.del': 'Delete this entitlement?', 'lic.t.deleted': 'Deleted', 'lic.t.updated': 'Updated', 'lic.t.added': 'Entitlement added',
    'lic.p.seats': 'Seats (0 = site/unlimited):', 'lic.p.expiry': 'Expiry date YYYY-MM-DD (blank = none):',
    'lic.new': 'New entitlement', 'lic.create': 'Create entitlement', 'lic.f.name': 'Name', 'lic.f.product': 'Product', 'lic.f.other': '— Other / none —',
    'lic.f.type': 'Licence type', 'lic.f.seats': 'Seats (0 = site / unlimited)', 'lic.f.covers': 'Covers',
    'lic.covers.lab': 'A lab', 'lic.covers.school': 'A school', 'lic.covers.municipality': 'A municipality', 'lic.covers.global': 'All (global)',
    'lic.f.which': 'Which', 'lic.f.expires': 'Expires (optional)', 'lic.f.notes': 'Notes', 'lic.scope.none': '(none yet)',
    'img.register': '＋ Register image', 'img.col.image': 'Image', 'img.col.osver': 'OS / version', 'img.col.size': 'Size', 'img.col.scope': 'Scope', 'img.col.source': 'Source', 'img.col.sha': 'SHA-256', 'img.del': 'Delete',
    'img.none.manage': 'No images registered — click “Register image”.', 'img.none': 'No images registered.',
    'img.labtitle': 'Per-lab target image', 'img.col.school': 'School', 'img.col.lab': 'Lab', 'img.col.target': 'Target image', 'img.nolabs': 'No labs in your scope.', 'img.none.target': '— none —',
    'img.t.updated': 'Target image updated', 'img.t.deleted': 'Image deleted', 'img.t.registered': 'Image registered',
    'img.del.title': 'Delete image', 'img.del.body': 'Remove this image from the repository? Labs pointing at it will have their target cleared.',
    'img.new': 'Register an image', 'img.create': 'Register', 'img.f.name': 'Name', 'img.f.os': 'Operating system', 'img.f.version': 'Version',
    'img.f.source': 'Source (URL or share path)', 'img.f.size': 'Size (bytes)', 'img.f.sha': 'SHA-256 (optional)', 'img.f.scope': 'Scope', 'img.f.scopetarget': 'Scope target', 'img.f.notes': 'Notes',
    'img.f.note': 'The image file itself is not uploaded — KEM stores a reference (location + checksum). Gateway distribution and reimaging are not built yet.',
    'set.pw.title.self': 'Change your password', 'set.pw.title.admin': 'Change admin password', 'set.pw.current': 'Current password', 'set.pw.new': 'New password (10+ characters)', 'set.pw.update': 'Update password', 'set.t.pwupdated': 'Password updated',
    'set.notif': 'Notifications', 'set.notif.note': 'Get told when something needs attention. Use a chat webhook, e-mail, or both.',
    'set.f.webhook': 'Webhook URL', 'set.notif.whichhelp': 'Which webhook URLs work?', 'set.f.email': 'E-mail to (comma separated)',
    'set.f.smtphost': 'SMTP server', 'set.f.port': 'Port', 'set.f.security': 'Security', 'set.f.from': 'From address', 'set.f.smtpuser': 'SMTP user', 'set.f.smtppass': 'SMTP password', 'set.pwsaved': '•••••• (saved — leave blank to keep)',
    'set.notif.when': 'Notify me when', 'set.f.offline': 'Offline threshold (hours, 0 = off)', 'set.save': 'Save', 'set.sendtest': 'Send test', 'set.t.testsent': 'Test notification sent', 'set.t.saved': 'Settings saved',
    'set.auto': 'Automation', 'set.auto.scan': 'Scan every device for missing Windows updates once a day', 'set.auto.agent': 'Keep agents up to date automatically', 'set.auto.agent.sub': "Devices update to the server's agent version on their next check-in.",
    'set.ai': 'AI diagnostics', 'set.ai.note': 'Point KEM at a local OpenAI-compatible model (Ollama, llama.cpp, LM Studio, vLLM). "Diagnose" on a device page sends that device\'s health data only — never the signed-in user, IP or serial — and shows the model\'s advice. Suggestions only; review before acting.',
    'set.f.aiurl': 'Endpoint base URL', 'set.f.aimodel': 'Model', 'set.f.aikey': 'API key (optional)', 'set.ai.key.need': 'only if your endpoint needs one', 'set.ai.enable': 'Enable AI diagnostics', 'set.ai.enable.sub': 'Keep the endpoint on localhost or your LAN; data leaves KEM only to the URL above.', 'set.testconn': 'Test connection', 'set.ai.reachable': 'AI reachable',
    'set.notiflog': 'Recent notifications', 'set.col.time': 'Time', 'set.col.device': 'Device', 'set.col.event': 'Event', 'set.col.message': 'Message', 'set.col.delivery': 'Delivery', 'set.notiflog.none': 'Nothing sent yet.',
    'cls.active': 'Class in session', 'cls.active.sub': 'classroom controls are enabled', 'cls.start.msg': 'Start a class session to control the computers in your lab.',
    'cls.start': 'Start class', 'cls.end': 'End class', 'cls.t.started': 'Class started', 'cls.t.ended': 'Class ended',
    'exam.locks.internet': 'internet blocked', 'exam.locks.usb': 'USB blocked', 'exam.locks.sites': '{n} sites filtered', 'exam.locks.none': 'no restrictions',
    'exam.label': 'Exam', 'exam.stations': 'stations', 'exam.by': 'by', 'exam.end': 'End exam',
    'exam.mode': 'Exam mode', 'exam.mode.desc': "lock a lab's stations for a test", 'exam.needclass': '(needs an active class)', 'exam.name.ph': 'Exam name',
    'exam.internet': 'internet', 'exam.usb': 'USB', 'exam.start': 'Start exam', 'exam.nolabs': 'No labs with stations to run an exam on yet.',
    'exam.t.ended': 'Exam ended', 'exam.t.started': 'Exam started',
    'sw.name': 'Name', 'sw.version': 'Version', 'sw.publisher': 'Publisher', 'sw.installed': 'Installed', 'sw.peruser': 'per-user',
    'sw.programs': 'programs', 'sw.collected': 'collected', 'sw.notcollected': 'Not collected yet', 'sw.none': 'Nothing to show',
    'sw.uninstallsel': 'Uninstall selected', 'sw.confirm': 'Uninstall {n} program(s)? This runs their uninstaller on the device.', 'sw.t.queued': 'Uninstall queued for {n} program(s)',
    'nav.packages': 'Packages', 'nav.classes': 'Classes', 'nav.fleetai': 'Ask AI', 'nav.exams': 'Exam schedule',
    'scr.view': 'View screen', 'scr.freeze': 'Freeze input', 'scr.title': 'Station screen', 'scr.refresh': 'Capture again',
    'scr.asking': 'Asking the station for its screen…', 'scr.timeout': 'No screen received (the station may be offline or no user is signed in).',
    'scr.note': 'The signed-in student sees a brief “your screen was viewed by IT” indicator. One frame per capture.',
    'scr.apply': 'Apply', 'scr.freeze.title': 'Freeze keyboard & mouse', 'scr.freeze.lock': 'Lock input',
    'scr.freeze.unlock': 'Unlock input', 'scr.freeze.note': 'Disables the station’s keyboard and mouse until you unlock it.',
    'scr.unlock.note': 'Restores keyboard and mouse control to the student.', 'scr.locked': 'Input lock queued', 'scr.unlocked': 'Input unlock queued',
    'es.title': 'Scheduled exams', 'es.sub': 'Lock a lab into exam mode automatically at a set time, and lift it when the window ends',
    'es.new': '＋ New schedule', 'es.name': 'Exam name', 'es.lab': 'Lab', 'es.when': 'When', 'es.locks': 'Locks',
    'es.cadence': 'Repeat', 'es.once': 'Once', 'es.daily': 'Every day', 'es.weekly': 'Every week',
    'es.date': 'Date', 'es.weekday': 'Day', 'es.time': 'Start time', 'es.duration': 'Duration (minutes)',
    'es.internet': 'Block internet', 'es.usb': 'Block USB', 'es.lan': 'Keep local network',
    'es.create': 'Create schedule', 'es.save': 'Save', 'es.col.exam': 'Exam', 'es.col.lab': 'Lab',
    'es.col.when': 'When', 'es.col.next': 'Next run', 'es.col.status': 'Status', 'es.none': 'No scheduled exams yet.',
    'es.on': 'On', 'es.off': 'Off', 'es.active': 'Running now', 'es.enabled': 'Scheduled', 'es.disabled': 'Paused',
    'es.del': 'delete', 'es.edit': 'Edit', 'es.confirm.del': 'Delete this scheduled exam?',
    'es.t.created': 'Exam scheduled', 'es.t.saved': 'Schedule updated', 'es.t.deleted': 'Schedule deleted',
    'es.nolabs': 'Create a lab first.', 'es.for': 'for {d} min', 'es.locks.none': 'no locks',
    'es.wd.0': 'Monday', 'es.wd.1': 'Tuesday', 'es.wd.2': 'Wednesday', 'es.wd.3': 'Thursday', 'es.wd.4': 'Friday', 'es.wd.5': 'Saturday', 'es.wd.6': 'Sunday',
    'fa.title': 'Ask AI about the fleet', 'fa.sub': 'Natural-language questions over every station’s specs and live usage',
    'fa.ph': 'e.g. Which stations have a weak CPU or low memory?', 'fa.ask': 'Ask', 'fa.asking': 'Thinking…',
    'fa.presets': 'Quick questions', 'fa.answer': 'Answer', 'fa.model': 'Answered by {m} over {n} station(s)',
    'fa.off': 'The local AI endpoint is not enabled. An administrator can set it up in Settings. The insights below still work without it.',
    'fa.insights': 'Fleet insights', 'fa.insights.sub': 'Computed directly from inventory — no AI needed', 'fa.insights.none': 'No stations reporting yet.',
    'fa.stations': 'stations', 'fa.allgood': 'None',
    'fa.f.weak_cpu': 'Weak CPU (≤2 cores)', 'fa.f.low_ram': 'Low memory (<4 GB)', 'fa.f.low_disk': 'Low disk (<10 GB / <10% free)',
    'fa.f.slow_nic': 'Slow network card (<1 Gbps)', 'fa.f.high_cpu': 'High CPU (≥90%)', 'fa.f.high_mem': 'High memory (≥90%)',
    'fa.f.high_disk': 'High disk use (≥90%)', 'fa.f.offline': 'Offline',
    'fa.q.weak': 'Which stations have a weak CPU or low memory?', 'fa.q.disk': 'Which stations are low on disk space?',
    'fa.q.nic': 'Which stations have a slow network card (under 1 Gbps)?', 'fa.q.busy': 'Which stations have high CPU, memory or disk usage right now?',
    'fa.q.upgrade': 'Which stations should be upgraded or replaced first, and why?',
    'cl.title': 'Classes', 'cl.sub': 'Group stations into a class and promote one to a teacher station the others connect through',
    'cl.new': '＋ New class', 'cl.name': 'Class name', 'cl.lab': 'Lab', 'cl.lab.any': '— any lab —',
    'cl.members': 'Stations', 'cl.members.help': 'Pick the stations in this class.', 'cl.create': 'Create class',
    'cl.col.name': 'Class', 'cl.col.members': 'Stations', 'cl.col.teacher': 'Teacher station', 'cl.col.status': 'Status',
    'cl.none': 'No classes yet.', 'cl.nomembers': 'no stations', 'cl.del': 'delete', 'cl.confirm.del': 'Delete this class?',
    'cl.t.created': 'Class created', 'cl.t.deleted': 'Class deleted', 'cl.t.saved': 'Class updated',
    'cl.edit': 'Edit', 'cl.setteacher': 'Set teacher station', 'cl.dissolve': 'Dissolve',
    'cl.active': 'Active · {n} re-homed', 'cl.inactive': 'Direct to server', 'cl.gw.online': 'relay online', 'cl.gw.offline': 'relay offline',
    'cl.promote.title': 'Promote a teacher station', 'cl.promote.pick': 'Teacher station',
    'cl.promote.addr': 'Teacher station address (LAN IP or name)', 'cl.promote.addr.help': 'Leave blank to use the station hostname. Classmates connect to http://<address>:<port>.',
    'cl.promote.port': 'Relay port', 'cl.promote.submit': 'Promote & re-home',
    'cl.promote.note': 'The other stations will reconnect through this station. If it is offline, they fall back to the central server automatically.',
    'cl.t.promoted': 'Teacher station set — {n} station(s) re-homed', 'cl.t.dissolved': 'Teacher station dissolved',
    'cl.dissolve.confirm': 'Send all stations back to the central server and stop the relay?',
    'cl.needmembers': 'Add at least one station first.', 'cl.teacher.badge': '★ teacher',
    'pkg.title': 'Software packages', 'pkg.sub': 'Desired app sets for stations — install the set, optionally remove the rest',
    'pkg.new': '＋ New package', 'pkg.name': 'Name', 'pkg.items': 'Apps (one per line)',
    'pkg.items.help': 'Format:  Label | match | winget:Id   or   Label | match | url:https://…   — "match" is text found in the installed name. Leave the 3rd part blank to only keep it (e.g.  Windows | windows | ).',
    'pkg.create': 'Create package', 'pkg.scope': 'Scope', 'pkg.scopetarget': 'Scope target', 'pkg.notes': 'Notes',
    'pkg.col.name': 'Package', 'pkg.col.scope': 'Scope', 'pkg.col.items': 'Apps', 'pkg.del': 'delete', 'pkg.none': 'No packages yet.',
    'pkg.confirm.del': 'Delete this package?', 'pkg.t.created': 'Package created', 'pkg.t.deleted': 'Package deleted',
    'pkg.applybtn': 'Apply package', 'pkg.apply.title': 'Apply a package', 'pkg.apply': 'Apply', 'pkg.pkg': 'Package',
    'pkg.removeextras': 'Also remove apps not in the package (keeps Windows, drivers, security, runtimes)',
    'pkg.previewhint': 'Pick a package to preview the plan.', 'pkg.note': 'Preview first. Installs/removals run on the device as the agent processes them.',
    'pkg.install': 'Install', 'pkg.remove': 'Remove', 'pkg.keep': 'Keep', 'pkg.protected': 'Protected',
    'pkg.t.applied': 'Queued {n} action(s)', 'pkg.none.apply': 'No packages defined — create one first.', 'pkg.badline': 'Bad line (use Label | match | winget:Id or url:…): ',
    'pkg.bl.title': 'Lab baselines', 'pkg.bl.sub': 'Set a package as a lab’s standard — new stations auto-install it, and you can see which stations have drifted.',
    'pkg.bl.lab': 'Lab', 'pkg.bl.pkg': 'Baseline', 'pkg.bl.none': '— none —', 'pkg.bl.remove': 'Remove extras',
    'pkg.bl.auto': 'Auto on enroll', 'pkg.bl.auto.help': 'Installs the set (never removes) the first time a station registers.',
    'pkg.bl.col.status': 'Status', 'pkg.bl.apply': 'Apply to all', 'pkg.bl.saved': 'Baseline updated', 'pkg.bl.nolabs': 'No labs yet.',
    'pkg.bl.compliant': 'All compliant', 'pkg.bl.drift': '{d} of {n} drifted', 'pkg.bl.empty': 'No stations',
    'pkg.bl.applytitle': 'Apply baseline to the lab', 'pkg.bl.applybtn': 'Update drifted stations',
    'pkg.bl.willfix': '{n} station(s) will be updated:', 'pkg.bl.allok': 'All stations already match the baseline.',
    'pkg.bl.queued': 'Queued updates for {n} station(s)', 'pkg.bl.ok': 'OK',
  },
  he: {
    'app.title': 'KEM · ניהול עמדות',
    'nav.devices': 'עמדות', 'nav.activity': 'פעילות', 'nav.incidents': 'תקריות', 'nav.org': 'ארגון',
    'nav.gateways': 'שערים', 'nav.users': 'משתמשים', 'nav.licensing': 'רישוי', 'nav.reports': 'דוחות',
    'nav.enroll': 'הוספת עמדות', 'nav.audit': 'יומן ביקורת', 'nav.settings': 'הגדרות', 'nav.images': 'תמונות מערכת',
    'login.username': 'שם משתמש', 'login.password': 'סיסמה', 'login.signin': 'כניסה', 'sidebar.signout': 'התנתקות',
    'devices.title': 'עמדות', 'devices.sub.server': 'עמדות המנוהלות על ידי שרת זה', 'devices.sub.lab': 'המעבדה שלך',
    'devices.add': '＋ הוספת עמדות', 'devices.search': 'חיפוש לפי שם, משתמש, IP, מערכת הפעלה, דגם…', 'devices.allgroups': 'כל הקבוצות',
    'tile.all': 'סך העמדות', 'tile.online': 'מחוברות', 'tile.offline': 'מנותקות', 'tile.isolated': 'אינטרנט חסום',
    'tile.updates': 'עדכוני אבטחה חסרים', 'tile.alerts': 'דורשות טיפול',
    'col.device': 'עמדה', 'col.user': 'משתמש', 'col.os': 'מערכת הפעלה', 'col.ip': 'כתובת IP', 'col.cpu': 'מעבד', 'col.ram': 'זיכרון',
    'col.disk': 'דיסק', 'col.lastseen': 'נראתה לאחרונה', 'col.status': 'מצב',
    'bulk.selected': 'נבחרו', 'bulk.clear': 'ניקוי הבחירה',
    'act.block_internet': '⛔ חסום אינטרנט', 'act.unblock_internet': '🌐 שחזר אינטרנט', 'act.install_software': '⬇ התקן תוכנה',
    'act.distribute_file': '📄 הפץ קובץ', 'act.install_updates': '⟳ עדכוני Windows', 'act.set_web_filter': '🚫 סינון אתרים',
    'act.usb_storage': '🔌 USB', 'act.set_app_policy': '🛡 רשימת היתר', 'act.launch_app': '▶ הפעל אפליקציה', 'act.send_message': '💬 הודעה',
    'act.lock_session': '🔒 נעילה', 'act.run_script': '›_ הרצת סקריפט', 'act.defender_scan': '🛡 סריקה', 'act.reboot': '↻ הפעלה מחדש',
    'dev.rename': 'שנה שם מחשב', 'dev.rename.title': 'שנה שם ל‑{host}', 'dev.rename.label': 'שם מחשב חדש',
    'dev.rename.help': '1–15 אותיות, ספרות או מקפים (לא רק ספרות). העמדה תופעל מחדש כדי להחיל את השם.',
    'dev.rename.reboot': 'הפעל מחדש עכשיו כדי להחיל את השם', 'dev.rename.submit': 'שנה שם והפעל מחדש',
    'dev.rename.confirm': 'הקלד את השם הנוכחי ', 'dev.rename.bad': 'שם מחשב לא תקין.', 'dev.rename.one': 'שנו שם לעמדה אחת בכל פעם.',
    'dev.setpw': 'הגדר סיסמת מנהל', 'dev.setpw.title': 'הגדרת סיסמת מנהל מקומי', 'dev.setpw.acct': 'חשבון',
    'dev.setpw.acctdefault': 'מנהל מנוהל של KEM‏ (kemadmin)', 'dev.setpw.acctother': 'חשבון מקומי אחר…', 'dev.setpw.acctname': 'שם חשבון',
    'dev.setpw.pw': 'סיסמה חדשה', 'dev.setpw.pw2': 'אימות סיסמה', 'dev.setpw.gen': 'צור סיסמה חזקה',
    'dev.setpw.help': 'מגדיר את הסיסמה של מנהל מקומי מנוהל. החשבון נשאר בקבוצת Administrators וחסום להתחברות אינטראקטיבית/RDP. הסיסמה נשלחת פעם אחת ב‑TLS ואינה מוצגת שוב.',
    'dev.setpw.mismatch': 'הסיסמאות אינן תואמות.', 'dev.setpw.short': 'הסיסמה חייבת להיות באורך 8 תווים לפחות.',
    'dev.setpw.submit': 'הגדר סיסמה', 'dev.setpw.t.queued': 'שינוי הסיסמה נשלח',
    'pill.blocked': '⛔ חסום', 'pill.working': 'פועל…', 'pill.filter': '🚫 סינון', 'pill.healthy': 'תקין',
    'devices.none': 'אין עדיין עמדות.', 'devices.nomatch': 'אין עמדות התואמות לסינון זה.', 'common.loading': 'טוען…',
    'common.cancel': 'ביטול',
    'role.superadmin': 'בעל הפלטפורמה', 'role.municipality_admin': 'מנהל עירייה', 'role.school_manager': 'מנהל בית ספר', 'role.teacher': 'מורה',
    'page.activity.title': 'פעילות', 'page.activity.sub': 'כל פקודה שנשלחה לכל עמדה, מהחדשה לישנה',
    'page.audit.title': 'יומן ביקורת', 'page.audit.sub': 'כניסות, רישומים וכל פעולת מנהל',
    'page.enroll.title': 'הוספת עמדות', 'page.enroll.sub': 'צרו אסימון רישום, ואז הריצו את פקודת ההתקנה בכל מחשב',
    'page.settings.title': 'הגדרות', 'page.settings.sub': 'הגדרות שרת, התראות ואוטומציה',
    'page.org.title': 'ארגון', 'page.org.sub': 'עיריות, בתי ספר ומעבדות מחשבים',
    'page.users.title': 'משתמשים', 'page.users.sub': 'מנהלים, מנהלי בתי ספר ומורים',
    'page.gateways.title': 'שערי מורה', 'page.gateways.sub': 'ממסרי מעבדה בין עמדות התלמידים לשרת זה',
    'page.licensing.title': 'רישוי תוכנה', 'page.licensing.sub': 'תוכנה מסחרית מותקנת מול רישיונות רשומים',
    'page.incidents.title': 'תקריות', 'page.incidents.sub': 'התראות תקינות ובעיות למעקב',
    'page.reports.title': 'דוחות', 'page.reports.sub': 'ייצוא נתוני ההרשאה שלך — CSV נפתח ב‑Excel ותצוגת ה‑HTML מודפסת ל‑PDF',
    'page.images.title': 'מאגר תמונות מערכת', 'page.images.sub': 'תמונות מערכת זהב לפי מיקום + סכום ביקורת, והתמונה שכל מעבדה אמורה להריץ.',
    'page.images.note': 'ההפצה והדמיית מחדש דורשות מדיית אתחול ועדיין לא מומשו.',
    'inc.scan': '⟳ סרוק עכשיו', 'inc.new': '＋ תקרית חדשה',
    'inc.seg.unresolved': 'לא פתורות', 'inc.seg.open': 'פתוחות', 'inc.seg.acknowledged': 'טופלו', 'inc.seg.resolved': 'נפתרו', 'inc.seg.all': 'הכול',
    'inc.col.severity': 'חומרה', 'inc.col.issue': 'תקלה', 'inc.col.device': 'עמדה / מעבדה', 'inc.col.status': 'מצב', 'inc.col.assignee': 'אחראי', 'inc.col.opened': 'נפתחה',
    'sev.critical': 'קריטי', 'sev.warning': 'אזהרה', 'sev.info': 'מידע',
    'ist.open': 'פתוחה', 'ist.acknowledged': 'טופלה', 'ist.resolved': 'נפתרה',
    'inc.auto': 'זוהתה אוטומטית', 'inc.autores': 'אוטומטי',
    'inc.ack': 'אישור', 'inc.resolve': 'פתירה', 'inc.reopen': 'פתיחה מחדש', 'inc.assignnote': 'שיוך / הערה',
    'inc.empty': 'אין כאן תקריות.', 'inc.none': '—',
    'inc.edit.title': 'שיוך / הוספת הערה', 'inc.assignee': 'אחראי', 'inc.note': 'הערה', 'inc.assignee.ph': 'מי מטפל בזה',
    'inc.new.title': 'תקרית חדשה', 'inc.create': 'צור תקרית', 'inc.title': 'כותרת', 'inc.severity': 'חומרה', 'inc.device': 'עמדה', 'inc.detail': 'פירוט',
    'inc.t.created': 'התקרית נוצרה', 'inc.t.updated': 'התקרית עודכנה', 'inc.t.acknowledged': 'התקרית אושרה', 'inc.t.resolved': 'התקרית נפתרה', 'inc.t.reopened': 'התקרית נפתחה מחדש', 'inc.t.scanned': 'הסריקה הושלמה',
    'common.save': 'שמירה', 'common.delete': 'מחיקה', 'common.notied': '— לא משויך לעמדה —',
    'report.devices': 'מצאי עמדות', 'report.licensing': 'תאימות רישוי תוכנה', 'report.incidents': 'תקריות',
    'rep.desc.devices': 'כל עמדה בהרשאה שלך — שיוך, מערכת הפעלה, תקינות, בקרות והתראות נוכחיות.',
    'rep.desc.licensing': 'תוכנה מסחרית מותקנת מול הרישיונות הרשומים: מושבים, תפוגה וממצאים.',
    'rep.desc.incidents': 'כל התקריות בהרשאה שלך עם חומרה, מצב, אחראי וחותמות זמן.',
    'rep.open': 'פתח (הדפסה / PDF)', 'rep.csv': 'הורד CSV', 'rep.nocards': 'אין דוחות זמינים לתפקידך.',
    'rep.sched': 'דוחות מתוזמנים', 'rep.newsched': '＋ תזמון חדש', 'rep.runs': 'ריצות אחרונות',
    'rep.col.report': 'דוח', 'rep.col.cadence': 'תדירות', 'rep.col.next': 'ריצה הבאה', 'rep.col.delivery': 'משלוח',
    'rep.col.status': 'מצב', 'rep.col.when': 'מתי', 'rep.col.scope': 'הרשאה', 'rep.col.rows': 'שורות',
    'rep.hist': 'היסטוריה בלבד', 'rep.webhook': 'webhook', 'rep.on': 'פעיל', 'rep.off': 'כבוי',
    'rep.runnow': 'הרץ עכשיו', 'rep.enable': 'הפעל', 'rep.disable': 'השבת', 'rep.last': 'אחרונה',
    'rep.noruns': 'עדיין לא הופקו דוחות.', 'rep.nosched': 'אין עדיין תזמונים. צרו אחד כדי להפיק דוחות אוטומטית.',
    'rep.del.title': 'מחיקת תזמון', 'rep.del.body': 'להסיר את התזמון הזה ואת היסטוריית הדוחות שלו?',
    'rep.new.title': 'דוח מתוזמן חדש', 'rep.create': 'צור תזמון',
    'rep.f.hour': 'שעה (0–23)', 'rep.f.weekday': 'יום בשבוע', 'rep.f.monthday': 'יום בחודש (1–28)',
    'rep.f.recipients': 'נמעני דוא״ל (רשות, מופרדים בפסיק)', 'rep.f.webhook': 'שלח גם סיכום ל‑webhook שהוגדר',
    'rep.f.note': 'כל ריצה נשמרת כאן להורדה. בדוא״ל מצורף קובץ ה‑CSV; שניהם דורשים הגדרת הערוץ המתאים בהגדרות.',
    'rep.t.created': 'התזמון נוצר', 'rep.t.deleted': 'התזמון נמחק', 'rep.t.generated': 'הופק',
    'cad.daily': 'מדי יום', 'cad.weekly': 'שבועי', 'cad.monthly': 'חודשי', 'cad.at': 'בשעה',
    'cad.weekly.on': 'מדי שבוע ביום', 'cad.weekly.suffix': '', 'cad.monthly.on': 'מדי חודש ביום',
    'weekday.0': 'שני', 'weekday.1': 'שלישי', 'weekday.2': 'רביעי', 'weekday.3': 'חמישי', 'weekday.4': 'שישי', 'weekday.5': 'שבת', 'weekday.6': 'ראשון',
    'usr.add': '＋ הוסף משתמש', 'usr.new': 'משתמש חדש', 'usr.username': 'שם משתמש', 'usr.display': 'שם לתצוגה', 'usr.display.ph': 'רשות',
    'usr.password': 'סיסמה (10+ תווים)', 'usr.role': 'תפקיד', 'usr.scope': 'הרשאה', 'usr.create': 'צור משתמש', 'usr.scope.none': '(צרו אחת תחילה בארגון)',
    'usr.col.user': 'משתמש', 'usr.col.role': 'תפקיד', 'usr.col.scope': 'הרשאה', 'usr.col.last': 'כניסה אחרונה', 'usr.col.status': 'מצב',
    'usr.never': 'מעולם לא', 'usr.active': 'פעיל', 'usr.disabled': 'מושבת', 'usr.pw': 'סיסמה', 'usr.enable': 'הפעל', 'usr.disable': 'השבת', 'usr.none': 'אין משתמשים.',
    'usr.t.created': 'המשתמש נוצר', 'usr.t.deleted': 'המשתמש נמחק', 'usr.t.pwreset': 'הסיסמה אופסה', 'usr.confirm.del': 'למחוק את המשתמש הזה?', 'usr.prompt.pw': 'סיסמה חדשה (10+ תווים):',
    'org.addmuni': '＋ הוסף עירייה', 'org.addschool': '+ בית ספר', 'org.addlab': '+ מעבדה', 'org.del': 'מחק',
    'org.nolabs': 'אין עדיין מעבדות', 'org.noschools': 'אין עדיין בתי ספר', 'org.nomunis': 'אין עדיין עיריות.', 'org.devices': 'מחשבים', 'org.gateways': 'שערים',
    'org.unplaced': 'מחשבים לא משויכים — שייכו בדף כל מחשב',
    'org.p.muni': 'שם העירייה החדשה:', 'org.p.school': 'שם בית הספר החדש:', 'org.p.lab': 'שם המעבדה החדשה:',
    'org.c.muni': 'למחוק את העירייה? היא חייבת להיות ריקה.', 'org.c.school': 'למחוק את בית הספר? הוא חייב להיות ריק.', 'org.c.lab': 'למחוק את המעבדה? העבירו ממנה קודם את המחשבים.',
    'org.t.added': 'נוסף', 'org.t.deleted': 'נמחק',
    'gw.token': 'צור אסימון שער', 'gw.col.gateway': 'שער', 'gw.col.lab': 'מעבדה', 'gw.col.devices': 'מחשבים', 'gw.col.version': 'גרסה', 'gw.col.last': 'נראה לאחרונה', 'gw.col.status': 'מצב',
    'gw.online': 'מחובר', 'gw.offline': 'מנותק', 'gw.remove': 'הסר', 'gw.none': 'עדיין לא נרשמו שערים.', 'gw.never': 'מעולם לא',
    'gw.confirm.remove': 'להסיר את השער? המחשבים יישארו רשומים אך יאבדו את קישור הממסר.', 'gw.t.removed': 'השער הוסר',
    'fnd.confirmed_issue': 'בעיה מאומתת', 'fnd.potential_gap': 'פער אפשרי', 'fnd.verification_required': 'נדרש אימות', 'fnd.compliant': 'תקין', 'fnd.not_applicable': 'לא רלוונטי',
    'lic.addent': '＋ הוסף רישיון', 'lic.ents': 'רישיונות',
    'lic.col.product': 'מוצר', 'lic.col.installs': 'התקנות', 'lic.col.licence': 'רישיון', 'lic.col.status': 'מצב', 'lic.col.detail': 'פירוט',
    'lic.site': 'אתר', 'lic.seats': 'מושבים', 'lic.nofindings': 'לא זוהתה עדיין תוכנה מסחרית בהרשאה.',
    'lic.col.name': 'שם', 'lic.col.type': 'סוג', 'lic.col.seats': 'מושבים', 'lic.col.scope': 'הרשאה', 'lic.col.expires': 'תפוגה',
    'lic.edit': 'עריכה', 'lic.noents': 'לא נרשמו רישיונות. הוסיפו את מה שבית הספר מחזיק כדי להפוך "פערים אפשריים" לתקינים.',
    'lic.confirm.del': 'למחוק את הרישיון הזה?', 'lic.t.deleted': 'נמחק', 'lic.t.updated': 'עודכן', 'lic.t.added': 'הרישיון נוסף',
    'lic.p.seats': 'מושבים (0 = אתר/ללא הגבלה):', 'lic.p.expiry': 'תאריך תפוגה YYYY-MM-DD (ריק = ללא):',
    'lic.new': 'רישיון חדש', 'lic.create': 'צור רישיון', 'lic.f.name': 'שם', 'lic.f.product': 'מוצר', 'lic.f.other': '— אחר / ללא —',
    'lic.f.type': 'סוג רישיון', 'lic.f.seats': 'מושבים (0 = אתר / ללא הגבלה)', 'lic.f.covers': 'מכסה',
    'lic.covers.lab': 'מעבדה', 'lic.covers.school': 'בית ספר', 'lic.covers.municipality': 'עירייה', 'lic.covers.global': 'הכול (גלובלי)',
    'lic.f.which': 'איזה', 'lic.f.expires': 'תפוגה (רשות)', 'lic.f.notes': 'הערות', 'lic.scope.none': '(אין עדיין)',
    'img.register': '＋ רשום תמונה', 'img.col.image': 'תמונה', 'img.col.osver': 'מערכת הפעלה / גרסה', 'img.col.size': 'גודל', 'img.col.scope': 'הרשאה', 'img.col.source': 'מקור', 'img.col.sha': 'SHA-256', 'img.del': 'מחק',
    'img.none.manage': 'לא נרשמו תמונות — לחצו "רשום תמונה".', 'img.none': 'לא נרשמו תמונות.',
    'img.labtitle': 'תמונת יעד לכל מעבדה', 'img.col.school': 'בית ספר', 'img.col.lab': 'מעבדה', 'img.col.target': 'תמונת יעד', 'img.nolabs': 'אין מעבדות בהרשאה שלך.', 'img.none.target': '— ללא —',
    'img.t.updated': 'תמונת היעד עודכנה', 'img.t.deleted': 'התמונה נמחקה', 'img.t.registered': 'התמונה נרשמה',
    'img.del.title': 'מחיקת תמונה', 'img.del.body': 'להסיר את התמונה מהמאגר? למעבדות שמצביעות עליה תנוקה תמונת היעד.',
    'img.new': 'רישום תמונה', 'img.create': 'רשום', 'img.f.name': 'שם', 'img.f.os': 'מערכת הפעלה', 'img.f.version': 'גרסה',
    'img.f.source': 'מקור (כתובת URL או נתיב שיתוף)', 'img.f.size': 'גודל (בתים)', 'img.f.sha': 'SHA-256 (רשות)', 'img.f.scope': 'הרשאה', 'img.f.scopetarget': 'יעד ההרשאה', 'img.f.notes': 'הערות',
    'img.f.note': 'קובץ התמונה עצמו אינו מועלה — KEM שומר הפניה (מיקום + סכום ביקורת). הפצה דרך השער והדמיה מחדש עדיין לא מומשו.',
    'set.pw.title.self': 'שינוי הסיסמה שלך', 'set.pw.title.admin': 'שינוי סיסמת המנהל', 'set.pw.current': 'סיסמה נוכחית', 'set.pw.new': 'סיסמה חדשה (10+ תווים)', 'set.pw.update': 'עדכן סיסמה', 'set.t.pwupdated': 'הסיסמה עודכנה',
    'set.notif': 'התראות', 'set.notif.note': 'קבלו עדכון כשמשהו דורש טיפול. השתמשו ב‑webhook של צ׳אט, בדוא״ל או בשניהם.',
    'set.f.webhook': 'כתובת Webhook', 'set.notif.whichhelp': 'אילו כתובות webhook נתמכות?', 'set.f.email': 'דוא״ל אל (מופרד בפסיקים)',
    'set.f.smtphost': 'שרת SMTP', 'set.f.port': 'פורט', 'set.f.security': 'אבטחה', 'set.f.from': 'כתובת שולח', 'set.f.smtpuser': 'משתמש SMTP', 'set.f.smtppass': 'סיסמת SMTP', 'set.pwsaved': '•••••• (שמור — השאירו ריק לשמירה)',
    'set.notif.when': 'הודיעו לי כאשר', 'set.f.offline': 'סף ניתוק (שעות, 0 = כבוי)', 'set.save': 'שמור', 'set.sendtest': 'שלח בדיקה', 'set.t.testsent': 'התראת בדיקה נשלחה', 'set.t.saved': 'ההגדרות נשמרו',
    'set.auto': 'אוטומציה', 'set.auto.scan': 'סרוק כל מחשב לעדכוני Windows חסרים פעם ביום', 'set.auto.agent': 'עדכן את הסוכנים אוטומטית', 'set.auto.agent.sub': 'המחשבים יתעדכנו לגרסת הסוכן שבשרת בכניסה הבאה שלהם.',
    'set.ai': 'אבחון AI', 'set.ai.note': 'הפנו את KEM למודל מקומי תואם‑OpenAI (Ollama, llama.cpp, LM Studio, vLLM). "אבחן" בדף מחשב שולח רק את נתוני התקינות של המחשב — לעולם לא את המשתמש המחובר, כתובת ה‑IP או המספר הסריאלי — ומציג את המלצת המודל. המלצות בלבד; בדקו לפני פעולה.',
    'set.f.aiurl': 'כתובת בסיס של נקודת הקצה', 'set.f.aimodel': 'מודל', 'set.f.aikey': 'מפתח API (רשות)', 'set.ai.key.need': 'רק אם נקודת הקצה דורשת', 'set.ai.enable': 'הפעל אבחון AI', 'set.ai.enable.sub': 'השאירו את נקודת הקצה ב‑localhost או ברשת המקומית; מידע יוצא מ‑KEM רק לכתובת שלמעלה.', 'set.testconn': 'בדוק חיבור', 'set.ai.reachable': 'ה‑AI זמין',
    'set.notiflog': 'התראות אחרונות', 'set.col.time': 'זמן', 'set.col.device': 'מחשב', 'set.col.event': 'אירוע', 'set.col.message': 'הודעה', 'set.col.delivery': 'משלוח', 'set.notiflog.none': 'עדיין לא נשלח דבר.',
    'alert.offline_3d': 'מנותק יותר מ‑3 ימים', 'alert.low_disk': 'שטח דיסק נמוך בכונן {drive}', 'alert.defender_off': 'הגנת Defender בזמן אמת כבויה',
    'alert.av_sig': 'חתימות אנטי‑וירוס בנות {days} ימים', 'alert.fw_off': 'חומת אש כבויה ({name})', 'alert.sec_updates': '{n} עדכוני אבטחה חסרים', 'alert.reboot_pending': 'ממתין לאתחול',
    'cls.active': 'שיעור פעיל', 'cls.active.sub': 'בקרות הכיתה מופעלות', 'cls.start.msg': 'התחילו שיעור כדי לשלוט במחשבי המעבדה שלכם.',
    'cls.start': 'התחל שיעור', 'cls.end': 'סיים שיעור', 'cls.t.started': 'השיעור התחיל', 'cls.t.ended': 'השיעור הסתיים',
    'exam.locks.internet': 'אינטרנט חסום', 'exam.locks.usb': 'USB חסום', 'exam.locks.sites': '{n} אתרים מסוננים', 'exam.locks.none': 'ללא הגבלות',
    'exam.label': 'מבחן', 'exam.stations': 'עמדות', 'exam.by': 'מאת', 'exam.end': 'סיים מבחן',
    'exam.mode': 'מצב מבחן', 'exam.mode.desc': 'נעלו את עמדות המעבדה למבחן', 'exam.needclass': '(דורש שיעור פעיל)', 'exam.name.ph': 'שם המבחן',
    'exam.internet': 'אינטרנט', 'exam.usb': 'USB', 'exam.start': 'התחל מבחן', 'exam.nolabs': 'אין עדיין מעבדות עם עמדות להרצת מבחן.',
    'exam.t.ended': 'המבחן הסתיים', 'exam.t.started': 'המבחן התחיל',
    'sw.name': 'שם', 'sw.version': 'גרסה', 'sw.publisher': 'יצרן', 'sw.installed': 'הותקן', 'sw.peruser': 'למשתמש',
    'sw.programs': 'תוכנות', 'sw.collected': 'נאסף', 'sw.notcollected': 'עדיין לא נאסף', 'sw.none': 'אין מה להציג',
    'sw.uninstallsel': 'הסר נבחרות', 'sw.confirm': 'להסיר {n} תוכנות? פעולה זו מריצה את מסיר ההתקנה במחשב.', 'sw.t.queued': 'הסרה נשלחה עבור {n} תוכנות',
    'nav.packages': 'חבילות', 'nav.classes': 'כיתות', 'nav.fleetai': 'שאל AI', 'nav.exams': 'מבחנים מתוזמנים',
    'scr.view': 'צפה במסך', 'scr.freeze': 'הקפא קלט', 'scr.title': 'מסך העמדה', 'scr.refresh': 'צלם שוב',
    'scr.asking': 'מבקש מהעמדה את המסך…', 'scr.timeout': 'לא התקבל מסך (ייתכן שהעמדה לא מקוונת או שאין משתמש מחובר).',
    'scr.note': 'התלמיד המחובר רואה חיווי קצר “המסך שלך נצפה ע״י IT”. פריים אחד לכל צילום.',
    'scr.apply': 'החל', 'scr.freeze.title': 'הקפאת מקלדת ועכבר', 'scr.freeze.lock': 'נעל קלט',
    'scr.freeze.unlock': 'שחרר קלט', 'scr.freeze.note': 'משבית את המקלדת והעכבר של העמדה עד לשחרור.',
    'scr.unlock.note': 'מחזיר את השליטה במקלדת ובעכבר לתלמיד.', 'scr.locked': 'נעילת הקלט נשלחה', 'scr.unlocked': 'שחרור הקלט נשלח',
    'es.title': 'מבחנים מתוזמנים', 'es.sub': 'נעלו מעבדה למצב מבחן אוטומטית בשעה קבועה, ושחררו אותה בתום החלון',
    'es.new': '＋ תזמון חדש', 'es.name': 'שם המבחן', 'es.lab': 'מעבדה', 'es.when': 'מתי', 'es.locks': 'נעילות',
    'es.cadence': 'חזרה', 'es.once': 'פעם אחת', 'es.daily': 'כל יום', 'es.weekly': 'כל שבוע',
    'es.date': 'תאריך', 'es.weekday': 'יום', 'es.time': 'שעת התחלה', 'es.duration': 'משך (דקות)',
    'es.internet': 'חסום אינטרנט', 'es.usb': 'חסום USB', 'es.lan': 'שמור רשת מקומית',
    'es.create': 'צור תזמון', 'es.save': 'שמור', 'es.col.exam': 'מבחן', 'es.col.lab': 'מעבדה',
    'es.col.when': 'מתי', 'es.col.next': 'הרצה הבאה', 'es.col.status': 'מצב', 'es.none': 'אין עדיין מבחנים מתוזמנים.',
    'es.on': 'פעיל', 'es.off': 'כבוי', 'es.active': 'רץ כעת', 'es.enabled': 'מתוזמן', 'es.disabled': 'מושהה',
    'es.del': 'מחק', 'es.edit': 'עריכה', 'es.confirm.del': 'למחוק את המבחן המתוזמן?',
    'es.t.created': 'המבחן תוזמן', 'es.t.saved': 'התזמון עודכן', 'es.t.deleted': 'התזמון נמחק',
    'es.nolabs': 'צרו מעבדה תחילה.', 'es.for': 'ל‑{d} דק׳', 'es.locks.none': 'ללא נעילות',
    'es.wd.0': 'שני', 'es.wd.1': 'שלישי', 'es.wd.2': 'רביעי', 'es.wd.3': 'חמישי', 'es.wd.4': 'שישי', 'es.wd.5': 'שבת', 'es.wd.6': 'ראשון',
    'fa.title': 'שאל את ה‑AI על הצי', 'fa.sub': 'שאלות בשפה חופשית על המפרט והשימוש החי של כל עמדה',
    'fa.ph': 'למשל: לאילו עמדות יש מעבד חלש או זיכרון נמוך?', 'fa.ask': 'שאל', 'fa.asking': 'חושב…',
    'fa.presets': 'שאלות מהירות', 'fa.answer': 'תשובה', 'fa.model': 'נענה ע״י {m} על פני {n} עמדות',
    'fa.off': 'נקודת ה‑AI המקומית אינה מופעלת. מנהל יכול להגדיר אותה בהגדרות. התובנות שלמטה עובדות גם בלעדיה.',
    'fa.insights': 'תובנות צי', 'fa.insights.sub': 'מחושב ישירות מהמלאי — ללא צורך ב‑AI', 'fa.insights.none': 'אין עדיין עמדות מדווחות.',
    'fa.stations': 'עמדות', 'fa.allgood': 'אין',
    'fa.f.weak_cpu': 'מעבד חלש (≤2 ליבות)', 'fa.f.low_ram': 'זיכרון נמוך (<4 ג״ב)', 'fa.f.low_disk': 'דיסק נמוך (<10 ג״ב / <10% פנוי)',
    'fa.f.slow_nic': 'כרטיס רשת איטי (<1 Gbps)', 'fa.f.high_cpu': 'עומס מעבד (≥90%)', 'fa.f.high_mem': 'עומס זיכרון (≥90%)',
    'fa.f.high_disk': 'עומס דיסק (≥90%)', 'fa.f.offline': 'לא מקוון',
    'fa.q.weak': 'לאילו עמדות יש מעבד חלש או זיכרון נמוך?', 'fa.q.disk': 'אילו עמדות נמוכות במקום בדיסק?',
    'fa.q.nic': 'לאילו עמדות יש כרטיס רשת איטי (מתחת ל‑1 Gbps)?', 'fa.q.busy': 'לאילו עמדות יש כעת עומס מעבד, זיכרון או דיסק?',
    'fa.q.upgrade': 'אילו עמדות כדאי לשדרג או להחליף ראשונות, ולמה?',
    'cl.title': 'כיתות', 'cl.sub': 'קבצו עמדות לכיתה והעלו אחת לעמדת מורה שהשאר מתחברים דרכה',
    'cl.new': '＋ כיתה חדשה', 'cl.name': 'שם הכיתה', 'cl.lab': 'מעבדה', 'cl.lab.any': '— כל מעבדה —',
    'cl.members': 'עמדות', 'cl.members.help': 'בחרו את העמדות בכיתה זו.', 'cl.create': 'צור כיתה',
    'cl.col.name': 'כיתה', 'cl.col.members': 'עמדות', 'cl.col.teacher': 'עמדת מורה', 'cl.col.status': 'מצב',
    'cl.none': 'אין עדיין כיתות.', 'cl.nomembers': 'אין עמדות', 'cl.del': 'מחק', 'cl.confirm.del': 'למחוק כיתה זו?',
    'cl.t.created': 'הכיתה נוצרה', 'cl.t.deleted': 'הכיתה נמחקה', 'cl.t.saved': 'הכיתה עודכנה',
    'cl.edit': 'עריכה', 'cl.setteacher': 'הגדר עמדת מורה', 'cl.dissolve': 'פרק',
    'cl.active': 'פעיל · {n} הופנו מחדש', 'cl.inactive': 'ישירות לשרת', 'cl.gw.online': 'ממסר מקוון', 'cl.gw.offline': 'ממסר במצב לא מקוון',
    'cl.promote.title': 'קידום עמדת מורה', 'cl.promote.pick': 'עמדת מורה',
    'cl.promote.addr': 'כתובת עמדת המורה (IP או שם ברשת)', 'cl.promote.addr.help': 'השאירו ריק כדי להשתמש בשם המחשב. חברי הכיתה מתחברים אל http://<כתובת>:<פורט>.',
    'cl.promote.port': 'פורט הממסר', 'cl.promote.submit': 'קדם והפנה מחדש',
    'cl.promote.note': 'שאר העמדות יתחברו מחדש דרך עמדה זו. אם היא לא מקוונת, הן יחזרו אוטומטית לשרת המרכזי.',
    'cl.t.promoted': 'עמדת מורה הוגדרה — {n} עמדות הופנו מחדש', 'cl.t.dissolved': 'עמדת המורה פורקה',
    'cl.dissolve.confirm': 'להחזיר את כל העמדות לשרת המרכזי ולעצור את הממסר?',
    'cl.needmembers': 'הוסיפו לפחות עמדה אחת תחילה.', 'cl.teacher.badge': '★ מורה',
    'pkg.title': 'חבילות תוכנה', 'pkg.sub': 'מערכי תוכנה רצויים לעמדות — התקנת המערך, ואופציונלית הסרת השאר',
    'pkg.new': '＋ חבילה חדשה', 'pkg.name': 'שם', 'pkg.items': 'אפליקציות (אחת בשורה)',
    'pkg.items.help': 'מבנה:  תווית | התאמה | winget:Id   או   תווית | התאמה | url:https://…   — "התאמה" = טקסט שמופיע בשם המותקן. השאירו את החלק השלישי ריק כדי רק לשמור (למשל  Windows | windows | ).',
    'pkg.create': 'צור חבילה', 'pkg.scope': 'הרשאה', 'pkg.scopetarget': 'יעד ההרשאה', 'pkg.notes': 'הערות',
    'pkg.col.name': 'חבילה', 'pkg.col.scope': 'הרשאה', 'pkg.col.items': 'אפליקציות', 'pkg.del': 'מחק', 'pkg.none': 'אין עדיין חבילות.',
    'pkg.confirm.del': 'למחוק את החבילה?', 'pkg.t.created': 'החבילה נוצרה', 'pkg.t.deleted': 'החבילה נמחקה',
    'pkg.applybtn': 'החל חבילה', 'pkg.apply.title': 'החלת חבילה', 'pkg.apply': 'החל', 'pkg.pkg': 'חבילה',
    'pkg.removeextras': 'הסר גם אפליקציות שאינן בחבילה (שומר על Windows, מנהלי התקנים, אבטחה, רכיבי ריצה)',
    'pkg.previewhint': 'בחרו חבילה כדי לצפות בתוכנית.', 'pkg.note': 'צפו תחילה. ההתקנות וההסרות ירוצו במחשב כשהסוכן יעבד אותן.',
    'pkg.install': 'התקנה', 'pkg.remove': 'הסרה', 'pkg.keep': 'שמירה', 'pkg.protected': 'מוגן',
    'pkg.t.applied': 'נשלחו {n} פעולות', 'pkg.none.apply': 'לא הוגדרו חבילות — צרו אחת תחילה.', 'pkg.badline': 'שורה שגויה (השתמשו ב‑תווית | התאמה | winget:Id או url:…): ',
    'pkg.bl.title': 'בסיס מעבדה', 'pkg.bl.sub': 'הגדירו חבילה כסטנדרט של מעבדה — עמדות חדשות יתקינו אותה אוטומטית, ותוכלו לראות אילו עמדות סטו.',
    'pkg.bl.lab': 'מעבדה', 'pkg.bl.pkg': 'בסיס', 'pkg.bl.none': '— ללא —', 'pkg.bl.remove': 'הסר עודפים',
    'pkg.bl.auto': 'אוטומטי בהרשמה', 'pkg.bl.auto.help': 'מתקין את המערך (לעולם לא מסיר) בפעם הראשונה שעמדה נרשמת.',
    'pkg.bl.col.status': 'מצב', 'pkg.bl.apply': 'החל על כולן', 'pkg.bl.saved': 'הבסיס עודכן', 'pkg.bl.nolabs': 'אין עדיין מעבדות.',
    'pkg.bl.compliant': 'כולן תואמות', 'pkg.bl.drift': '{d} מתוך {n} סטו', 'pkg.bl.empty': 'אין עמדות',
    'pkg.bl.applytitle': 'החלת הבסיס על המעבדה', 'pkg.bl.applybtn': 'עדכן עמדות שסטו',
    'pkg.bl.willfix': '{n} עמדות יעודכנו:', 'pkg.bl.allok': 'כל העמדות כבר תואמות לבסיס.',
    'pkg.bl.queued': 'נשלחו עדכונים ל‑{n} עמדות', 'pkg.bl.ok': 'אישור',
  },
};

// Localize a device alert from its stable code + params (English `text` is the fallback and identity).
function alertLabel(a) {
  if (a && a.code && LANG !== 'en' && I18N[LANG] && I18N[LANG]['alert.' + a.code]) {
    return t('alert.' + a.code).replace(/\{(\w+)\}/g, (m, k) => (a.params && a.params[k] != null ? a.params[k] : m));
  }
  return a ? (a.text || '') : '';
}
let LANG = (() => { try { return localStorage.getItem('kem.lang') === 'he' ? 'he' : 'en'; } catch { return 'en'; } })();
const t = (key) => (I18N[LANG] && I18N[LANG][key]) || I18N.en[key] || key;

function applyStaticI18n() {
  $$('[data-i18n]').forEach((el) => { el.textContent = t(el.dataset.i18n); });
  $$('[data-i18n-ph]').forEach((el) => { el.setAttribute('placeholder', t(el.dataset.i18nPh)); });
  document.title = t('app.title');
  $$('.langsw [data-lang]').forEach((b) => b.classList.toggle('on', b.dataset.lang === LANG));
}

function applyDir() {
  document.documentElement.lang = LANG;
  document.documentElement.dir = LANG === 'he' ? 'rtl' : 'ltr';
}

function setLang(lang) {
  LANG = lang === 'he' ? 'he' : 'en';
  try { localStorage.setItem('kem.lang', LANG); } catch { /* private mode */ }
  applyDir();
  applyStaticI18n();
  if (state.me) route();  // re-render the current view in the new language
}

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
    case 'uninstall_software': return p.name ? p.name : `winget: ${p.package_id}`;
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
    <footer><button type="button" class="btn" data-close>${t('common.cancel')}</button>
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
  distribute_file(ids) {
    modal({
      title: 'Distribute a file', submit: 'Send file',
      body: `${targetLine(ids)}
        <label>File URL<input name="url" required placeholder="https://files.example.com/handout.pdf" spellcheck="false"></label>
        <label>Destination folder<input name="dest" class="mono" required placeholder="C:\\Lab\\Handouts"></label>
        <label>Save as (optional)<input name="filename" placeholder="leave blank to keep the URL's file name"></label>
        <label>SHA-256 (optional)<input name="sha256" class="mono" placeholder="64 hex — verifies the download"></label>
        <label class="check"><input type="checkbox" name="overwrite"> Overwrite if a file with that name already exists</label>
        <p class="note">The agent downloads the file over TLS as SYSTEM, checks the SHA-256 if given, and places it in the folder (created if missing). System folders are blocked.</p>`,
      onSubmit: (f) => queue(ids, 'distribute_file', { url: f.url.value.trim(), dest: f.dest.value.trim(), filename: f.filename.value.trim(), sha256: f.sha256.value.trim(), overwrite: f.overwrite.checked }),
    });
  },
  set_app_policy(ids) {
    modal({
      title: 'Application allowlist (AppLocker)', submit: 'Apply policy', danger: true,
      body: `${targetLine(ids)}
        <label>Mode<select name="mode">
          <option value="audit">Audit — log blocked apps only (safe to start)</option>
          <option value="enforce">Enforce — actually block apps not on the list</option>
          <option value="off">Off — remove the allowlist</option></select></label>
        <label>Allowed apps — one per line<textarea name="rules" spellcheck="false" style="min-height:120px;font-family:ui-monospace,Consolas,monospace;font-size:13px" placeholder="file: chrome.exe&#10;path: C:\\Program Files\\MyApp\\*&#10;path: %PROGRAMFILES%\\Zoom\\*"></textarea></label>
        <p class="note">Windows and everything in <b>Program Files</b> stay allowed automatically. <b>Enforce blocks every other executable</b> — start in Audit and review first. Needs Windows Enterprise/Education + the App Identity service. <b>Not yet tested on real hardware — try it on a spare PC before a lab.</b></p>`,
      onSubmit: (f) => {
        const mode = f.mode.value;
        let rules = [];
        if (mode !== 'off') {
          rules = f.rules.value.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => {
            const m = l.match(/^(path|file|filename)\s*:\s*(.+)$/i);
            if (m) return { type: m[1].toLowerCase() === 'path' ? 'path' : 'filename', value: m[2].trim() };
            return { type: /^([A-Za-z]:\\|%|\*)/.test(l) ? 'path' : 'filename', value: l };
          });
          if (!rules.length) throw new Error('Add at least one allowed app, or choose Off.');
        }
        return queue(ids, 'set_app_policy', { mode, rules });
      },
    });
  },
  launch_app(ids) {
    modal({
      title: 'Launch an app or web page', submit: 'Launch',
      body: `${targetLine(ids)}
        <label class="option"><input type="radio" name="target" value="app" checked><div><b>Program</b><span>Full path to a program on the station</span></div></label>
        <label class="option"><input type="radio" name="target" value="url"><div><b>Web page</b><span>Opens in the default browser</span></div></label>
        <label>Program path or URL<input name="value" required spellcheck="false" placeholder="C:\\Program Files\\App\\app.exe   or   https://exam.school.org"></label>
        <label>Arguments (programs only, optional)<input name="args" spellcheck="false"></label>
        <p class="note">Runs in the signed-in student's session (not as admin). Nothing happens if no one is signed in.</p>`,
      onSubmit: (f) => queue(ids, 'launch_app', { target: f.querySelector('[name=target]:checked').value, value: f.value.value.trim(), args: f.args.value.trim() }),
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
  set_hostname(ids) {
    if (ids.length !== 1) { toast(t('dev.rename.one'), true); return; }
    const d = state.devices.find((x) => x.id === ids[0]) || { hostname: '' };
    modal({
      title: t('dev.rename.title').replace('{host}', d.hostname), submit: t('dev.rename.submit'), danger: true,
      body: `<label>${t('dev.rename.label')}<input name="hostname" class="mono" maxlength="15" autocomplete="off" required placeholder="LAB204-PC01"></label>
        <p class="note">${t('dev.rename.help')}</p>
        <label class="check"><input type="checkbox" name="reboot" checked> ${t('dev.rename.reboot')}</label>
        <label><span>${t('dev.rename.confirm').replace('{host}', '')}<b class="mono">${esc(d.hostname)}</b></span><input name="confirm" autocomplete="off" required></label>`,
      onSubmit: (f) => {
        const h = f.hostname.value.trim();
        if (!/^(?!-)(?!\d+$)[A-Za-z0-9-]{1,15}(?<!-)$/.test(h)) throw new Error(t('dev.rename.bad'));
        return queue(ids, 'set_hostname', { hostname: h, reboot: f.reboot.checked }, f.confirm.value);
      },
    });
  },
  set_local_admin_password(ids) {
    const form = modal({
      title: t('dev.setpw.title'), submit: t('dev.setpw.submit'), danger: true,
      body: `${targetLine(ids)}
        <label>${t('dev.setpw.acct')}<select name="which"><option value="managed">${t('dev.setpw.acctdefault')}</option><option value="other">${t('dev.setpw.acctother')}</option></select></label>
        <label data-acctname class="hidden">${t('dev.setpw.acctname')}<input name="account" class="mono" maxlength="20" autocomplete="off" placeholder="localadmin"></label>
        <label>${t('dev.setpw.pw')}<input name="pw" type="password" autocomplete="new-password" required></label>
        <label>${t('dev.setpw.pw2')}<input name="pw2" type="password" autocomplete="new-password" required></label>
        <button type="button" class="btn small" id="genpw">${t('dev.setpw.gen')}</button>
        <p class="note">${t('dev.setpw.help')}</p>`,
      onSubmit: (f) => {
        const pw = f.pw.value;
        if (pw.length < 8) throw new Error(t('dev.setpw.short'));
        if (pw !== f.pw2.value) throw new Error(t('dev.setpw.mismatch'));
        const account = f.which.value === 'other' ? (f.account.value || '').trim() : '';
        return queue(ids, 'set_local_admin_password', account ? { account, password: pw } : { password: pw })
          .then(() => toast(t('dev.setpw.t.queued')));
      },
    });
    form.which.onchange = () => $('[data-acctname]', form).classList.toggle('hidden', form.which.value !== 'other');
    $('#genpw', form).onclick = () => {
      const a = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%*';
      const buf = new Uint32Array(18); crypto.getRandomValues(buf);
      const gen = [...buf].map((n) => a[n % a.length]).join('');
      form.pw.value = gen; form.pw2.value = gen;
      form.pw.type = form.pw2.type = 'text';
    };
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
    audit: viewAudit, settings: viewSettings, org: viewOrg, users: viewUsers, gateways: viewGateways, licensing: viewLicensing, incidents: viewIncidents, reports: viewReports, images: viewImages, packages: viewPackages, classes: viewClasses, fleetai: viewFleetAI, exams: viewExamSchedules };
  const needs = { org: 'manage_org', users: 'manage_users', gateways: 'manage_gateways', enroll: 'manage_tokens', audit: 'view_audit', licensing: 'view_licensing', incidents: 'view_incidents', reports: 'view_reports', images: 'view_images', packages: 'view_packages' };
  if (needs[name] && !cap(needs[name])) { location.hash = '#/devices'; return; }
  (views[name] || viewDevices)();
}

function every(fn, ms) { refreshCurrent = fn; state.timer = setInterval(() => { if (!document.hidden) fn(); }, ms); }

// ------------------------------------------------------------------ devices list
async function viewDevices() {
  const bulkActs = ['block_internet', 'unblock_internet', 'install_software', 'distribute_file', 'install_updates',
    'set_web_filter', 'usb_storage', 'set_app_policy', 'launch_app', 'send_message', 'lock_session', 'run_script', 'defender_scan', 'reboot'];
  view.innerHTML = `
    <div class="page-head"><div><h1>${t('devices.title')}</h1><p class="sub">${state.me.role === 'teacher' ? t('devices.sub.lab') : t('devices.sub.server')}${state.me.scope_label && state.me.role !== 'superadmin' ? ' · ' + esc(state.me.scope_label) : ''}</p></div>
      ${cap('manage_tokens') ? `<a class="btn primary" href="#/enroll">${t('devices.add')}</a>` : ''}</div>
    <div id="classbar"></div>
    <div id="exambar"></div>
    <section class="tiles" id="tiles"></section>
    <div class="toolbar">
      <input id="q" type="search" placeholder="${esc(t('devices.search'))}" value="${esc(state.filter.q)}">
      <select id="fgroup"></select>
    </div>
    <div class="bulkbar hidden" id="bulk">
      <b id="bulkcount"></b>
      ${bulkActs.map((a) => `<button class="btn small" data-act="${a}">${t('act.' + a)}</button>`).join('')}
      <button class="link small" id="bulkclear" style="margin-inline-start:auto">${t('bulk.clear')}</button>
    </div>
    <div id="grid" class="appgrid"></div>`;

  $('#q').oninput = (e) => { state.filter.q = e.target.value; state.devGrid && state.devGrid.setGridOption('rowData', filtered()); };
  $('#fgroup').onchange = (e) => { state.filter.group = e.target.value; renderDevices(); };
  $('#bulkclear').onclick = () => { state.selected.clear(); state.devGrid && state.devGrid.deselectAll(); renderDevices(); };
  const allowedCmds = new Set(state.me.capabilities.commands || []);
  $$('#bulk [data-act]').forEach((b) => { if (!allowedCmds.has(b.dataset.act)) b.remove(); else b.onclick = () => ACTIONS[b.dataset.act]([...state.selected]); });
  if (state.me.role === 'teacher') renderClassBar();
  if (cap('manage_exams')) renderExamBar();

  const side = (typeof LANG !== 'undefined' && LANG === 'he') ? 'right' : 'left';
  const cols = [
    { headerName: '', checkboxSelection: true, headerCheckboxSelection: true, headerCheckboxSelectionFilteredOnly: true, width: 46, maxWidth: 46, pinned: side, sortable: false, filter: false, resizable: false, suppressMovable: true, lockPosition: true },
    { headerName: t('col.device'), field: 'hostname', flex: 2.2, minWidth: 220, cellRenderer: gridHtml((d) => `<span class="dot ${d.online ? 'on' : ''}" title="${d.online ? 'Online' : 'Offline'}"></span><span class="host"><a href="#/device/${esc(d.id)}"><b>${deviceIcon(d.chassis)} ${esc(d.hostname)}</b></a><small>${esc(d.model || '')}${placeText(d) ? ' · ' + esc(placeText(d)) : ''}${d.group ? ' · ' + esc(d.group) : ''}</small></span>`) },
    { headerName: t('col.user'), valueGetter: (p) => (p.data.user || '').split('\\').pop(), cellRenderer: gridHtml((d) => dash((d.user || '').split('\\').pop())) },
    { headerName: t('col.os'), valueGetter: (p) => p.data.os, cellRenderer: gridHtml((d) => `${dash((d.os || '').replace('Microsoft ', ''))}${d.os_version ? ` <span class="muted">${esc(d.os_version)}</span>` : ''}`) },
    { headerName: t('col.ip'), valueGetter: (p) => (p.data.ips || [])[0] || '', cellClass: 'mono' },
    { headerName: t('col.cpu'), valueGetter: (p) => (p.data.online ? p.data.cpu : null), cellRenderer: gridHtml((d) => meter(d.online ? d.cpu : null)), maxWidth: 120, filter: false },
    { headerName: t('col.ram'), valueGetter: (p) => (p.data.online ? p.data.mem : null), cellRenderer: gridHtml((d) => meter(d.online ? d.mem : null)), maxWidth: 120, filter: false },
    { headerName: t('col.disk'), valueGetter: (p) => p.data.disk, cellRenderer: gridHtml((d) => meter(d.disk)), maxWidth: 120, filter: false },
    { headerName: t('col.lastseen'), field: 'last_seen', sort: 'desc', cellRenderer: gridHtml((d) => `<span class="muted small">${ago(d.last_seen)}</span>`), maxWidth: 150 },
    { headerName: t('col.status'), sortable: false, filter: false, flex: 1.6, minWidth: 150, cellRenderer: gridHtml((d) => deviceStatusPills(d)) },
  ];
  state.devGrid = makeGrid($('#grid'), {
    columnDefs: cols, rowData: [], rowSelection: 'multiple', rowHeight: 56,
    getRowId: (p) => p.data.id, noRows: `<span class="muted">${t('devices.none')}</span>`,
    onSelectionChanged: (e) => {
      state.selected = new Set(e.api.getSelectedRows().map((d) => d.id));
      $('#bulk').classList.toggle('hidden', !state.selected.size);
      $('#bulkcount').textContent = `${state.selected.size} ${t('bulk.selected')}`;
    },
  });

  const load = async () => { state.devices = await api('/api/devices'); renderDevices(); };
  await load().catch((e) => toast(e.message, true));
  every(load, 10000);
}

function deviceStatusPills(d) {
  return `${d.isolated ? `<span class="pill crit">${t('pill.blocked')}</span>` : ''}${d.busy ? `<span class="pill blue">${t('pill.working')}</span>` : ''}` +
    `${d.web_filter ? `<span class="pill" title="Web filter: ${d.web_filter} domains blocked">${t('pill.filter')}</span>` : ''}` +
    `${d.usb && d.usb !== 'allow' ? `<span class="pill" title="USB storage ${esc(USB_LABEL[d.usb])}">🔌 USB ${d.usb === 'block' ? 'off' : 'RO'}</span>` : ''}` +
    `${d.alerts.filter((a) => a.level !== 'info').slice(0, 2).map((a) => `<span class="pill ${a.level}" title="${esc(alertLabel(a))}">${esc(alertLabel(a))}</span>`).join('')}` +
    `${!d.isolated && !d.alerts.some((a) => a.level !== 'info') ? `<span class="pill ok">${t('pill.healthy')}</span>` : ''}`;
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
  const tiles = [['all', t('tile.all'), ''], ['online', t('tile.online'), '<span class="dot on"></span>'], ['offline', t('tile.offline'), '<span class="dot"></span>'],
    ['isolated', t('tile.isolated'), '⛔'], ['updates', t('tile.updates'), '⟳'], ['alerts', t('tile.alerts'), '⚠']];
  $('#tiles').innerHTML = tiles.map(([k, l, ic]) => `<button class="tile ${state.filter.status === k ? 'on' : ''}" data-k="${k}"><div class="l">${ic}${l}</div><div class="n">${counts[k]}</div></button>`).join('');
  $$('#tiles .tile').forEach((t) => (t.onclick = () => { state.filter.status = state.filter.status === t.dataset.k ? 'all' : t.dataset.k; renderDevices(); }));

  const groups = [...new Set(all.map((d) => d.group).filter(Boolean))].sort();
  const gsel = $('#fgroup');
  gsel.innerHTML = `<option value="">${t('devices.allgroups')}</option>` + groups.map((g) => `<option ${g === state.filter.group ? 'selected' : ''}>${esc(g)}</option>`).join('');
  gsel.classList.toggle('hidden', !groups.length);

  if (state.devGrid) state.devGrid.setGridOption('rowData', filtered());
}

async function renderClassBar() {
  const bar = $('#classbar');
  if (!bar) return;
  let info;
  try { info = await api('/api/class/active'); } catch { return; }
  const active = info.active;
  bar.innerHTML = `<div class="classbar ${active ? 'on' : ''}">
    <span>${active ? `<b>${t('cls.active')}</b> — ${t('cls.active.sub')}${active.note ? ' · ' + esc(active.note) : ''}` : t('cls.start.msg')}</span>
    <button class="btn ${active ? '' : 'primary'} small" id="classtoggle">${active ? t('cls.end') : t('cls.start')}</button></div>`;
  $('#classtoggle').onclick = async () => {
    try {
      if (active) await api('/api/class/stop', { method: 'POST' });
      else await api('/api/class/start', { method: 'POST', body: {} });
      toast(active ? t('cls.t.ended') : t('cls.t.started'));
      renderClassBar();
    } catch (e) { toast(e.message, true); }
  };
}

const EXAM_LOCKS = (e) => [e.lock_internet ? t('exam.locks.internet') : null, e.lock_usb ? t('exam.locks.usb') : null,
  (e.web_filter && e.web_filter.length) ? t('exam.locks.sites').replace('{n}', e.web_filter.length) : null].filter(Boolean).join(' · ') || t('exam.locks.none');

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
      <span>🔒 <b>${t('exam.label')}: ${esc(e.name)}</b> — ${esc(e.lab_name)} · ${e.stations} ${t('exam.stations')}
        · ${EXAM_LOCKS(e)} · ${t('exam.by')} ${esc(e.started_by)} ${ago(e.started)}</span>
      <button class="btn small" data-stop="${esc(e.id)}">${t('exam.end')}</button>
    </div>`).join('');

  const labPicker = isTeacher ? '' :
    `<select name="lab_id" required>${[...labs].map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join('')}</select>`;
  const startHtml = canStart ? `
    <form class="classbar exam" id="examstart">
      <span>🎓 <b>${t('exam.mode')}</b> — ${t('exam.mode.desc')}${isTeacher ? ' ' + t('exam.needclass') : ''}:</span>
      ${labPicker}
      <input name="name" placeholder="${esc(t('exam.name.ph'))}" maxlength="120" style="flex:1;min-width:120px">
      <label class="chk"><input type="checkbox" name="li" checked> ${t('exam.internet')}</label>
      <label class="chk"><input type="checkbox" name="lu" checked> ${t('exam.usb')}</label>
      <button class="btn primary small" type="submit">${t('exam.start')}</button>
    </form>` :
    (active.length ? '' : `<div class="classbar exam"><span class="muted">${t('exam.nolabs')}</span></div>`);

  bar.innerHTML = activeHtml + startHtml;

  bar.querySelectorAll('[data-stop]').forEach((b) => (b.onclick = async () => {
    b.disabled = true;
    try { const r = await api(`/api/exams/${b.dataset.stop}/stop`, { method: 'POST' }); toast(`${t('exam.t.ended')} · ${r.commands}`); renderExamBar(); }
    catch (e) { toast(e.message, true); b.disabled = false; }
  }));
  const form = $('#examstart');
  if (form) form.onsubmit = async (ev) => {
    ev.preventDefault();
    const body = { name: form.name.value.trim(), lock_internet: form.li.checked, lock_usb: form.lu.checked };
    if (!isTeacher) body.lab_id = form.lab_id.value;
    try { const r = await api('/api/exams/start', { method: 'POST', body }); toast(`${t('exam.t.started')} · ${r.stations} ${t('exam.stations')}`); renderExamBar(); }
    catch (e) { toast(e.message, true); }
  };
}

// ------------------------------------------------------------------ device page
async function viewDevice(id) {
  const TABS = [['commands', 'Activity'], ['updates', 'Windows updates'], ['software', 'Installed software'], ['processes', 'Processes'], ['services', 'Services']];
  const ui = { tab: 'commands', softQ: '', softAt: null, updSig: null, open: new Set(), loaded: {}, busy: {}, sel: new Set(), softSel: new Set(),
    procQ: '', procSort: 'mem', procs: null, procAt: null, svcQ: '', svcFilter: 'all', svcs: null, svcAt: null };
  view.innerHTML = `<p><a href="#/devices">← All devices</a></p><div id="dhead"></div><div id="dbanner"></div><div class="cards" id="dcards"></div><div id="aicard"></div>
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

  function renderAI() {
    const el = $('#aicard');
    if (!el) return;
    if (!cap('run_diagnostics')) { el.innerHTML = ''; return; }
    const has = dev.ai_diagnosis;
    el.innerHTML = `<div class="card pad"><div class="row" style="justify-content:space-between;align-items:center">
        <h2>AI diagnosis</h2><button class="btn small" id="airun">${has ? 'Re-run' : 'Run AI diagnosis'}</button></div>
      <div id="aiout">${has
        ? `<div class="muted small">${ago(dev.ai_diagnosis_at)} · last run</div><pre class="aiout-text">${esc(dev.ai_diagnosis)}</pre>`
        : '<p class="muted">Ask a local model to review this device\'s health and suggest fixes. Only health data is sent — never the signed-in user, IP or serial. Configure the endpoint in Settings.</p>'}</div></div>`;
    $('#airun').onclick = async () => {
      const b = $('#airun'); b.disabled = true;
      $('#aiout').innerHTML = '<div class="muted"><span class="spin"></span> Asking the model…</div>';
      try {
        const r = await api(`/api/devices/${id}/diagnose`, { method: 'POST' });
        dev.ai_diagnosis = r.diagnosis; dev.ai_diagnosis_at = r.at;
        $('#aiout').innerHTML = `<div class="muted small">just now · ${esc(r.model)}</div><pre class="aiout-text">${esc(r.diagnosis)}</pre>
          <details class="help"><summary>Exactly what was sent to the model</summary><pre class="aiout-text">${esc(JSON.stringify(r.context_sent, null, 2))}</pre></details>
          <p class="note">Suggestions only — review before acting. KEM never runs anything automatically.</p>`;
      } catch (e) { $('#aiout').innerHTML = `<div class="banner crit">⚠ ${esc(e.message)}</div>`; }
      finally { b.disabled = false; }
    };
  }

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
    const canUn = (state.me.capabilities.commands || []).includes('uninstall_software');
    const sw = (dev.software || []).filter((s) => !ui.softQ || `${s.name} ${s.publisher}`.toLowerCase().includes(ui.softQ));
    const names = new Set((dev.software || []).map((s) => s.name));
    [...ui.softSel].forEach((n) => { if (!names.has(n)) ui.softSel.delete(n); });
    $('#softmeta').textContent = dev.software_at ? `${dev.software.length} ${t('sw.programs')} · ${t('sw.collected')} ${ago(dev.software_at)}` : t('sw.notcollected');
    const cols = canUn ? 5 : 4;
    const head = `<tr>${canUn ? '<th style="width:30px"><input type="checkbox" id="swall" aria-label="select all"></th>' : ''}<th>${t('sw.name')}</th><th>${t('sw.version')}</th><th>${t('sw.publisher')}</th><th>${t('sw.installed')}</th></tr>`;
    const rows = sw.map((s) => `<tr>${canUn ? `<td class="sel"><input type="checkbox" data-sw="${esc(s.name)}" ${ui.softSel.has(s.name) ? 'checked' : ''}></td>` : ''}<td>${esc(s.name)}${s.scope === 'user' ? ` <span class="pill">${t('sw.peruser')}</span>` : ''}</td><td class="mono small">${dash(s.version)}</td><td class="small">${dash(s.publisher)}</td><td class="small muted">${dash(s.installed)}</td></tr>`).join('')
      || `<tr><td colspan="${cols}" class="empty">${t('sw.none')}</td></tr>`;
    const bulk = (canUn && ui.softSel.size) ? `<div class="bulkbar" style="margin-bottom:10px"><b>${ui.softSel.size}</b><button class="btn small danger" id="swuninstall">🗑 ${t('sw.uninstallsel')}</button><button class="link small" id="swclear" style="margin-inline-start:auto">${t('bulk.clear')}</button></div>` : '';
    $('#softlist').innerHTML = bulk + `<table class="grid"><thead>${head}</thead><tbody>${rows}</tbody></table>`;
    if (!canUn) return;
    const all = $('#swall');
    if (all) { all.checked = sw.length > 0 && sw.every((s) => ui.softSel.has(s.name)); all.onchange = () => { sw.forEach((s) => (all.checked ? ui.softSel.add(s.name) : ui.softSel.delete(s.name))); renderSoftware(); }; }
    $$('#softlist [data-sw]').forEach((c) => (c.onchange = () => { c.checked ? ui.softSel.add(c.dataset.sw) : ui.softSel.delete(c.dataset.sw); renderSoftware(); }));
    if ($('#swclear')) $('#swclear').onclick = () => { ui.softSel.clear(); renderSoftware(); };
    if ($('#swuninstall')) $('#swuninstall').onclick = () => {
      const sel = [...ui.softSel];
      if (!sel.length) return;
      modal({
        title: t('sw.uninstallsel'), submit: t('sw.uninstallsel'), danger: true,
        body: `<p class="note">${t('sw.confirm').replace('{n}', sel.length)}</p>
          <ul class="checklist">${sel.map((n) => `<li>${esc(n)}</li>`).join('')}</ul>`,
        onSubmit: async () => {
          for (const n of sel) await api('/api/commands', { method: 'POST', body: { device_ids: [id], type: 'uninstall_software', params: { name: n } } });
          toast(t('sw.t.queued').replace('{n}', sel.length)); ui.softSel.clear(); refreshCurrent();
        },
      });
    };
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
        ${allowedHas('request_screenshot') ? `<button class="btn" id="viewscreen">🖥 ${t('scr.view')}</button>` : ''}
        ${allowedHas('lock_input') ? `<button class="btn" id="freezeinput">🧊 ${t('scr.freeze')}</button>` : ''}
        ${cap('manage_packages') ? `<button class="btn" id="applypkg">📦 ${t('pkg.applybtn')}</button>` : ''}
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
    if ($('#applypkg')) $('#applypkg').onclick = () => applyPackageModal(id);
    if ($('#viewscreen')) $('#viewscreen').onclick = () => viewScreenModal(id, dev.hostname);
    if ($('#freezeinput')) $('#freezeinput').onclick = () => freezeInputModal(id);
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
    $('#dbanner').innerHTML = alerts.map((a) => `<div class="banner ${a.level}">⚠ ${esc(alertLabel(a))}</div>`).join('');

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
      <div class="danger-item"><div><b>${t('dev.rename')}</b><p>${t('dev.rename.help')}</p></div><button class="btn" data-act="set_hostname">${t('dev.rename')}…</button></div>
      <div class="danger-item"><div><b>${t('dev.setpw')}</b><p>${t('dev.setpw.help')}</p></div><button class="btn" data-act="set_local_admin_password">${t('dev.setpw')}…</button></div>
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
    renderAI();

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
  view.innerHTML = `<div class="page-head"><div><h1>${t('page.activity.title')}</h1><p class="sub">${t('page.activity.sub')}</p></div></div><div class="card" id="acts"><div class="empty">Loading…</div></div>`;
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
  view.innerHTML = `<div class="page-head"><div><h1>${t('page.audit.title')}</h1><p class="sub">${t('page.audit.sub')}</p></div></div><div id="aud" class="appgrid tall"></div>`;
  const cols = [
    { headerName: 'Time', field: 'ts', sort: 'desc', maxWidth: 180, valueFormatter: (p) => fmtDate(p.value), cellClass: 'small' },
    { headerName: 'Actor', field: 'actor', maxWidth: 170 },
    { headerName: 'Action', field: 'action', maxWidth: 220, cellRenderer: gridHtml((r) => `<span class="pill ${/fail|reject/.test(r.action) ? 'crit' : ''}">${esc(r.action)}</span>`) },
    { headerName: 'Target', field: 'target' },
    { headerName: 'Details', field: 'details', flex: 2, cellClass: 'small mono' },
    { headerName: 'IP', field: 'ip', maxWidth: 150, cellClass: 'mono small' },
  ];
  const grid = makeGrid($('#aud'), { columnDefs: cols, rowData: [], noRows: '<span class="muted">Nothing yet</span>' });
  try { grid.setGridOption('rowData', await api('/api/audit?limit=500')); } catch (e) { toast(e.message, true); }
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
  view.innerHTML = `<div class="page-head"><div><h1>${t('page.enroll.title')}</h1><p class="sub">${t('page.enroll.sub')}</p></div></div>
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
  const pwCard = `<div class="card pad"><h2>${t('set.pw.title.self')}</h2>
      <form id="pw" class="stack">
        <label>${t('set.pw.current')}<input type="password" name="current" required autocomplete="current-password"></label>
        <label>${t('set.pw.new')}<input type="password" name="new" required minlength="10" autocomplete="new-password"></label>
        <button class="btn primary" style="align-self:flex-start">${t('set.pw.update')}</button></form></div>`;
  const wirePw = () => { $('#pw').onsubmit = async (e) => {
    e.preventDefault();
    try { await api('/api/password', { method: 'POST', body: { current: e.target.current.value, new: e.target.new.value } }); e.target.reset(); toast(t('set.t.pwupdated')); } catch (err) { toast(err.message, true); }
  }; };
  if (!isAdmin()) {
    view.innerHTML = `<div class="page-head"><div><h1>${t('page.settings.title')}</h1><p class="sub">${esc(roleLabel(state.me.role))}${state.me.scope_label ? ' · ' + esc(state.me.scope_label) : ''}</p></div></div>
      <div class="settings-grid"><div class="stack">${pwCard}</div></div>`;
    wirePw();
    return;
  }
  view.innerHTML = `<div class="page-head"><div><h1>${t('page.settings.title')}</h1><p class="sub">${t('page.settings.sub')} · KEM v${esc(state.me?.version)}</p></div></div>
    <div class="settings-grid">
      <form class="card pad" id="notif"><h2>${t('set.notif')}</h2><div class="empty">${t('common.loading')}</div></form>
      <div class="stack">
        <form class="card pad" id="auto"><h2>${t('set.auto')}</h2></form>
        <form class="card pad" id="ai"><h2>${t('set.ai')}</h2></form>
        <div class="card pad"><h2>${t('set.pw.title.admin')}</h2>
          <form id="pw" class="stack">
            <label>${t('set.pw.current')}<input type="password" name="current" required autocomplete="current-password"></label>
            <label>${t('set.pw.new')}<input type="password" name="new" required minlength="10" autocomplete="new-password"></label>
            <button class="btn primary" style="align-self:flex-start">${t('set.pw.update')}</button></form></div>
      </div>
    </div>
    <div class="card" style="margin-top:16px"><div class="pad-h"><h2>${t('set.notiflog')}</h2></div><div id="notiflog"></div></div>`;
  $('#pw').onsubmit = async (e) => {
    e.preventDefault();
    try { await api('/api/password', { method: 'POST', body: { current: e.target.current.value, new: e.target.new.value } }); e.target.reset(); toast(t('set.t.pwupdated')); } catch (err) { toast(err.message, true); }
  };
  let s;
  try { s = await api('/api/settings'); } catch (e) { toast(e.message, true); return; }

  const render = () => {
    $('#notif').innerHTML = `<h2>${t('set.notif')}</h2>
      <p class="note">${t('set.notif.note')}</p>
      <label>${t('set.f.webhook')}<input name="notify_webhook" value="${esc(s.notify_webhook)}" placeholder="https://hooks.slack.com/services/…" spellcheck="false"></label>
      <details class="help"><summary>${t('set.notif.whichhelp')}</summary><ul>
        <li><b>Slack</b>, <b>Mattermost</b>, <b>Google Chat</b> — incoming-webhook URL</li>
        <li><b>Microsoft Teams</b> — a <i>Workflows</i> "post to a channel when a webhook request is received" URL</li>
        <li><b>Discord</b> — channel webhook URL</li>
        <li><b>Telegram</b> — <span class="mono">https://api.telegram.org/bot&lt;TOKEN&gt;/sendMessage?chat_id=&lt;CHAT_ID&gt;</span></li>
        <li>Anything else receives JSON <span class="mono">{"text": "…"}</span></li></ul></details>
      <label>${t('set.f.email')}<input name="notify_email" value="${esc(s.notify_email)}" placeholder="it@company.com"></label>
      <div class="form-2">
        <label>${t('set.f.smtphost')}<input name="smtp_host" value="${esc(s.smtp_host)}" placeholder="smtp.gmail.com"></label>
        <label>${t('set.f.port')}<input name="smtp_port" type="number" value="${esc(s.smtp_port)}" min="1" max="65535"></label>
        <label>${t('set.f.security')}<select name="smtp_security">${[['starttls', 'STARTTLS (587)'], ['ssl', 'SSL/TLS (465)'], ['none', 'None']].map(([v, l]) => `<option value="${v}" ${s.smtp_security === v ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
        <label>${t('set.f.from')}<input name="smtp_from" value="${esc(s.smtp_from)}" placeholder="kem@company.com"></label>
        <label>${t('set.f.smtpuser')}<input name="smtp_user" value="${esc(s.smtp_user)}" autocomplete="off"></label>
        <label>${t('set.f.smtppass')}<input name="smtp_pass" type="password" autocomplete="new-password" placeholder="${s.smtp_pass_set ? esc(t('set.pwsaved')) : ''}"></label>
      </div>
      <div><div class="muted small" style="margin-bottom:6px;font-weight:500">${t('set.notif.when')}</div>
        ${Object.entries(s.event_names).map(([k, l]) => `<label class="check"><input type="checkbox" name="ev" value="${k}" ${s.notify_events.includes(k) ? 'checked' : ''}> ${esc(l)}</label>`).join('')}</div>
      <label style="max-width:260px">${t('set.f.offline')}<input name="notify_offline_hours" type="number" min="0" max="720" value="${esc(s.notify_offline_hours)}"></label>
      <div class="row"><button class="btn primary">${t('set.save')}</button><button type="button" class="btn" id="testn">${t('set.sendtest')}</button></div>`;
    $('#auto').innerHTML = `<h2>${t('set.auto')}</h2>
      <label class="check"><input type="checkbox" name="auto_update_scan" ${s.auto_update_scan === '1' ? 'checked' : ''}><div>${t('set.auto.scan')}</div></label>
      <label class="check"><input type="checkbox" name="auto_update_agent" ${s.auto_update_agent === '1' ? 'checked' : ''}><div>${t('set.auto.agent')}<br><span class="muted small">${t('set.auto.agent.sub')}</span></div></label>
      <button class="btn primary" style="align-self:flex-start">${t('set.save')}</button>`;
    $('#testn').onclick = async () => {
      const b = $('#testn'); b.disabled = true;
      try { await save(false); await api('/api/settings/test-notification', { method: 'POST' }); toast(t('set.t.testsent')); } catch (e) { toast(e.message, true); } finally { b.disabled = false; }
    };
    $('#ai').innerHTML = `<h2>${t('set.ai')}</h2>
      <p class="note">${t('set.ai.note')}</p>
      <label>${t('set.f.aiurl')}<input name="ai_base_url" value="${esc(s.ai_base_url)}" placeholder="http://localhost:11434/v1" spellcheck="false"></label>
      <div class="form-2">
        <label>${t('set.f.aimodel')}<input name="ai_model" value="${esc(s.ai_model)}" placeholder="llama3.1" spellcheck="false"></label>
        <label>${t('set.f.aikey')}<input name="ai_api_key" type="password" autocomplete="new-password" placeholder="${s.ai_api_key_set ? esc(t('set.pwsaved')) : esc(t('set.ai.key.need'))}"></label>
      </div>
      <label class="check"><input type="checkbox" name="ai_enabled" ${s.ai_enabled ? 'checked' : ''}><div>${t('set.ai.enable')}<br><span class="muted small">${t('set.ai.enable.sub')}</span></div></label>
      <div class="row"><button class="btn primary">${t('set.save')}</button><button type="button" class="btn" id="testai">${t('set.testconn')}</button></div>`;
    $('#testai').onclick = async () => {
      const b = $('#testai'); b.disabled = true;
      try { await save(false); const r = await api('/api/ai/test', { method: 'POST' }); toast(`${t('set.ai.reachable')} (${r.model}): ${r.reply}`); } catch (e) { toast(e.message, true); } finally { b.disabled = false; }
    };
  };
  const collect = () => {
    const n = $('#notif'), a = $('#auto'), ai = $('#ai');
    return {
      notify_webhook: n.notify_webhook.value.trim(), notify_email: n.notify_email.value.trim(), smtp_host: n.smtp_host.value.trim(),
      smtp_port: +n.smtp_port.value || 587, smtp_security: n.smtp_security.value, smtp_from: n.smtp_from.value.trim(), smtp_user: n.smtp_user.value.trim(),
      smtp_pass: n.smtp_pass.value, notify_events: $$('[name=ev]:checked', n).map((x) => x.value), notify_offline_hours: +n.notify_offline_hours.value || 0,
      auto_update_scan: a.auto_update_scan.checked, auto_update_agent: a.auto_update_agent.checked,
      ai_base_url: ai.ai_base_url.value.trim(), ai_model: ai.ai_model.value.trim(), ai_api_key: ai.ai_api_key.value, ai_enabled: ai.ai_enabled.checked,
    };
  };
  const save = async (announce = true) => { s = await api('/api/settings', { method: 'PUT', body: collect() }); render(); if (announce) toast(t('set.t.saved')); };
  render();
  $('#notif').onsubmit = (e) => { e.preventDefault(); save().catch((err) => toast(err.message, true)); };
  $('#auto').onsubmit = (e) => { e.preventDefault(); save().catch((err) => toast(err.message, true)); };
  $('#ai').onsubmit = (e) => { e.preventDefault(); save().catch((err) => toast(err.message, true)); };

  const loadLog = async () => {
    const rows = await api('/api/notifications');
    $('#notiflog').innerHTML = rows.length ? `<div class="table-wrap"><table class="grid"><thead><tr><th class="nowrap">${t('set.col.time')}</th><th>${t('set.col.device')}</th><th>${t('set.col.event')}</th><th>${t('set.col.message')}</th><th>${t('set.col.delivery')}</th></tr></thead><tbody>${
      rows.map((r) => `<tr><td class="small nowrap">${fmtDate(r.ts)}</td><td>${r.device_id ? `<a href="#/device/${esc(r.device_id)}">${esc(r.hostname)}</a>` : esc(r.hostname)}</td>
        <td><span class="pill">${esc(r.event.replace('_', ' '))}</span></td><td class="small">${esc(r.text)}</td>
        <td>${statusPill(r.status)}${r.error ? `<div class="small muted">${esc(r.error)}</div>` : ''}</td></tr>`).join('')}</tbody></table></div>`
      : `<div class="empty">${t('set.notiflog.none')}</div>`;
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
  view.innerHTML = `<div class="page-head"><div><h1>${t('page.org.title')}</h1><p class="sub">${t('page.org.sub')}</p></div></div>
    <div id="orgwrap" class="card"><div class="empty">Loading…</div></div>`;
  let org;
  try { org = await api('/api/org'); } catch (e) { toast(e.message, true); return; }
  const reload = () => viewOrg();
  const canEdit = org.can_edit;
  const labRow = (l) => `<div class="orgl orgrow"><span>▸ ${esc(l.name)} <span class="muted small">${l.devices} ${t('org.devices')}${l.gateways ? ` · ${l.gateways} ${t('org.gateways')}` : ''}</span></span>${canEdit ? `<button class="link small danger-link" data-dellab="${l.id}">${t('org.del')}</button>` : ''}</div>`;
  const schoolRow = (s) => `<div class="orgs"><div class="orgrow"><span><b>${esc(s.name)}</b></span>${canEdit ? `<span class="orgacts"><button class="link small" data-addlab="${s.id}">${t('org.addlab')}</button> <button class="link small danger-link" data-dels="${s.id}">${t('org.del')}</button></span>` : ''}</div>${(s.labs || []).map(labRow).join('') || `<div class="orgl muted small">${t('org.nolabs')}</div>`}</div>`;
  const muniRow = (m) => `<div class="orgm"><div class="orgrow"><span><b style="font-size:16px">${esc(m.name)}</b></span>${canEdit ? `<span class="orgacts"><button class="link small" data-addschool="${m.id}">${t('org.addschool')}</button> ${state.me.role === 'superadmin' ? `<button class="link small danger-link" data-delm="${m.id}">${t('org.del')}</button>` : ''}</span>` : ''}</div>${(m.schools || []).map(schoolRow).join('') || `<div class="orgs muted small">${t('org.noschools')}</div>`}</div>`;
  const tree = (org.municipalities || []).map(muniRow).join('') || `<div class="empty">${t('org.nomunis')}</div>`;
  $('#orgwrap').innerHTML = `<div class="pad">${state.me.role === 'superadmin' ? `<button class="btn small" id="addmuni">${t('org.addmuni')}</button>` : ''}${org.unassigned_devices ? `<span class="pill" style="margin-inline-start:10px">${org.unassigned_devices} ${t('org.unplaced')}</span>` : ''}</div><div class="orgtree">${tree}</div>`;
  const ask = (label, url, extra) => async () => { const name = prompt(label); if (!name) return; try { await api(url, { method: 'POST', body: { name, ...extra } }); toast(t('org.t.added')); reload(); } catch (e) { toast(e.message, true); } };
  const del = (url, msg) => async () => { if (!confirm(msg)) return; try { await api(url, { method: 'DELETE' }); toast(t('org.t.deleted')); reload(); } catch (e) { toast(e.message, true); } };
  if ($('#addmuni')) $('#addmuni').onclick = ask(t('org.p.muni'), '/api/municipalities', {});
  $$('[data-addschool]').forEach((b) => (b.onclick = ask(t('org.p.school'), '/api/schools', { municipality_id: b.dataset.addschool })));
  $$('[data-addlab]').forEach((b) => (b.onclick = ask(t('org.p.lab'), '/api/labs', { school_id: b.dataset.addlab })));
  $$('[data-delm]').forEach((b) => (b.onclick = del(`/api/municipalities/${b.dataset.delm}`, t('org.c.muni'))));
  $$('[data-dels]').forEach((b) => (b.onclick = del(`/api/schools/${b.dataset.dels}`, t('org.c.school'))));
  $$('[data-dellab]').forEach((b) => (b.onclick = del(`/api/labs/${b.dataset.dellab}`, t('org.c.lab'))));
}

// ------------------------------------------------------------------ users
async function viewUsers() {
  view.innerHTML = `<div class="page-head"><div><h1>${t('page.users.title')}</h1><p class="sub">${t('page.users.sub')}</p></div>
      <button class="btn primary" id="adduser">${t('usr.add')}</button></div>
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
    ? ['municipality_admin', 'school_manager', 'teacher'] : ['school_manager', 'teacher'];
  const opts = (arr) => arr.map((v) => `<option value="${v}">${esc(t('role.' + v))}</option>`).join('');
  box.classList.remove('hidden');
  box.innerHTML = `<h2>${t('usr.new')}</h2><form id="uform" class="form-grid">
    <label>${t('usr.username')}<input name="username" required autocomplete="off"></label>
    <label>${t('usr.display')}<input name="display_name" placeholder="${esc(t('usr.display.ph'))}"></label>
    <label>${t('usr.password')}<input name="password" type="password" required minlength="10" autocomplete="new-password"></label>
    <label>${t('usr.role')}<select name="role">${opts(roles)}</select></label>
    <label id="scopewrap">${t('usr.scope')}<select name="scope_id"></select></label>
    <div class="row" style="grid-column:1/-1"><button class="btn primary">${t('usr.create')}</button><button type="button" class="btn" id="ucancel">${t('common.cancel')}</button></div></form>`;
  const scopeSel = box.querySelector('[name=scope_id]');
  const syncScope = () => {
    const role = box.querySelector('[name=role]').value;
    const src = role === 'municipality_admin' ? munis : role === 'school_manager' ? schools : labs;
    scopeSel.innerHTML = src.length ? src.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join('') : `<option value="">${t('usr.scope.none')}</option>`;
  };
  box.querySelector('[name=role]').onchange = syncScope; syncScope();
  $('#ucancel').onclick = () => box.classList.add('hidden');
  $('#uform').onsubmit = async (e) => {
    e.preventDefault();
    const f = e.target;
    try {
      await api('/api/users', { method: 'POST', body: { username: f.username.value, display_name: f.display_name.value, password: f.password.value, role: f.role.value, scope_id: f.scope_id.value } });
      toast(t('usr.t.created')); box.classList.add('hidden'); loadUsers();
    } catch (err) { toast(err.message, true); }
  };
}

async function loadUsers() {
  const users = await api('/api/users');
  $('#userlist').innerHTML = users.length ? `<div class="table-wrap"><table class="grid"><thead><tr><th>${t('usr.col.user')}</th><th>${t('usr.col.role')}</th><th>${t('usr.col.scope')}</th><th class="nowrap">${t('usr.col.last')}</th><th>${t('usr.col.status')}</th><th></th></tr></thead><tbody>${
    users.map((u) => `<tr>
      <td><b>${esc(u.username)}</b>${u.display_name ? `<br><span class="small muted">${esc(u.display_name)}</span>` : ''}</td>
      <td><span class="pill">${esc(roleLabel(u.role))}</span></td>
      <td>${esc(u.scope_label || '—')}</td>
      <td class="small nowrap">${u.last_login ? ago(u.last_login) : t('usr.never')}</td>
      <td>${u.disabled ? `<span class="pill">${t('usr.disabled')}</span>` : `<span class="pill ok">${t('usr.active')}</span>`}</td>
      <td class="nowrap">${u.role === 'superadmin' ? '' : `<button class="link small" data-pw="${u.id}">${t('usr.pw')}</button>
        <button class="link small" data-toggle="${u.id}" data-dis="${u.disabled ? 0 : 1}">${u.disabled ? t('usr.enable') : t('usr.disable')}</button>
        <button class="link small danger-link" data-deluser="${u.id}">${t('org.del')}</button>`}</td></tr>`).join('')
  }</tbody></table></div>` : `<div class="empty">${t('usr.none')}</div>`;
  $$('[data-deluser]').forEach((b) => (b.onclick = async () => { if (!confirm(t('usr.confirm.del'))) return; try { await api(`/api/users/${b.dataset.deluser}`, { method: 'DELETE' }); toast(t('usr.t.deleted')); loadUsers(); } catch (e) { toast(e.message, true); } }));
  $$('[data-toggle]').forEach((b) => (b.onclick = async () => { try { await api(`/api/users/${b.dataset.toggle}`, { method: 'PATCH', body: { disabled: !!+b.dataset.dis } }); loadUsers(); } catch (e) { toast(e.message, true); } }));
  $$('[data-pw]').forEach((b) => (b.onclick = async () => { const p = prompt(t('usr.prompt.pw')); if (!p) return; try { await api(`/api/users/${b.dataset.pw}`, { method: 'PATCH', body: { password: p } }); toast(t('usr.t.pwreset')); } catch (e) { toast(e.message, true); } }));
}

// ------------------------------------------------------------------ gateways
async function viewGateways() {
  view.innerHTML = `<div class="page-head"><div><h1>${t('page.gateways.title')}</h1><p class="sub">${t('page.gateways.sub')}</p></div>
      <a class="btn" href="#/enroll">${t('gw.token')}</a></div>
    <div class="card pad" style="margin-bottom:16px"><h2>How a gateway works</h2>
      <p class="note">Students connect to the gateway on their lab PC; the gateway forwards to this server and never lets students reach it directly.</p>
      <ol class="steps"><li>Create a <b>gateway token</b> for a lab under <a href="#/enroll">Add devices</a>.</li>
        <li>On the lab's teacher PC (Python 3.8+), run elevated from the <code>gateway/</code> folder:
          <div class="cmdbox"><code>.\\install-gateway.ps1 -Server ${esc(location.origin)} -Token &lt;gateway-token&gt;</code></div></li>
        <li>Enroll that lab's student agents against <code>http://&lt;gateway-host&gt;:8171</code> with a <b>device</b> token for the same lab.</li></ol></div>
    <div class="card" id="gwlist"><div class="empty">Loading…</div></div>`;
  const load = async () => {
    const gws = await api('/api/gateways');
    $('#gwlist').innerHTML = gws.length ? `<div class="table-wrap"><table class="grid"><thead><tr><th>${t('gw.col.gateway')}</th><th>${t('gw.col.lab')}</th><th>${t('gw.col.devices')}</th><th>${t('gw.col.version')}</th><th class="nowrap">${t('gw.col.last')}</th><th>${t('gw.col.status')}</th><th></th></tr></thead><tbody>${
      gws.map((g) => `<tr><td><b>${esc(g.hostname)}</b><br><span class="small mono muted">${esc(g.public_ip || '')}</span></td>
        <td>${esc(g.place.lab || '—')}${g.place.school ? `<br><span class="small muted">${esc(g.place.school)}</span>` : ''}</td>
        <td>${g.devices}</td><td class="small">${dash(g.agent_version)}</td>
        <td class="small nowrap">${g.last_seen ? ago(g.last_seen) : t('gw.never')}</td>
        <td>${g.online ? `<span class="pill ok">${t('gw.online')}</span>` : `<span class="pill">${t('gw.offline')}</span>`}</td>
        <td><button class="link small danger-link" data-delgw="${g.id}">${t('gw.remove')}</button></td></tr>`).join('')
    }</tbody></table></div>` : `<div class="empty">${t('gw.none')}</div>`;
    $$('[data-delgw]').forEach((b) => (b.onclick = async () => { if (!confirm(t('gw.confirm.remove'))) return; try { await api(`/api/gateways/${b.dataset.delgw}`, { method: 'DELETE' }); toast(t('gw.t.removed')); load(); } catch (e) { toast(e.message, true); } }));
  };
  await load().catch((e) => toast(e.message, true));
  every(load, 10000);
}

// ------------------------------------------------------------------ licensing
const FINDING_CLASS = { confirmed_issue: 'crit', potential_gap: 'warn', verification_required: 'blue', compliant: 'ok', not_applicable: '' };
async function viewLicensing() {
  view.innerHTML = `<div class="page-head"><div><h1>${t('page.licensing.title')}</h1><p class="sub">${t('page.licensing.sub')}</p></div>
      ${cap('manage_licensing') ? `<button class="btn primary" id="addent">${t('lic.addent')}</button>` : ''}</div>
    <section class="tiles" id="lictiles"></section>
    <div class="card" id="findings"><div class="empty">${t('common.loading')}</div></div>
    <div class="card pad hidden" id="entform"></div>
    <h2 style="margin:20px 0 10px">${t('lic.ents')}</h2>
    <div class="card" id="entlist"><div class="empty">${t('common.loading')}</div></div>`;
  if ($('#addent')) $('#addent').onclick = () => entForm().catch((e) => toast(e.message, true));
  const load = async () => {
    const [res, ents] = await Promise.all([api('/api/license/findings'), api('/api/entitlements')]);
    const sum = res.summary || {};
    const tileKeys = ['confirmed_issue', 'potential_gap', 'verification_required', 'compliant'];
    $('#lictiles').innerHTML = tileKeys.map((k) => `<div class="tile"><div class="l">${t('fnd.' + k)}</div><div class="n">${sum[k] || 0}</div></div>`).join('');
    $('#findings').innerHTML = res.findings.length ? `<div class="table-wrap"><table class="grid"><thead><tr><th>${t('lic.col.product')}</th><th>${t('lic.col.installs')}</th><th>${t('lic.col.licence')}</th><th>${t('lic.col.status')}</th><th>${t('lic.col.detail')}</th></tr></thead><tbody>${
      res.findings.map((f) => `<tr>
        <td><b>${esc(f.label)}</b><br><span class="small muted">${esc(f.type)}</span></td>
        <td>${f.installs}</td>
        <td>${f.site ? t('lic.site') : (f.seats ? f.seats + ' ' + t('lic.seats') : '—')}</td>
        <td><span class="pill ${FINDING_CLASS[f.category] || ''}">${esc(t('fnd.' + f.category))}</span></td>
        <td class="small">${esc(f.message)}${f.samples && f.samples.length ? `<br><span class="muted">${esc(f.samples.slice(0, 4).map((s) => s.host).join(', '))}${f.installs > 4 ? ' …' : ''}</span>` : ''}</td></tr>`).join('')
    }</tbody></table></div>` : `<div class="empty">${t('lic.nofindings')}</div>`;
    $('#entlist').innerHTML = ents.length ? `<div class="table-wrap"><table class="grid"><thead><tr><th>${t('lic.col.name')}</th><th>${t('lic.col.product')}</th><th>${t('lic.col.type')}</th><th>${t('lic.col.seats')}</th><th>${t('lic.col.scope')}</th><th>${t('lic.col.expires')}</th><th></th></tr></thead><tbody>${
      ents.map((e) => `<tr><td><b>${esc(e.name)}</b>${e.notes ? `<br><span class="small muted">${esc(e.notes)}</span>` : ''}</td>
        <td>${esc(e.product_label || e.product || '—')}</td><td class="small">${esc(e.license_type)}</td>
        <td>${e.seats || `<span class="muted">${t('lic.site')}</span>`}</td><td class="small">${esc(e.scope_name)}</td>
        <td class="small nowrap ${e.expires && e.expires * 1000 < Date.now() ? 'crit-text' : ''}">${e.expires ? fmtDate(e.expires).split(',')[0] : '—'}</td>
        <td>${cap('manage_licensing') ? `<button class="link small" data-editent="${e.id}">${t('lic.edit')}</button> <button class="link small danger-link" data-delent="${e.id}">${t('org.del')}</button>` : ''}</td></tr>`).join('')
    }</tbody></table></div>` : `<div class="empty">${t('lic.noents')}</div>`;
    $$('[data-delent]').forEach((b) => (b.onclick = async () => { if (!confirm(t('lic.confirm.del'))) return; try { await api(`/api/entitlements/${b.dataset.delent}`, { method: 'DELETE' }); toast(t('lic.t.deleted')); load(); } catch (e) { toast(e.message, true); } }));
    $$('[data-editent]').forEach((b) => (b.onclick = async () => {
      const e = ents.find((x) => x.id === b.dataset.editent);
      const seats = prompt(t('lic.p.seats'), e.seats); if (seats === null) return;
      const expires = prompt(t('lic.p.expiry'), e.expires ? fmtDate(e.expires).split(',')[0].split('/').reverse().join('-') : '');
      if (expires === null) return;
      try { await api(`/api/entitlements/${e.id}`, { method: 'PATCH', body: { seats: +seats || 0, expires } }); toast(t('lic.t.updated')); load(); } catch (err) { toast(err.message, true); }
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
  box.innerHTML = `<h2>${t('lic.new')}</h2><form id="eform" class="form-grid">
    <label>${t('lic.f.name')}<input name="name" required placeholder="e.g. Office 365 A3 (district)"></label>
    <label>${t('lic.f.product')}<select name="product"><option value="">${t('lic.f.other')}</option>${cat.products.map((p) => `<option value="${p.key}">${esc(p.label)}</option>`).join('')}</select></label>
    <label>${t('lic.f.type')}<select name="license_type">${cat.license_types.map((lt) => `<option value="${lt}">${esc(lt)}</option>`).join('')}</select></label>
    <label>${t('lic.f.seats')}<input name="seats" type="number" min="0" value="0"></label>
    <label>${t('lic.f.covers')}<select name="scope_type"><option value="lab">${t('lic.covers.lab')}</option><option value="school">${t('lic.covers.school')}</option><option value="municipality">${t('lic.covers.municipality')}</option>${global ? `<option value="global">${t('lic.covers.global')}</option>` : ''}</select></label>
    <label id="escope">${t('lic.f.which')}<select name="scope_id"></select></label>
    <label>${t('lic.f.expires')}<input name="expires" type="date"></label>
    <label>${t('lic.f.notes')}<input name="notes" placeholder="PO number, contract…"></label>
    <div class="row" style="grid-column:1/-1"><button class="btn primary">${t('lic.create')}</button><button type="button" class="btn" id="ecancel">${t('common.cancel')}</button></div></form>`;
  const sel = box.querySelector('[name=scope_id]');
  const sync = () => {
    const st = box.querySelector('[name=scope_type]').value;
    box.querySelector('#escope').style.display = st === 'global' ? 'none' : '';
    const src = st === 'municipality' ? munis : st === 'school' ? schools : labs;
    sel.innerHTML = src.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join('') || `<option value="">${t('lic.scope.none')}</option>`;
  };
  box.querySelector('[name=scope_type]').onchange = sync; sync();
  $('#ecancel').onclick = () => box.classList.add('hidden');
  $('#eform').onsubmit = async (e) => {
    e.preventDefault(); const f = e.target;
    try {
      await api('/api/entitlements', { method: 'POST', body: { name: f.name.value, product: f.product.value, license_type: f.license_type.value, seats: +f.seats.value || 0, scope_type: f.scope_type.value, scope_id: f.scope_id.value, expires: f.expires.value, notes: f.notes.value } });
      toast(t('lic.t.added')); box.classList.add('hidden'); viewLicensing();
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
const INC_SEV = { critical: 'crit', warning: 'warn', info: 'info' };
const INC_STATUS = { open: 'crit', acknowledged: 'blue', resolved: 'ok' };
const INC_SEGS = ['unresolved', 'open', 'acknowledged', 'resolved', ''];

async function viewIncidents() {
  const manage = cap('manage_incidents');
  if (state.incFilter == null) state.incFilter = 'unresolved';
  view.innerHTML = `
    <div class="page-head"><div><h1>${t('page.incidents.title')}</h1><p class="sub">${t('page.incidents.sub')}${state.me.scope_label && state.me.role !== 'superadmin' ? ' · ' + esc(state.me.scope_label) : ''}</p></div>
      <div class="row">${manage ? `<button class="btn" id="incscan">${t('inc.scan')}</button> <button class="btn primary" id="incnew">${t('inc.new')}</button>` : ''}</div></div>
    <div class="toolbar"><div class="seg" id="incseg" style="max-width:520px">
      ${INC_SEGS.map((s) => `<button data-s="${s}" class="${state.incFilter === s ? 'on' : ''}">${t('inc.seg.' + (s || 'all'))}</button>`).join('')}
    </div></div>
    <div class="card table-wrap"><table class="grid">
      <thead><tr><th>${t('inc.col.severity')}</th><th>${t('inc.col.issue')}</th><th>${t('inc.col.device')}</th><th>${t('inc.col.status')}</th><th>${t('inc.col.assignee')}</th><th class="nowrap">${t('inc.col.opened')}</th>${manage ? '<th></th>' : ''}</tr></thead>
      <tbody id="incrows"><tr><td colspan="7" class="empty">${t('common.loading')}</td></tr></tbody></table></div>`;

  const load = async () => {
    let rows;
    try { rows = await api(`/api/incidents?status=${encodeURIComponent(state.incFilter)}`); } catch (e) { toast(e.message, true); return; }
    const body = $('#incrows');
    if (!rows.length) { body.innerHTML = `<tr><td colspan="7" class="empty">${t('inc.empty')}</td></tr>`; refreshIncidentBadge(); return; }
    body.innerHTML = rows.map(renderIncRow).join('');
    if (manage) {
      body.querySelectorAll('[data-act]').forEach((b) => (b.onclick = () => incAction(b.dataset.id, b.dataset.act, load)));
      body.querySelectorAll('[data-edit]').forEach((b) => (b.onclick = () => incEdit(rows.find((r) => r.id === b.dataset.edit), load)));
    }
    refreshIncidentBadge();
  };
  $$('#incseg button').forEach((b) => (b.onclick = () => { state.incFilter = b.dataset.s; $$('#incseg button').forEach((x) => x.classList.toggle('on', x === b)); load(); }));
  if (manage) {
    $('#incscan').onclick = async () => { try { const s = await api('/api/incidents/scan', { method: 'POST' }); toast(`${t('inc.t.scanned')} · ${s.total}`); load(); } catch (e) { toast(e.message, true); } };
    $('#incnew').onclick = () => incForm(load);
  }
  every(load, 15000);
  await load();
}

function renderIncRow(i) {
  const manage = cap('manage_incidents');
  const sc = INC_SEV[i.severity] || '';
  const stc = INC_STATUS[i.status] || '';
  const none = `<span class="muted">${t('inc.none')}</span>`;
  const acts = [];
  if (manage) {
    if (i.status === 'open') acts.push(`<button class="btn small" data-act="acknowledge" data-id="${i.id}">${t('inc.ack')}</button>`);
    if (i.status !== 'resolved') acts.push(`<button class="btn small" data-act="resolve" data-id="${i.id}">${t('inc.resolve')}</button>`);
    if (i.status === 'resolved') acts.push(`<button class="btn small" data-act="reopen" data-id="${i.id}">${t('inc.reopen')}</button>`);
    acts.push(`<button class="link small" data-edit="${i.id}">${t('inc.assignnote')}</button>`);
  }
  return `<tr>
    <td><span class="pill ${sc}">${esc(t('sev.' + i.severity))}</span></td>
    <td><b>${esc(i.title)}</b>${i.detail ? `<br><small class="muted">${esc(i.detail)}</small>` : ''}${i.note ? `<br><small class="muted">📝 ${esc(i.note)}</small>` : ''}</td>
    <td class="small">${i.device_hostname ? esc(i.device_hostname) : none}${i.lab_name ? `<br><span class="muted">${esc(i.lab_name)}</span>` : ''}</td>
    <td><span class="pill ${stc}">${esc(t('ist.' + i.status))}</span>${i.auto_resolved ? ` <small class="muted">${t('inc.autores')}</small>` : ''}</td>
    <td class="small">${i.assignee ? esc(i.assignee) : none}</td>
    <td class="nowrap small muted">${ago(i.created)}</td>
    ${manage ? `<td class="nowrap">${acts.join(' ')}</td>` : ''}</tr>`;
}

async function incAction(id, action, done) {
  const key = { acknowledge: 'inc.t.acknowledged', resolve: 'inc.t.resolved', reopen: 'inc.t.reopened' }[action] || 'inc.t.updated';
  try { await api(`/api/incidents/${id}`, { method: 'PATCH', body: { action } }); toast(t(key)); done(); }
  catch (e) { toast(e.message, true); }
}

function incEdit(i, done) {
  modal({
    title: t('inc.edit.title'), submit: t('common.save'),
    body: `<p class="note">${esc(i.title)}</p>
      <label>${t('inc.assignee')}<input name="assignee" maxlength="64" value="${esc(i.assignee || '')}" placeholder="${esc(t('inc.assignee.ph'))}"></label>
      <label>${t('inc.note')}<textarea name="note" maxlength="1000" dir="auto" style="min-height:80px;font-family:inherit;font-size:14px">${esc(i.note || '')}</textarea></label>`,
    onSubmit: async (f) => { await api(`/api/incidents/${i.id}`, { method: 'PATCH', body: { action: 'assign', assignee: f.assignee.value, note: f.note.value } }); toast(t('inc.t.updated')); done(); },
  });
}

async function incForm(done) {
  let devs = [];
  try { devs = await api('/api/devices'); } catch { /* none */ }
  const mgr = state.me.role === 'school_manager';
  modal({
    title: t('inc.new.title'), submit: t('inc.create'),
    body: `<label>${t('inc.title')}<input name="title" maxlength="200" required dir="auto"></label>
      <label>${t('inc.severity')}<select name="severity"><option value="warning">${t('sev.warning')}</option><option value="critical">${t('sev.critical')}</option><option value="info">${t('sev.info')}</option></select></label>
      <label>${t('inc.device')}<select name="device_id" ${mgr ? 'required' : ''}>
        ${mgr ? '' : `<option value="">${t('common.notied')}</option>`}
        ${devs.map((d) => `<option value="${esc(d.id)}">${esc(d.hostname)}${placeText(d) ? ' · ' + esc(placeText(d)) : ''}</option>`).join('')}</select></label>
      <label>${t('inc.detail')}<textarea name="detail" maxlength="1000" dir="auto" style="min-height:80px;font-family:inherit;font-size:14px"></textarea></label>`,
    onSubmit: async (f) => { await api('/api/incidents', { method: 'POST', body: { title: f.title.value, severity: f.severity.value, device_id: f.device_id.value, detail: f.detail.value } }); toast(t('inc.t.created')); done(); },
  });
}

// ------------------------------------------------------------------ reports
const repLabel = (kind, fallback) => (I18N.en['report.' + kind] ? t('report.' + kind) : (fallback || kind));
const pad2 = (n) => String(n).padStart(2, '0');
function cadenceText(s) {
  const at = ` ${t('cad.at')} ${pad2(s.hour)}:00`;
  if (s.cadence === 'daily') return t('cad.daily') + at;
  if (s.cadence === 'weekly') return `${t('cad.weekly.on')} ${t('weekday.' + s.weekday)}${t('cad.weekly.suffix')}` + at;
  return `${t('cad.monthly.on')} ${s.monthday}` + at;
}

async function viewReports() {
  const admin = isAdmin();
  view.innerHTML = `<div class="page-head"><div><h1>${t('page.reports.title')}</h1><p class="sub">${t('page.reports.sub')}${state.me.scope_label && state.me.role !== 'superadmin' ? ' · ' + esc(state.me.scope_label) : ''}</p></div></div>
    <div class="cards" id="reportcards"><div class="empty">${t('common.loading')}</div></div>
    ${admin ? `
    <div class="card" style="margin-top:18px"><div class="pad-h row" style="justify-content:space-between;align-items:center"><h2>${t('rep.sched')}</h2><button class="btn primary small" id="newsched">${t('rep.newsched')}</button></div>
      <div id="schedlist"><div class="empty">${t('common.loading')}</div></div></div>
    <div class="card" style="margin-top:16px"><div class="pad-h"><h2>${t('rep.runs')}</h2></div><div id="runlist"></div></div>` : ''}`;
  let list;
  try { list = await api('/api/reports'); } catch (e) { toast(e.message, true); return; }
  $('#reportcards').innerHTML = list.map((r) => `
    <div class="card pad">
      <h2>${esc(repLabel(r.kind, r.label))}</h2>
      <p class="muted">${esc(t('rep.desc.' + r.kind))}</p>
      <div class="row" style="margin-top:4px">
        <a class="btn" href="/api/reports/${encodeURIComponent(r.kind)}?format=html" target="_blank" rel="noopener">${t('rep.open')}</a>
        <a class="btn primary" href="/api/reports/${encodeURIComponent(r.kind)}?format=csv">${t('rep.csv')}</a>
      </div>
    </div>`).join('') || `<div class="empty">${t('rep.nocards')}</div>`;
  if (!admin) return;

  const loadRuns = async () => {
    let runs; try { runs = await api('/api/report-runs'); } catch { return; }
    $('#runlist').innerHTML = runs.length ? `<div class="table-wrap"><table class="grid">
      <thead><tr><th class="nowrap">${t('rep.col.when')}</th><th>${t('rep.col.report')}</th><th>${t('rep.col.scope')}</th><th>${t('rep.col.rows')}</th><th>${t('rep.col.delivery')}</th><th></th></tr></thead><tbody>${
        runs.map((r) => `<tr><td class="small nowrap">${fmtDate(r.generated)}</td><td>${esc(repLabel(r.kind))}</td>
          <td class="small">${esc(r.scope_label || '')}</td><td>${r.rows}</td><td class="small muted">${esc(r.note || '')}</td>
          <td class="nowrap"><a class="btn small" href="/api/report-runs/${encodeURIComponent(r.id)}/download">CSV</a></td></tr>`).join('')}</tbody></table></div>`
      : `<div class="empty">${t('rep.noruns')}</div>`;
  };
  const loadSched = async () => {
    let scheds; try { scheds = await api('/api/report-schedules'); } catch (e) { toast(e.message, true); return; }
    $('#schedlist').innerHTML = scheds.length ? `<div class="table-wrap"><table class="grid">
      <thead><tr><th>${t('rep.col.report')}</th><th>${t('rep.col.cadence')}</th><th class="nowrap">${t('rep.col.next')}</th><th>${t('rep.col.delivery')}</th><th>${t('rep.col.status')}</th><th></th></tr></thead><tbody>${
        scheds.map((s) => `<tr>
          <td><b>${esc(repLabel(s.kind, s.label))}</b></td>
          <td class="small">${esc(cadenceText(s))}</td>
          <td class="small nowrap">${fmtDate(s.next_run)}${s.last ? `<br><span class="muted">${t('rep.last')}: ${fmtDate(s.last.generated)} (${s.last.rows})</span>` : ''}</td>
          <td class="small">${[s.to_webhook ? t('rep.webhook') : '', s.recipients ? esc(s.recipients) : ''].filter(Boolean).join('<br>') || `<span class="muted">${t('rep.hist')}</span>`}</td>
          <td>${s.enabled ? `<span class="pill ok">${t('rep.on')}</span>` : `<span class="pill">${t('rep.off')}</span>`}</td>
          <td class="nowrap"><button class="btn small" data-run="${esc(s.id)}">${t('rep.runnow')}</button>
            <button class="btn small" data-toggle="${esc(s.id)}" data-on="${s.enabled ? 1 : 0}">${s.enabled ? t('rep.disable') : t('rep.enable')}</button>
            <button class="link small danger-link" data-del="${esc(s.id)}">${t('common.delete')}</button></td></tr>`).join('')}</tbody></table></div>`
      : `<div class="empty" style="padding:16px">${t('rep.nosched')}</div>`;
    $$('#schedlist [data-run]').forEach((b) => (b.onclick = async () => { b.disabled = true; try { const r = await api(`/api/report-schedules/${b.dataset.run}/run`, { method: 'POST' }); toast(`${t('rep.t.generated')} · ${r.rows}`); loadSched(); loadRuns(); } catch (e) { toast(e.message, true); b.disabled = false; } }));
    $$('#schedlist [data-toggle]').forEach((b) => (b.onclick = async () => { try { await api(`/api/report-schedules/${b.dataset.toggle}`, { method: 'PATCH', body: { enabled: b.dataset.on !== '1' } }); loadSched(); } catch (e) { toast(e.message, true); } }));
    $$('#schedlist [data-del]').forEach((b) => (b.onclick = () => modal({
      title: t('rep.del.title'), submit: t('common.delete'), danger: true,
      body: `<p class="note">${t('rep.del.body')}</p>`,
      onSubmit: async () => { await api(`/api/report-schedules/${b.dataset.del}`, { method: 'DELETE' }); toast(t('rep.t.deleted')); loadSched(); loadRuns(); },
    })));
  };
  $('#newsched').onclick = () => schedForm(list, () => { loadSched(); loadRuns(); });
  await loadSched();
  await loadRuns();
}

function schedForm(reports, done) {
  modal({
    title: t('rep.new.title'), submit: t('rep.create'),
    body: `<label>${t('rep.col.report')}<select name="kind">${reports.map((r) => `<option value="${esc(r.kind)}">${esc(repLabel(r.kind, r.label))}</option>`).join('')}</select></label>
      <div class="form-2">
        <label>${t('rep.col.cadence')}<select name="cadence"><option value="daily">${t('cad.daily')}</option><option value="weekly" selected>${t('cad.weekly')}</option><option value="monthly">${t('cad.monthly')}</option></select></label>
        <label>${t('rep.f.hour')}<input name="hour" type="number" min="0" max="23" value="7"></label>
        <label>${t('rep.f.weekday')}<select name="weekday">${[0, 1, 2, 3, 4, 5, 6].map((i) => `<option value="${i}">${t('weekday.' + i)}</option>`).join('')}</select></label>
        <label>${t('rep.f.monthday')}<input name="monthday" type="number" min="1" max="28" value="1"></label>
      </div>
      <label>${t('rep.f.recipients')}<input name="recipients" placeholder="it@school.org"></label>
      <label class="check"><input type="checkbox" name="to_webhook"> ${t('rep.f.webhook')}</label>
      <p class="note">${t('rep.f.note')}</p>`,
    onSubmit: async (f) => {
      await api('/api/report-schedules', { method: 'POST', body: {
        kind: f.kind.value, cadence: f.cadence.value, hour: +f.hour.value, weekday: +f.weekday.value,
        monthday: +f.monthday.value, recipients: f.recipients.value.trim(), to_webhook: f.to_webhook.checked } });
      toast(t('rep.t.created'));
      done();
    },
  });
}

// ------------------------------------------------------------------ image repository
function fmtBytes(n) {
  n = +n || 0;
  if (!n) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i >= 2 ? 1 : 0)} ${u[i]}`;
}

async function viewImages() {
  const manage = cap('manage_images');
  view.innerHTML = `<div class="page-head"><div><h1>${t('page.images.title')}</h1><p class="sub">${t('page.images.sub')} <b>${t('page.images.note')}</b></p></div>
      ${manage ? `<button class="btn primary" id="newimg">${t('img.register')}</button>` : ''}</div>
    <div class="card table-wrap"><table class="grid"><thead><tr><th>${t('img.col.image')}</th><th>${t('img.col.osver')}</th><th>${t('img.col.size')}</th><th>${t('img.col.scope')}</th><th>${t('img.col.source')}</th><th>${t('img.col.sha')}</th>${manage ? '<th></th>' : ''}</tr></thead>
      <tbody id="imgrows"><tr><td colspan="7" class="empty">${t('common.loading')}</td></tr></tbody></table></div>
    <h2 style="margin:22px 0 10px">${t('img.labtitle')}</h2>
    <div class="card table-wrap"><table class="grid"><thead><tr><th>${t('img.col.school')}</th><th>${t('img.col.lab')}</th><th>${t('img.col.target')}</th></tr></thead>
      <tbody id="labimgrows"><tr><td colspan="3" class="empty">${t('common.loading')}</td></tr></tbody></table></div>`;

  let images = [];
  const loadImages = async () => {
    try { images = await api('/api/images'); } catch (e) { toast(e.message, true); return; }
    $('#imgrows').innerHTML = images.length ? images.map((i) => `<tr>
        <td><b>${esc(i.name)}</b>${i.notes ? `<br><small class="muted">${esc(i.notes)}</small>` : ''}</td>
        <td class="small">${esc(i.os || '—')}${i.version ? ' · ' + esc(i.version) : ''}</td>
        <td class="small">${fmtBytes(i.size_bytes)}</td>
        <td class="small">${esc(i.scope_name || '')}</td>
        <td class="small mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${esc(i.source_url || '—')}</td>
        <td class="small mono">${i.sha256 ? esc(i.sha256.slice(0, 12)) + '…' : '—'}</td>
        ${manage ? `<td class="nowrap"><button class="link small danger-link" data-del="${esc(i.id)}">${t('img.del')}</button></td>` : ''}</tr>`).join('')
      : `<tr><td colspan="7" class="empty">${manage ? t('img.none.manage') : t('img.none')}</td></tr>`;
    if (manage) $$('#imgrows [data-del]').forEach((b) => (b.onclick = () => modal({
      title: t('img.del.title'), submit: t('common.delete'), danger: true,
      body: `<p class="note">${t('img.del.body')}</p>`,
      onSubmit: async () => { await api(`/api/images/${b.dataset.del}`, { method: 'DELETE' }); toast(t('img.t.deleted')); loadImages(); loadLabs(); },
    })));
  };
  const loadLabs = async () => {
    let labs; try { labs = await api('/api/lab-images'); } catch (e) { toast(e.message, true); return; }
    $('#labimgrows').innerHTML = labs.length ? labs.map((l) => `<tr>
        <td class="small">${esc(l.school)}</td><td><b>${esc(l.lab)}</b></td>
        <td><select data-lab="${esc(l.lab_id)}"><option value="">${t('img.none.target')}</option>${images.map((i) => `<option value="${esc(i.id)}" ${l.image_id === i.id ? 'selected' : ''}>${esc(i.name)}</option>`).join('')}</select></td></tr>`).join('')
      : `<tr><td colspan="3" class="empty">${t('img.nolabs')}</td></tr>`;
    $$('#labimgrows select[data-lab]').forEach((s) => (s.onchange = async () => {
      try { await api(`/api/labs/${s.dataset.lab}/image`, { method: 'POST', body: { image_id: s.value } }); toast(t('img.t.updated')); }
      catch (e) { toast(e.message, true); loadLabs(); }
    }));
  };
  if (manage) $('#newimg').onclick = () => imageForm(() => { loadImages(); loadLabs(); });
  await loadImages();
  await loadLabs();
}

async function imageForm(done) {
  let org; try { org = await api('/api/org'); } catch { org = { municipalities: [] }; }
  const { munis, schools, labs } = orgFlat(org);
  const scopes = { global: [['', t('lic.covers.global')]], municipality: munis, school: schools, lab: labs };
  const form = modal({
    title: t('img.new'), submit: t('img.create'),
    body: `<label>${t('img.f.name')}<input name="name" maxlength="120" required placeholder="e.g. Win11 Edu 23H2 - Lab baseline"></label>
      <div class="form-2">
        <label>${t('img.f.os')}<input name="os" maxlength="100" placeholder="Windows 11 Education"></label>
        <label>${t('img.f.version')}<input name="version" maxlength="60" placeholder="23H2 / build 22631"></label>
      </div>
      <label>${t('img.f.source')}<input name="source_url" spellcheck="false" placeholder="https://images.lan/win11-edu.wim or \\\\nas\\images\\win11.wim"></label>
      <div class="form-2">
        <label>${t('img.f.size')}<input name="size_bytes" type="number" min="0" placeholder="e.g. 5368709120"></label>
        <label>${t('img.f.sha')}<input name="sha256" class="mono" placeholder="64 hex"></label>
      </div>
      <div class="form-2">
        <label>${t('img.f.scope')}<select name="scope_type">${['global', 'municipality', 'school', 'lab'].filter((s) => s !== 'global' || state.me.role === 'superadmin').map((s) => `<option value="${s}">${t('lic.covers.' + s)}</option>`).join('')}</select></label>
        <label>${t('img.f.scopetarget')}<select name="scope_id"></select></label>
      </div>
      <label>${t('img.f.notes')}<textarea name="notes" maxlength="1000" style="min-height:60px;font-family:inherit;font-size:14px"></textarea></label>
      <p class="note">${t('img.f.note')}</p>`,
    onSubmit: async (f) => {
      await api('/api/images', { method: 'POST', body: {
        name: f.name.value, os: f.os.value, version: f.version.value, source_url: f.source_url.value.trim(),
        size_bytes: +f.size_bytes.value || 0, sha256: f.sha256.value.trim(),
        scope_type: f.scope_type.value, scope_id: f.scope_id.value, notes: f.notes.value } });
      toast(t('img.t.registered')); done();
    },
  });
  const sync = () => {
    const opts = scopes[form.scope_type.value] || [['', '—']];
    form.scope_id.innerHTML = opts.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join('');
  };
  form.scope_type.onchange = sync; sync();
}

// ------------------------------------------------------------------ software packages
async function viewPackages() {
  const manage = cap('manage_packages');
  view.innerHTML = `<div class="page-head"><div><h1>${t('pkg.title')}</h1><p class="sub">${t('pkg.sub')}</p></div>
      ${manage ? `<button class="btn primary" id="newpkg">${t('pkg.new')}</button>` : ''}</div>
    <div class="card table-wrap"><table class="grid"><thead><tr><th>${t('pkg.col.name')}</th><th>${t('pkg.col.scope')}</th><th>${t('pkg.col.items')}</th>${manage ? '<th></th>' : ''}</tr></thead>
      <tbody id="pkgrows"><tr><td colspan="4" class="empty">${t('common.loading')}</td></tr></tbody></table></div>`;
  const load = async () => {
    let pkgs; try { pkgs = await api('/api/packages'); } catch (e) { toast(e.message, true); return; }
    $('#pkgrows').innerHTML = pkgs.length ? pkgs.map((p) => `<tr>
      <td><b>${esc(p.name)}</b>${p.notes ? `<br><small class="muted">${esc(p.notes)}</small>` : ''}</td>
      <td class="small">${esc(p.scope_name || '')}</td>
      <td class="small">${p.items.map((i) => esc(i.label)).join(', ')}</td>
      ${manage ? `<td class="nowrap"><button class="link small danger-link" data-del="${esc(p.id)}">${t('pkg.del')}</button></td>` : ''}</tr>`).join('')
      : `<tr><td colspan="4" class="empty">${t('pkg.none')}</td></tr>`;
    if (manage) $$('#pkgrows [data-del]').forEach((b) => (b.onclick = () => modal({
      title: t('pkg.col.name'), submit: t('common.delete'), danger: true, body: `<p class="note">${t('pkg.confirm.del')}</p>`,
      onSubmit: async () => { await api(`/api/packages/${b.dataset.del}`, { method: 'DELETE' }); toast(t('pkg.t.deleted')); load(); },
    })));
  };
  if (manage) $('#newpkg').onclick = () => packageForm(load);
  await load();
  if (manage) await loadBaselines();
}

async function loadBaselines() {
  let labs, pkgs;
  try { [labs, pkgs] = await Promise.all([api('/api/lab-baselines'), api('/api/packages')]); }
  catch (e) { toast(e.message, true); return; }
  const card = document.createElement('div');
  card.className = 'card';
  card.style.marginTop = '18px';
  const opts = (sel) => `<option value="">${t('pkg.bl.none')}</option>` +
    pkgs.map((p) => `<option value="${esc(p.id)}"${p.id === sel ? ' selected' : ''}>${esc(p.name)}</option>`).join('');
  const statusCell = (l) => !l.package_id ? '<span class="muted">—</span>'
    : l.drifted ? `<span class="pill warn" title="${t('pkg.bl.drift').replace('{d}', l.drifted).replace('{n}', l.total)}">${l.drifted}/${l.total}</span>`
    : l.total ? `<span class="pill ok">${t('pkg.bl.compliant')}</span>` : `<span class="muted">${t('pkg.bl.empty')}</span>`;
  card.innerHTML = `<div class="page-head sub-head"><div><h2>${t('pkg.bl.title')}</h2><p class="sub">${t('pkg.bl.sub')}</p></div></div>
    <div class="table-wrap"><table class="grid"><thead><tr>
      <th>${t('pkg.bl.lab')}</th><th>${t('pkg.bl.pkg')}</th><th class="center">${t('pkg.bl.remove')}</th>
      <th class="center" title="${t('pkg.bl.auto.help')}">${t('pkg.bl.auto')}</th><th>${t('pkg.bl.col.status')}</th><th></th></tr></thead>
      <tbody>${labs.length ? labs.map((l) => `<tr data-lab="${esc(l.lab_id)}">
        <td><b>${esc(l.lab)}</b><br><small class="muted">${esc(l.school)}</small></td>
        <td><select class="bl-pkg" data-lab="${esc(l.lab_id)}">${opts(l.package_id)}</select></td>
        <td class="center"><input type="checkbox" class="bl-rm" data-lab="${esc(l.lab_id)}"${l.remove_extras ? ' checked' : ''}></td>
        <td class="center"><input type="checkbox" class="bl-auto" data-lab="${esc(l.lab_id)}"${l.auto ? ' checked' : ''}></td>
        <td class="bl-status">${statusCell(l)}</td>
        <td class="nowrap">${l.package_id ? `<button class="btn small bl-apply" data-lab="${esc(l.lab_id)}">${t('pkg.bl.apply')}</button>` : ''}</td>
      </tr>`).join('') : `<tr><td colspan="6" class="empty">${t('pkg.bl.nolabs')}</td></tr>`}</tbody></table></div>`;
  view.appendChild(card);
  const save = async (labId) => {
    const pkg = card.querySelector(`.bl-pkg[data-lab="${labId}"]`).value;
    const rm = card.querySelector(`.bl-rm[data-lab="${labId}"]`).checked;
    const auto = card.querySelector(`.bl-auto[data-lab="${labId}"]`).checked;
    try {
      await api(`/api/labs/${labId}/baseline`, { method: 'POST', body: { package_id: pkg, remove_extras: rm, auto } });
      toast(t('pkg.bl.saved'));
      await loadBaselines(); card.remove();
    } catch (e) { toast(e.message, true); }
  };
  $$('.bl-pkg', card).forEach((s) => (s.onchange = () => save(s.dataset.lab)));
  $$('.bl-rm', card).forEach((c) => (c.onchange = () => save(c.dataset.lab)));
  $$('.bl-auto', card).forEach((c) => (c.onchange = () => save(c.dataset.lab)));
  $$('.bl-apply', card).forEach((b) => (b.onclick = () => applyBaselineModal(b.dataset.lab, () => { loadBaselines(); card.remove(); })));
}

async function applyBaselineModal(labId, done) {
  let r; try { r = await api(`/api/labs/${labId}/apply-baseline`, { method: 'POST', body: { dry_run: true } }); }
  catch (e) { toast(e.message, true); return; }
  const drifted = r.stations.filter((s) => !s.compliant);
  const rows = drifted.map((s) => `<div class="pkgplan" style="margin:6px 0">
      <b>${esc(s.hostname)}</b>
      <div><b>${t('pkg.install')}</b> (${s.install.length}): ${s.install.map(esc).join(', ') || '—'}</div>
      <div class="${s.remove.length ? 'crit-text' : ''}"><b>${t('pkg.remove')}</b> (${s.remove.length}): ${s.remove.map(esc).join(', ') || '—'}</div>
    </div>`).join('');
  modal({
    title: t('pkg.bl.applytitle'), submit: drifted.length ? t('pkg.bl.applybtn') : t('pkg.bl.ok'),
    danger: r.remove_extras, wide: true,
    body: `<p class="note"><b>${esc(r.package)}</b></p>` + (drifted.length
      ? `<p>${t('pkg.bl.willfix').replace('{n}', drifted.length)}</p>${rows}`
      : `<p class="banner ok">${t('pkg.bl.allok')}</p>`),
    onSubmit: async () => {
      if (!drifted.length) return;
      const a = await api(`/api/labs/${labId}/apply-baseline`, { method: 'POST', body: { dry_run: false } });
      toast(t('pkg.bl.queued').replace('{n}', drifted.length));
      if (done) done(); return a;
    },
  });
}

async function packageForm(done) {
  let org; try { org = await api('/api/org'); } catch { org = { municipalities: [] }; }
  const { munis, schools, labs } = orgFlat(org);
  const scopes = { global: [['', t('lic.covers.global')]], municipality: munis, school: schools, lab: labs };
  const form = modal({
    title: t('pkg.create'), submit: t('pkg.create'), wide: true,
    body: `<label>${t('pkg.name')}<input name="name" maxlength="120" required placeholder="Student station"></label>
      <label>${t('pkg.items')}<textarea name="items" required spellcheck="false" style="min-height:130px;font-family:ui-monospace,Consolas,monospace;font-size:13px" placeholder="Windows | windows |&#10;Microsoft 365 | microsoft 365 | winget:Microsoft.Office&#10;Google Chrome | chrome | winget:Google.Chrome"></textarea></label>
      <p class="note">${t('pkg.items.help')}</p>
      <div class="form-2">
        <label>${t('pkg.scope')}<select name="scope_type">${['global', 'municipality', 'school', 'lab'].filter((s) => s !== 'global' || state.me.role === 'superadmin').map((s) => `<option value="${s}">${t('lic.covers.' + s)}</option>`).join('')}</select></label>
        <label>${t('pkg.scopetarget')}<select name="scope_id"></select></label>
      </div>
      <label>${t('pkg.notes')}<input name="notes" maxlength="500"></label>`,
    onSubmit: async (f) => {
      const items = f.items.value.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => {
        const parts = l.split('|').map((x) => x.trim());
        const label = parts[0], match = parts[1] || parts[0], spec = (parts[2] || '').trim();
        if (!label || !match) throw new Error(t('pkg.badline') + l);
        let install = null;
        if (spec) {
          const mm = spec.match(/^(winget|url)\s*:\s*(.+)$/i);
          if (!mm) throw new Error(t('pkg.badline') + l);
          install = mm[1].toLowerCase() === 'winget' ? { method: 'winget', package_id: mm[2].trim() } : { method: 'url', url: mm[2].trim() };
        }
        return { label, match, install };
      });
      await api('/api/packages', { method: 'POST', body: { name: f.name.value, items, notes: f.notes.value, scope_type: f.scope_type.value, scope_id: f.scope_id.value } });
      toast(t('pkg.t.created')); done();
    },
  });
  const sync = () => { const o = scopes[form.scope_type.value] || [['', '—']]; form.scope_id.innerHTML = o.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join(''); };
  form.scope_type.onchange = sync; sync();
}

async function applyPackageModal(deviceId) {
  let pkgs; try { pkgs = await api('/api/packages'); } catch (e) { toast(e.message, true); return; }
  if (!pkgs.length) { toast(t('pkg.none.apply'), true); return; }
  const form = modal({
    title: t('pkg.apply.title'), submit: t('pkg.apply'), danger: true,
    body: `<label>${t('pkg.pkg')}<select name="pkg">${pkgs.map((p) => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('')}</select></label>
      <label class="check"><input type="checkbox" name="rm"> ${t('pkg.removeextras')}</label>
      <div id="planbox" class="pkgplan"><div class="muted">${t('pkg.previewhint')}</div></div>
      <p class="note">${t('pkg.note')}</p>`,
    onSubmit: async (f) => {
      const r = await api(`/api/devices/${deviceId}/apply-package`, { method: 'POST', body: { package_id: f.pkg.value, remove_extras: f.rm.checked, dry_run: false } });
      toast(t('pkg.t.applied').replace('{n}', r.queued));
    },
  });
  const preview = async () => {
    try {
      const r = await api(`/api/devices/${deviceId}/apply-package`, { method: 'POST', body: { package_id: form.pkg.value, remove_extras: form.rm.checked, dry_run: true } });
      $('#planbox').innerHTML = `
        <div><b>${t('pkg.install')}</b> (${r.install.length}): ${r.install.map((i) => esc(i.label)).join(', ') || '—'}</div>
        <div class="${r.remove.length ? 'crit-text' : ''}"><b>${t('pkg.remove')}</b> (${r.remove.length}): ${r.remove.map(esc).join(', ') || '—'}</div>
        <div class="muted small" style="margin-top:4px">${t('pkg.keep')}: ${r.keep.length} · ${t('pkg.protected')}: ${r.protected.length}</div>`;
    } catch (e) { $('#planbox').innerHTML = `<div class="banner crit">⚠ ${esc(e.message)}</div>`; }
  };
  form.pkg.onchange = preview; form.rm.onchange = preview;
  preview();
}

async function viewScreenModal(deviceId, hostname) {
  const m = modal({
    title: `${t('scr.title')} · ${esc(hostname || '')}`, submit: t('scr.refresh'), wide: true,
    body: `<div id="scrbox" class="scrshot"><div class="muted" style="padding:40px;text-align:center"><span class="spin"></span> ${t('scr.asking')}</div></div>
      <p class="note">${t('scr.note')}</p>`,
    onSubmit: async () => { await capture(); return false; },  // keep the modal open on Refresh
  });
  let baseline = 0;
  try { baseline = (await api(`/api/devices/${deviceId}/screenshot/meta`)).captured || 0; } catch { baseline = 0; }
  const show = () => {
    const box = $('#scrbox', m); if (!box) return;
    box.innerHTML = `<img alt="screen" src="/api/devices/${deviceId}/screenshot?t=${Date.now()}">`;
  };
  const capture = async () => {
    const box = $('#scrbox', m); if (!box) return;
    box.innerHTML = `<div class="muted" style="padding:40px;text-align:center"><span class="spin"></span> ${t('scr.asking')}</div>`;
    try { await queue([deviceId], 'request_screenshot'); } catch (e) { box.innerHTML = `<div class="banner crit">⚠ ${esc(e.message)}</div>`; return; }
    for (let i = 0; i < 25; i++) {
      await new Promise((r) => setTimeout(r, 1200));
      if (!$('#scrbox', m)) return;  // modal closed
      let meta; try { meta = await api(`/api/devices/${deviceId}/screenshot/meta`); } catch { continue; }
      if (meta.captured && meta.captured > baseline) { baseline = meta.captured; show(); return; }
    }
    const box2 = $('#scrbox', m);
    if (box2) box2.innerHTML = `<div class="banner warn">⚠ ${t('scr.timeout')}</div>`;
  };
  capture();
}

function freezeInputModal(ids) {
  const list = Array.isArray(ids) ? ids : [ids];
  modal({
    title: t('scr.freeze.title'), submit: t('scr.apply'), danger: true,
    body: `${targetLine(list)}
      <label class="option"><input type="radio" name="mode" value="lock" checked><div><b>${t('scr.freeze.lock')}</b><span>${t('scr.freeze.note')}</span></div></label>
      <label class="option"><input type="radio" name="mode" value="unlock"><div><b>${t('scr.freeze.unlock')}</b><span>${t('scr.unlock.note')}</span></div></label>`,
    onSubmit: async (f) => {
      const mode = (f.querySelector('[name=mode]:checked') || {}).value || 'lock';
      await queue(list, 'lock_input', { mode });
      toast(mode === 'lock' ? t('scr.locked') : t('scr.unlocked'));
    },
  });
}

async function viewClasses() {
  const manage = cap('manage_classes');
  view.innerHTML = `<div class="page-head"><div><h1>${t('cl.title')}</h1><p class="sub">${t('cl.sub')}</p></div>
      ${manage ? `<button class="btn primary" id="newcls">${t('cl.new')}</button>` : ''}</div>
    <div class="card table-wrap"><table class="grid"><thead><tr>
      <th>${t('cl.col.name')}</th><th>${t('cl.col.members')}</th><th>${t('cl.col.teacher')}</th><th>${t('cl.col.status')}</th>${manage ? '<th></th>' : ''}</tr></thead>
      <tbody id="clsrows"><tr><td colspan="5" class="empty">${t('common.loading')}</td></tr></tbody></table></div>`;
  const load = async () => {
    let classes; try { classes = await api('/api/classes'); } catch (e) { toast(e.message, true); return; }
    $('#clsrows').innerHTML = classes.length ? classes.map((c) => {
      const teacher = c.teacher_hostname ? `★ ${esc(c.teacher_hostname)}` : '—';
      const status = c.active
        ? `<span class="pill ok">${t('cl.active').replace('{n}', Math.max(0, c.member_count - 1))}</span> <span class="pill ${c.gateway_online ? 'ok' : 'warn'}">${c.gateway_online ? t('cl.gw.online') : t('cl.gw.offline')}</span>`
        : `<span class="pill">${t('cl.inactive')}</span>`;
      return `<tr>
        <td><b>${esc(c.name)}</b>${c.lab_name ? `<br><small class="muted">${esc(c.lab_name)}</small>` : ''}</td>
        <td class="small">${c.member_count || t('cl.nomembers')}</td>
        <td class="small">${teacher}</td>
        <td>${status}</td>
        ${manage ? `<td class="nowrap">
          ${c.active ? `<button class="btn small ghost-danger" data-dissolve="${esc(c.id)}">${t('cl.dissolve')}</button>`
                     : `<button class="btn small" data-promote="${esc(c.id)}"${c.member_count ? '' : ' disabled'}>${t('cl.setteacher')}</button>`}
          <button class="link small" data-edit="${esc(c.id)}">${t('cl.edit')}</button>
          ${c.active ? '' : `<button class="link small danger-link" data-del="${esc(c.id)}">${t('cl.del')}</button>`}
        </td>` : ''}</tr>`;
    }).join('') : `<tr><td colspan="5" class="empty">${t('cl.none')}</td></tr>`;
    if (!manage) return;
    $$('#clsrows [data-edit]').forEach((b) => (b.onclick = () => classForm(load, classes.find((c) => c.id === b.dataset.edit))));
    $$('#clsrows [data-del]').forEach((b) => (b.onclick = () => modal({
      title: t('cl.col.name'), submit: t('common.delete'), danger: true, body: `<p class="note">${t('cl.confirm.del')}</p>`,
      onSubmit: async () => { await api(`/api/classes/${b.dataset.del}`, { method: 'DELETE' }); toast(t('cl.t.deleted')); load(); },
    })));
    $$('#clsrows [data-promote]').forEach((b) => (b.onclick = () => promoteClass(classes.find((c) => c.id === b.dataset.promote), load)));
    $$('#clsrows [data-dissolve]').forEach((b) => (b.onclick = () => modal({
      title: t('cl.dissolve'), submit: t('cl.dissolve'), danger: true, body: `<p class="note">${t('cl.dissolve.confirm')}</p>`,
      onSubmit: async () => { const r = await api(`/api/classes/${b.dataset.dissolve}/dissolve`, { method: 'POST', body: {} }); toast(t('cl.t.dissolved')); load(); return r; },
    })));
  };
  if (manage) $('#newcls').onclick = () => classForm(load, null);
  await load();
}

async function classMemberPicker(selected, labId) {
  let devs; try { devs = await api('/api/devices'); } catch { devs = []; }
  const inLab = labId ? devs.filter((d) => d.lab_id === labId) : devs;
  const sel = new Set(selected || []);
  return (inLab.length ? inLab : devs).map((d) => `<label class="check"><input type="checkbox" value="${esc(d.id)}" ${sel.has(d.id) ? 'checked' : ''}>
      ${esc(d.hostname)}${d.place && d.place.lab ? ` <span class="muted small">· ${esc(d.place.lab)}</span>` : ''}</label>`).join('')
    || `<p class="muted small">${t('devices.none')}</p>`;
}

async function classForm(done, existing) {
  let org; try { org = await api('/api/org'); } catch { org = { municipalities: [] }; }
  const { labs } = orgFlat(org);
  const labId = existing ? existing.lab_id : '';
  const picker = await classMemberPicker(existing ? existing.members.map((m) => m.device_id) : [], labId);
  const form = modal({
    title: existing ? t('cl.edit') : t('cl.create'), submit: existing ? t('common.save') : t('cl.create'), wide: true,
    body: `<label>${t('cl.name')}<input name="name" maxlength="120" required value="${existing ? esc(existing.name) : ''}" placeholder="Grade 7 · Lab 204"></label>
      ${existing ? '' : `<label>${t('cl.lab')}<select name="lab_id"><option value="">${t('cl.lab.any')}</option>${labs.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join('')}</select></label>`}
      <div><div class="muted small" style="margin-bottom:6px">${t('cl.members')} <span class="muted">— ${t('cl.members.help')}</span></div>
        <div class="checklist" id="clmembers">${picker}</div></div>`,
    onSubmit: async (f) => {
      const member_ids = $$('#clmembers input:checked', f).map((c) => c.value);
      if (existing) {
        await api(`/api/classes/${existing.id}`, { method: 'PATCH', body: { name: f.name.value, member_ids } });
        toast(t('cl.t.saved'));
      } else {
        await api('/api/classes', { method: 'POST', body: { name: f.name.value, lab_id: f.lab_id.value, member_ids } });
        toast(t('cl.t.created'));
      }
      done();
    },
  });
  if (!existing && form.lab_id) form.lab_id.onchange = async () => {
    $('#clmembers', form).innerHTML = await classMemberPicker([], form.lab_id.value);
  };
}

function promoteClass(c, done) {
  if (!c.members.length) { toast(t('cl.needmembers'), true); return; }
  modal({
    title: t('cl.promote.title'), submit: t('cl.promote.submit'), wide: true,
    body: `<p class="note"><b>${esc(c.name)}</b></p>
      <label>${t('cl.promote.pick')}<select name="teacher">${c.members.map((m) => `<option value="${esc(m.device_id)}">${esc(m.hostname)}</option>`).join('')}</select></label>
      <label>${t('cl.promote.addr')}<input name="addr" class="mono" placeholder="192.168.1.50" value="${esc(c.teacher_address || '')}"></label>
      <p class="note">${t('cl.promote.addr.help')}</p>
      <label>${t('cl.promote.port')}<input name="port" type="number" min="1" max="65535" value="${c.listen_port || 8171}"></label>
      <p class="note">${t('cl.promote.note')}</p>`,
    onSubmit: async (f) => {
      const addr = f.addr.value.trim(), port = +f.port.value || 8171;
      if (addr !== (c.teacher_address || '') || port !== c.listen_port) {
        await api(`/api/classes/${c.id}`, { method: 'PATCH', body: { teacher_address: addr, listen_port: port } });
      }
      const r = await api(`/api/classes/${c.id}/teacher`, { method: 'POST', body: { teacher_device_id: f.teacher.value } });
      toast(t('cl.t.promoted').replace('{n}', r.rehomed));
      done();
      return r;
    },
  });
}

function examWhen(s) {
  const hm = `${String(s.start_hour).padStart(2, '0')}:${String(s.start_min).padStart(2, '0')}`;
  if (s.cadence === 'daily') return `${t('es.daily')} · ${hm}`;
  if (s.cadence === 'weekly') return `${t('es.wd.' + s.weekday)} · ${hm}`;
  return `${s.start_date} · ${hm}`;
}
function examLocks(s) {
  const l = [s.lock_internet ? t('exam.internet') : null, s.lock_usb ? t('exam.usb') : null,
    (s.web_filter && s.web_filter.length) ? t('exam.locks.sites').replace('{n}', s.web_filter.length) : null].filter(Boolean);
  return l.join(' · ') || t('es.locks.none');
}

async function viewExamSchedules() {
  view.innerHTML = `<div class="page-head"><div><h1>${t('es.title')}</h1><p class="sub">${t('es.sub')}</p></div>
      <button class="btn primary" id="newes">${t('es.new')}</button></div>
    <div class="card table-wrap"><table class="grid"><thead><tr>
      <th>${t('es.col.exam')}</th><th>${t('es.col.lab')}</th><th>${t('es.col.when')}</th><th>${t('es.col.next')}</th><th>${t('es.col.status')}</th><th></th></tr></thead>
      <tbody id="esrows"><tr><td colspan="6" class="empty">${t('common.loading')}</td></tr></tbody></table></div>`;
  const load = async () => {
    let rows; try { rows = await api('/api/exam-schedules'); } catch (e) { toast(e.message, true); return; }
    $('#esrows').innerHTML = rows.length ? rows.map((s) => `<tr>
      <td><b>${esc(s.name)}</b><br><small class="muted">${esc(examLocks(s))} · ${t('es.for').replace('{d}', s.duration_min)}</small></td>
      <td class="small">${esc(s.lab_name || '')}</td>
      <td class="small">${esc(examWhen(s))}</td>
      <td class="small">${s.active || !s.next_start ? '—' : esc(fmtDate(s.next_start))}</td>
      <td>${s.active ? `<span class="pill crit">${t('es.active')}</span>` : s.enabled ? `<span class="pill ok">${t('es.enabled')}</span>` : `<span class="pill">${t('es.disabled')}</span>`}</td>
      <td class="nowrap">
        <label class="switch" title="${t('es.on')}/${t('es.off')}"><input type="checkbox" data-toggle="${esc(s.id)}" ${s.enabled ? 'checked' : ''}><span></span></label>
        <button class="link small" data-edit="${esc(s.id)}">${t('es.edit')}</button>
        <button class="link small danger-link" data-del="${esc(s.id)}">${t('es.del')}</button></td></tr>`).join('')
      : `<tr><td colspan="6" class="empty">${t('es.none')}</td></tr>`;
    $$('#esrows [data-toggle]').forEach((c) => (c.onchange = async () => {
      try { await api(`/api/exam-schedules/${c.dataset.toggle}`, { method: 'PATCH', body: { enabled: c.checked } }); load(); }
      catch (e) { toast(e.message, true); c.checked = !c.checked; }
    }));
    $$('#esrows [data-edit]').forEach((b) => (b.onclick = () => examScheduleForm(load, rows.find((s) => s.id === b.dataset.edit))));
    $$('#esrows [data-del]').forEach((b) => (b.onclick = () => modal({
      title: t('es.title'), submit: t('common.delete'), danger: true, body: `<p class="note">${t('es.confirm.del')}</p>`,
      onSubmit: async () => { await api(`/api/exam-schedules/${b.dataset.del}`, { method: 'DELETE' }); toast(t('es.t.deleted')); load(); },
    })));
  };
  $('#newes').onclick = () => examScheduleForm(load, null);
  await load();
}

async function examScheduleForm(done, s) {
  let org; try { org = await api('/api/org'); } catch { org = { municipalities: [] }; }
  const { labs } = orgFlat(org);
  if (!labs.length) { toast(t('es.nolabs'), true); return; }
  const cad = s ? s.cadence : 'once';
  const hm = s ? `${String(s.start_hour).padStart(2, '0')}:${String(s.start_min).padStart(2, '0')}` : '08:00';
  const today = new Date().toISOString().slice(0, 10);
  const form = modal({
    title: s ? t('es.edit') : t('es.new'), submit: s ? t('es.save') : t('es.create'), wide: true,
    body: `<label>${t('es.name')}<input name="name" maxlength="120" required value="${s ? esc(s.name) : ''}" placeholder="Math final"></label>
      <label>${t('es.lab')}<select name="lab_id" ${s ? 'disabled' : ''}>${labs.map(([v, l]) => `<option value="${v}" ${s && s.lab_id === v ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></label>
      <div class="form-2">
        <label>${t('es.cadence')}<select name="cadence">${['once', 'daily', 'weekly'].map((c) => `<option value="${c}" ${cad === c ? 'selected' : ''}>${t('es.' + c)}</option>`).join('')}</select></label>
        <label>${t('es.time')}<input type="time" name="time" value="${hm}" required></label>
      </div>
      <div class="form-2">
        <label data-f="date">${t('es.date')}<input type="date" name="start_date" value="${s && s.start_date ? esc(s.start_date) : today}" min="${today}"></label>
        <label data-f="weekday">${t('es.weekday')}<select name="weekday">${[0, 1, 2, 3, 4, 5, 6].map((w) => `<option value="${w}" ${s && s.weekday === w ? 'selected' : ''}>${t('es.wd.' + w)}</option>`).join('')}</select></label>
        <label>${t('es.duration')}<input type="number" name="duration_min" min="5" max="1440" value="${s ? s.duration_min : 60}" required></label>
      </div>
      <div class="checkrow">
        <label class="check"><input type="checkbox" name="lock_internet" ${!s || s.lock_internet ? 'checked' : ''}> ${t('es.internet')}</label>
        <label class="check"><input type="checkbox" name="lock_usb" ${!s || s.lock_usb ? 'checked' : ''}> ${t('es.usb')}</label>
        <label class="check"><input type="checkbox" name="allow_lan" ${s && s.allow_lan ? 'checked' : ''}> ${t('es.lan')}</label>
      </div>`,
    onSubmit: async (f) => {
      const [h, m] = f.time.value.split(':').map((x) => +x);
      const body = {
        lab_id: f.lab_id.value, name: f.name.value, cadence: f.cadence.value,
        start_hour: h || 0, start_min: m || 0, weekday: +f.weekday.value, start_date: f.start_date.value,
        duration_min: +f.duration_min.value, lock_internet: f.lock_internet.checked, lock_usb: f.lock_usb.checked,
        allow_lan: f.allow_lan.checked,
      };
      if (s) { await api(`/api/exam-schedules/${s.id}`, { method: 'PATCH', body }); toast(t('es.t.saved')); }
      else { await api('/api/exam-schedules', { method: 'POST', body }); toast(t('es.t.created')); }
      done();
    },
  });
  const sync = () => {
    const c = form.cadence.value;
    $('[data-f=date]', form).style.display = c === 'once' ? '' : 'none';
    $('[data-f=weekday]', form).style.display = c === 'weekly' ? '' : 'none';
  };
  form.cadence.onchange = sync; sync();
}

async function viewFleetAI() {
  const PRESETS = [['fa.q.weak', 'weak_cpu'], ['fa.q.disk', 'low_disk'], ['fa.q.nic', 'slow_nic'], ['fa.q.busy', 'high_cpu'], ['fa.q.upgrade', '']];
  let aiOn = false;
  try { aiOn = (await api('/api/ai/status')).enabled; } catch { aiOn = false; }
  view.innerHTML = `<div class="page-head"><div><h1>${t('fa.title')}</h1><p class="sub">${t('fa.sub')}</p></div></div>
    ${aiOn ? '' : `<div class="banner warn">⚠ ${t('fa.off')}</div>`}
    <div class="card pad">
      <div class="row" style="gap:8px;align-items:flex-start">
        <textarea id="faq" rows="2" style="flex:1;min-height:48px" placeholder="${esc(t('fa.ph'))}" ${aiOn ? '' : 'disabled'}></textarea>
        <button class="btn primary" id="faask" ${aiOn ? '' : 'disabled'}>${t('fa.ask')}</button>
      </div>
      <div class="muted small" style="margin:10px 0 6px">${t('fa.presets')}</div>
      <div class="chips" id="fapresets">${PRESETS.map(([k], i) => `<button type="button" class="chip" data-i="${i}" ${aiOn ? '' : 'disabled'}>${esc(t(k))}</button>`).join('')}</div>
      <div id="faanswer"></div>
    </div>
    <div class="card pad" style="margin-top:16px">
      <div class="page-head sub-head"><div><h2>${t('fa.insights')}</h2><p class="sub">${t('fa.insights.sub')}</p></div></div>
      <div id="fainsights"><div class="muted">${t('common.loading')}</div></div>
    </div>`;

  const ask = async (q) => {
    const box = $('#faanswer');
    box.innerHTML = `<div class="banner">${t('fa.asking')}</div>`;
    try {
      const r = await api('/api/fleet/ask', { method: 'POST', body: { question: q } });
      box.innerHTML = `<div class="muted small" style="margin-top:12px"><b>${t('fa.answer')}</b> · ${t('fa.model').replace('{m}', esc(r.model || 'AI')).replace('{n}', r.considered)}</div>
        <pre class="aiout-text">${esc(r.answer)}</pre>`;
    } catch (e) { box.innerHTML = `<div class="banner crit">⚠ ${esc(e.message)}</div>`; }
  };
  if (aiOn) {
    $('#faask').onclick = () => { const q = $('#faq').value.trim(); if (q) ask(q); };
    $$('#fapresets .chip').forEach((c) => (c.onclick = () => { const q = t(PRESETS[+c.dataset.i][0]); $('#faq').value = q; ask(q); }));
  }

  // Deterministic insights (work without AI).
  try {
    const s = await api('/api/fleet/summary');
    const FLAGS = ['weak_cpu', 'low_ram', 'low_disk', 'slow_nic', 'high_cpu', 'high_mem', 'high_disk', 'offline'];
    $('#fainsights').innerHTML = !s.count ? `<div class="empty">${t('fa.insights.none')}</div>`
      : `<div class="tiles">${FLAGS.map((f) => {
          const hosts = s.devices.filter((d) => d.flags.includes(f)).map((d) => d.hostname);
          const n = hosts.length;
          return `<div class="tile" style="cursor:default">
            <div class="row" style="justify-content:space-between"><span class="muted small">${esc(t('fa.f.' + f))}</span>
              <b class="${n ? (f.startsWith('high') || f === 'low_disk' ? 'crit-text' : '') : ''}">${n || t('fa.allgood')}</b></div>
            ${n ? `<div class="small" style="margin-top:6px;line-height:1.5">${hosts.slice(0, 8).map(esc).join(', ')}${n > 8 ? ` +${n - 8}` : ''}</div>` : ''}</div>`;
        }).join('')}</div>
        <p class="muted small" style="margin-top:10px">${s.count} ${t('fa.stations')}</p>`;
  } catch (e) { $('#fainsights').innerHTML = `<div class="banner crit">⚠ ${esc(e.message)}</div>`; }
}

async function boot() {
  try { state.me = await api('/api/me'); } catch { return; }
  $('#login').classList.add('hidden');
  $('#app').classList.remove('hidden');
  const m = state.me;
  $('#me').innerHTML = `${esc(m.display_name || m.user)}<br><small class="muted">${esc(roleLabel(m.role))}${m.scope_label ? ' · ' + esc(m.scope_label) : ''}</small>`;
  $$('.side nav a[data-cap]').forEach((a) => a.classList.toggle('hidden', !cap(a.dataset.cap)));
  applyStaticI18n();
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
document.addEventListener('click', (e) => { const b = e.target.closest('.langsw [data-lang]'); if (b) setLang(b.dataset.lang); });
applyDir();
applyStaticI18n();
boot();
