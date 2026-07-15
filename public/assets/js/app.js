/* =====================================================================
   Server Manager — SPA controller (jQuery)
   ===================================================================== */
(function ($) {
    'use strict';

    // -----------------------------------------------------------------
    // API client
    // -----------------------------------------------------------------
    const API = {
        base: '/api',
        request(method, path, body) {
            return $.ajax({
                url: this.base + path,
                method: method,
                contentType: 'application/json',
                dataType: 'json',
                xhrFields: { withCredentials: true },
                data: body ? JSON.stringify(body) : undefined
            }).then(
                (res) => res,
                (xhr) => {
                    const msg = (xhr.responseJSON && xhr.responseJSON.error) || xhr.statusText || 'Request failed';
                    UI.toast('error', 'API error', msg);
                    return $.Deferred().reject(msg).promise();
                }
            );
        },
        get(p) { return this.request('GET', p); },
        post(p, b) { return this.request('POST', p, b); },
        del(p) { return this.request('DELETE', p); }
    };

    // -----------------------------------------------------------------
    // Small helpers
    // -----------------------------------------------------------------
    const H = {
        esc(s) { return $('<div>').text(s == null ? '' : String(s)).html(); },
        bytes(n) {
            n = Number(n) || 0;
            const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
            let i = 0;
            while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
            return n.toFixed(i ? 1 : 0) + ' ' + u[i];
        },
        pct(n) { return (Number(n) || 0).toFixed(1) + '%'; },
        meterClass(v, warn, crit) { return v >= crit ? 'crit' : (v >= warn ? 'warn' : 'good'); },
        ago(ts) {
            if (!ts) return '—';
            const d = Math.floor((Date.now() - new Date(ts.replace(' ', 'T') + 'Z').getTime()) / 1000);
            if (isNaN(d)) return H.esc(ts);
            if (d < 60) return d + 's ago';
            if (d < 3600) return Math.floor(d / 60) + 'm ago';
            if (d < 86400) return Math.floor(d / 3600) + 'h ago';
            return Math.floor(d / 86400) + 'd ago';
        },
        dur(sec) {
            if (sec == null) return '∞';
            if (sec <= 0) return 'expired';
            const m = Math.floor(sec / 60), s = sec % 60;
            if (m < 60) return m + 'm ' + s + 's';
            const h = Math.floor(m / 60);
            return h + 'h ' + (m % 60) + 'm';
        }
    };

    // -----------------------------------------------------------------
    // UI utilities: toasts + modal
    // -----------------------------------------------------------------
    const UI = {
        toast(type, title, body) {
            const $t = $('<div class="toast"></div>').addClass(type)
                .append($('<div class="t-title"></div>').text(title))
                .append(body ? $('<div class="t-body"></div>').text(body) : '');
            $('#toasts').append($t);
            setTimeout(() => $t.fadeOut(200, () => $t.remove()), 4200);
        },
        modal(title, contentHtml, onSubmit, submitLabel) {
            const $bk = $('<div class="modal-backdrop"></div>');
            const $m = $('<div class="modal"></div>')
                .append($('<h3></h3>').text(title))
                .append($('<div class="modal-body"></div>').html(contentHtml))
                .append(
                    $('<div class="modal-actions"></div>')
                        .append($('<button class="btn ghost">Cancel</button>').on('click', () => $bk.remove()))
                        .append($('<button class="btn"></button>').text(submitLabel || 'Save').on('click', () => {
                            const data = {};
                            $m.find('[name]').each(function () { data[this.name] = $(this).is(':checkbox') ? this.checked : $(this).val(); });
                            onSubmit(data, () => $bk.remove());
                        }))
                );
            $bk.append($m).on('click', (e) => { if (e.target === $bk[0]) $bk.remove(); });
            $('body').append($bk);
        },
        confirm(msg, cb) {
            this.modal('Confirm', '<p>' + H.esc(msg) + '</p>', (_d, close) => { close(); cb(); }, 'Confirm');
        },
        loading($el) { $el.html('<div class="loading"><div class="spinner"></div></div>'); }
    };

    // -----------------------------------------------------------------
    // Views registry
    // -----------------------------------------------------------------
    const Views = {};
    let currentView = 'overview';
    let refreshTimer = null;
    const charts = {};

    // ---- Overview ----------------------------------------------------
    Views.overview = {
        title: 'Overview',
        render($el) {
            $el.html(
                '<div class="grid cols-4" id="ovStats"></div>' +
                '<div class="grid cols-2" style="margin-top:16px">' +
                '  <div class="card"><h3>Resource usage <span class="sub">last 6h</span></h3><div class="chart-box"><canvas id="ovChart"></canvas></div></div>' +
                '  <div class="card"><h3>Critical services</h3><div id="ovServices"></div></div>' +
                '</div>' +
                '<div class="grid cols-2" style="margin-top:16px">' +
                '  <div class="card"><h3>Security posture</h3><div id="ovNids"></div></div>' +
                '  <div class="card"><h3>Top processes</h3><div id="ovProcs"></div></div>' +
                '</div>'
            );
            this.load();
        },
        load() {
            API.get('/system/overview').then((r) => {
                const d = r.data, s = d.system;
                $('#hostPill').text(s.hostname + ' · ' + s.os);
                const badge = s.health.status;
                $('#healthBadge').attr('class', 'health-badge ' + badge).text(badge);

                const cards = [
                    { label: 'CPU', value: H.pct(s.cpu.usage_pct), meter: s.cpu.usage_pct, warn: 75, crit: 90, sub: s.cpu.cores + ' cores' },
                    { label: 'Memory', value: H.pct(s.memory.used_pct), meter: s.memory.used_pct, warn: 80, crit: 92, sub: H.bytes(s.memory.used) + ' / ' + H.bytes(s.memory.total) },
                    { label: 'Disk /', value: H.pct(s.disk.used_pct), meter: s.disk.used_pct, warn: 80, crit: 90, sub: H.bytes(s.disk.free) + ' free' },
                    { label: 'Load (1m)', value: s.load['1'], meter: Math.min(100, s.load.per_core_1 * 100), warn: 70, crit: 90, sub: 'uptime ' + s.uptime.human }
                ];
                $('#ovStats').html(cards.map((c) => (
                    '<div class="card"><div class="stat"><span class="label">' + c.label + '</span>' +
                    '<span class="value">' + c.value + '</span></div>' +
                    '<div class="meter ' + H.meterClass(c.meter, c.warn, c.crit) + '"><span style="width:' + Math.min(100, c.meter) + '%"></span></div>' +
                    '<small class="muted">' + H.esc(c.sub) + '</small></div>'
                )).join(''));

                // Services
                $('#ovServices').html('<div class="table-wrap"><table class="data"><tbody>' +
                    d.services.map((sv) => (
                        '<tr><td><span class="dot ' + (sv.healthy ? 'good' : 'bad') + '"></span>' + H.esc(sv.name) + '</td>' +
                        '<td style="text-align:right"><span class="badge ' + (sv.healthy ? 'active' : 'failed') + '">' + H.esc(sv.state) + '</span></td></tr>'
                    )).join('') + '</tbody></table></div>');

                // NIDS
                const n = d.nids;
                $('#ovNids').html(
                    '<div class="grid cols-2">' +
                    statBox('Active blocks', n.active_blocks) +
                    statBox('Events 24h', n.events_24h) +
                    statBox('Critical 24h', n.critical_24h, n.critical_24h > 0 ? 'crit' : '') +
                    statBox('Firewall rules', d.firewall.total_rules) +
                    '</div>'
                );

                Views.overview.chart();
                Views.overview.procs();
            });
        },
        chart() {
            API.get('/system/metrics/history?hours=6').then((r) => {
                const rows = r.data;
                const labels = rows.map((x) => x.created_at.slice(11, 16));
                const ctx = document.getElementById('ovChart');
                if (!ctx) return;
                if (charts.ov) charts.ov.destroy();
                charts.ov = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [
                            ds('CPU %', rows.map((x) => x.cpu_pct), '#4f8cff'),
                            ds('Mem %', rows.map((x) => x.mem_pct), '#8a5cff'),
                            ds('Disk %', rows.map((x) => x.disk_pct), '#2ecc71')
                        ]
                    },
                    options: chartOpts()
                });
            });
        },
        procs() {
            API.get('/system/processes?limit=8').then((r) => {
                $('#ovProcs').html('<div class="table-wrap"><table class="data"><thead><tr><th>PID</th><th>Process</th><th>CPU</th><th>Mem</th></tr></thead><tbody>' +
                    r.data.map((p) => (
                        '<tr><td class="mono">' + p.pid + '</td><td>' + H.esc(p.name) + '</td>' +
                        '<td>' + p.cpu.toFixed(1) + '%</td><td>' + p.mem.toFixed(1) + '%</td></tr>'
                    )).join('') + '</tbody></table></div>');
            });
        }
    };

    // ---- Services ----------------------------------------------------
    Views.services = {
        title: 'Services',
        render($el) {
            $el.html(
                '<div class="toolbar"><input class="search" id="svcSearch" placeholder="Filter services…">' +
                '<button class="btn ghost small" id="svcReload">↻ Reload list</button></div>' +
                '<div class="card"><div id="svcTable"></div></div>'
            );
            $('#svcSearch').on('input', () => this.filter());
            $('#svcReload').on('click', () => this.load());
            this.load();
        },
        load() {
            UI.loading($('#svcTable'));
            API.get('/services').then((r) => { this.data = r.data; this.filter(); });
        },
        filter() {
            const q = ($('#svcSearch').val() || '').toLowerCase();
            const rows = (this.data || []).filter((s) => s.name.toLowerCase().includes(q));
            $('#svcTable').html('<div class="table-wrap"><table class="data"><thead><tr>' +
                '<th>Service</th><th>Load</th><th>State</th><th>Detail</th><th style="text-align:right">Actions</th></tr></thead><tbody>' +
                rows.map((s) => {
                    const st = s.active === 'active' ? 'active' : (s.active === 'failed' ? 'failed' : 'inactive');
                    const admin = SM.admin ? (
                        '<button class="btn small ghost" data-act="restart" data-svc="' + H.esc(s.name) + '">Restart</button> ' +
                        (s.active === 'active'
                            ? '<button class="btn small warn" data-act="stop" data-svc="' + H.esc(s.name) + '">Stop</button>'
                            : '<button class="btn small" data-act="start" data-svc="' + H.esc(s.name) + '">Start</button>')
                    ) : '<span class="muted">read-only</span>';
                    return '<tr><td>' + (s.critical ? '★ ' : '') + H.esc(s.name) + '</td>' +
                        '<td>' + H.esc(s.load) + '</td>' +
                        '<td><span class="badge ' + st + '">' + H.esc(s.active) + '</span> <span class="muted">' + H.esc(s.sub) + '</span></td>' +
                        '<td class="muted">' + H.esc(s.description) + '</td>' +
                        '<td style="text-align:right">' + admin + '</td></tr>';
                }).join('') + '</tbody></table></div>');

            $('#svcTable [data-act]').on('click', function () {
                const svc = $(this).data('svc'), act = $(this).data('act');
                UI.confirm(act + ' service "' + svc + '"?', () => {
                    API.post('/services/' + encodeURIComponent(svc) + '/' + act).then((res) => {
                        UI.toast('success', 'Service ' + act, svc + ' → ' + (res.data.status.active_state || 'done'));
                        Views.services.load();
                    });
                });
            });
        }
    };

    // ---- Firewall ----------------------------------------------------
    Views.firewall = {
        title: 'Firewall',
        render($el) {
            $el.html(
                '<div class="grid cols-4" id="fwStats"></div>' +
                '<div class="grid cols-2" style="margin-top:16px">' +
                '  <div class="card"><h3>iptables rules <span class="sub" id="fwTable-sub"></span></h3><div id="fwRules"></div></div>' +
                '  <div class="card"><h3>Listening ports <span class="sub">attack surface</span></h3><div id="fwPorts"></div></div>' +
                '</div>'
            );
            this.load();
        },
        load() {
            API.get('/firewall/summary').then((r) => {
                const s = r.data;
                $('#fwStats').html(
                    statBox('Total rules', s.total_rules) +
                    statBox('Drop / reject', s.drop_rules) +
                    statBox('Accept', s.accept_rules) +
                    statBox('Chains', s.chains)
                );
            });
            UI.loading($('#fwRules'));
            API.get('/firewall/rules').then((r) => {
                const chains = r.data.chains || [];
                $('#fwRules').html(chains.map((c) => (
                    '<h4 style="margin:12px 0 6px">' + H.esc(c.name) + ' <span class="muted">(' + H.esc(c.policy) + ')</span></h4>' +
                    '<div class="table-wrap"><table class="data"><thead><tr><th>#</th><th>Pkts</th><th>Bytes</th><th>Target</th><th>Proto</th><th>Source</th><th>Detail</th></tr></thead><tbody>' +
                    (c.rules.length ? c.rules.map((rule) => (
                        '<tr><td>' + rule.num + '</td><td class="mono">' + rule.pkts.toLocaleString() + '</td>' +
                        '<td class="mono">' + H.bytes(rule.bytes) + '</td>' +
                        '<td><span class="badge ' + (rule.target === 'DROP' || rule.target === 'REJECT' ? 'failed' : (rule.target === 'ACCEPT' ? 'active' : 'info')) + '">' + H.esc(rule.target) + '</span></td>' +
                        '<td>' + H.esc(rule.prot) + '</td><td class="mono">' + H.esc(rule.source) + '</td><td class="muted">' + H.esc(rule.extra) + '</td></tr>'
                    )).join('') : '<tr><td colspan="7" class="muted">no rules</td></tr>') +
                    '</tbody></table></div>'
                )).join(''));
            });
            API.get('/firewall/ports').then((r) => {
                $('#fwPorts').html('<div class="table-wrap"><table class="data"><thead><tr><th>Proto</th><th>Local</th><th>Process</th></tr></thead><tbody>' +
                    r.data.map((p) => '<tr><td>' + H.esc(p.proto) + '</td><td class="mono">' + H.esc(p.local) + '</td><td class="muted">' + H.esc(p.process) + '</td></tr>').join('') +
                    '</tbody></table></div>');
            });
        }
    };

    // ---- NIDS --------------------------------------------------------
    Views.nids = {
        title: 'NIDS / Blocks',
        render($el) {
            $el.html(
                '<div class="grid cols-4" id="nidsStats"></div>' +
                '<div class="section-head" style="margin-top:16px"><h2>Blocked hosts</h2>' +
                (SM.admin ? '<div class="actions"><button class="btn" id="blockBtn">＋ Block host</button></div>' : '') + '</div>' +
                '<div class="card"><div id="blocksTable"></div></div>' +
                '<div class="grid cols-2" style="margin-top:16px">' +
                '  <div class="card"><h3>Top offenders <span class="sub">24h</span></h3><div id="offenders"></div></div>' +
                '  <div class="card"><h3>Recent events</h3><div id="nidsEvents"></div></div>' +
                '</div>'
            );
            $('#blockBtn').on('click', () => this.blockModal());
            this.load();
        },
        load() {
            API.get('/nids/stats').then((r) => {
                const n = r.data;
                $('#nidsStats').html(
                    statBox('Active blocks', n.active_blocks) +
                    statBox('Permanent', n.permanent) +
                    statBox('Events 24h', n.events_24h) +
                    statBox('Critical 24h', n.critical_24h, n.critical_24h > 0 ? 'crit' : '')
                );
            });
            UI.loading($('#blocksTable'));
            API.get('/nids/blocks').then((r) => {
                $('#blocksTable').html('<div class="table-wrap"><table class="data"><thead><tr>' +
                    '<th>IP</th><th>Reason</th><th>Source</th><th>Hits</th><th>Expires</th><th>By</th>' + (SM.admin ? '<th></th>' : '') + '</tr></thead><tbody>' +
                    (r.data.length ? r.data.map((b) => (
                        '<tr><td class="mono">' + H.esc(b.ip_address) + '</td>' +
                        '<td>' + H.esc(b.reason || '—') + '</td>' +
                        '<td><span class="badge info">' + H.esc(b.source) + '</span></td>' +
                        '<td class="mono">' + (b.hits || 0).toLocaleString() + '</td>' +
                        '<td>' + (b.permanent == 1 ? '<span class="badge failed">permanent</span>' : H.dur(b.remaining_seconds)) + '</td>' +
                        '<td class="muted">' + H.esc(b.created_by || '') + '</td>' +
                        (SM.admin ? '<td style="text-align:right"><button class="btn small ghost" data-unblock="' + H.esc(b.ip_address) + '">Unblock</button></td>' : '') +
                        '</tr>'
                    )).join('') : '<tr><td colspan="7" class="muted">no active blocks</td></tr>') +
                    '</tbody></table></div>');
                $('#blocksTable [data-unblock]').on('click', function () {
                    const ip = $(this).data('unblock');
                    UI.confirm('Unblock ' + ip + '?', () => API.post('/nids/unblock', { ip: ip }).then(() => {
                        UI.toast('success', 'Unblocked', ip); Views.nids.load();
                    }));
                });
            });
            API.get('/nids/offenders').then((r) => {
                $('#offenders').html('<div class="table-wrap"><table class="data"><thead><tr><th>IP</th><th>Events</th><th>Worst</th><th>Last</th>' + (SM.admin ? '<th></th>' : '') + '</tr></thead><tbody>' +
                    r.data.map((o) => (
                        '<tr><td class="mono">' + H.esc(o.src_ip) + '</td><td>' + o.events + '</td>' +
                        '<td><span class="badge ' + H.esc(o.worst) + '">' + H.esc(o.worst) + '</span></td>' +
                        '<td class="muted">' + H.ago(o.last_seen) + '</td>' +
                        (SM.admin ? '<td style="text-align:right"><button class="btn small danger" data-quickblock="' + H.esc(o.src_ip) + '">Block</button></td>' : '') + '</tr>'
                    )).join('') + '</tbody></table></div>');
                $('#offenders [data-quickblock]').on('click', function () {
                    const ip = $(this).data('quickblock');
                    API.post('/nids/block', { ip: ip, reason: 'Manual block from offenders', minutes: 60, source: 'manual' })
                        .then(() => { UI.toast('success', 'Blocked', ip); Views.nids.load(); });
                });
            });
            API.get('/nids/events?limit=40').then((r) => {
                $('#nidsEvents').html('<div class="table-wrap"><table class="data"><thead><tr><th>Time</th><th>Src</th><th>Category</th><th>Sev</th></tr></thead><tbody>' +
                    r.data.map((e) => (
                        '<tr><td class="muted">' + H.ago(e.created_at) + '</td><td class="mono">' + H.esc(e.src_ip) + '</td>' +
                        '<td>' + H.esc(e.category) + '</td><td><span class="badge ' + H.esc(e.severity) + '">' + H.esc(e.severity) + '</span></td></tr>'
                    )).join('') + '</tbody></table></div>');
            });
        },
        blockModal() {
            UI.modal('Block a host',
                '<div class="field"><label>IP address</label><input name="ip" placeholder="203.0.113.5"></div>' +
                '<div class="field"><label>Reason</label><input name="reason" placeholder="Manual block"></div>' +
                '<div class="field"><label>Duration (minutes, 0 = default)</label><input name="minutes" type="number" value="60"></div>' +
                '<div class="field"><label><input type="checkbox" name="permanent"> Permanent (until manually removed)</label></div>',
                (d, close) => {
                    if (!d.ip) { UI.toast('warn', 'IP required'); return; }
                    API.post('/nids/block', { ip: d.ip, reason: d.reason, minutes: Number(d.minutes) || 0, permanent: d.permanent, source: 'manual' })
                        .then((res) => {
                            if (res.data.ok) { UI.toast('success', 'Host blocked', d.ip); close(); Views.nids.load(); }
                            else UI.toast('error', 'Block failed', res.data.error);
                        });
                }, 'Block');
        }
    };

    // ---- Traffic map -------------------------------------------------
    Views.traffic = {
        title: 'Traffic Map',
        _map: null,
        _layer: null,
        _hours: 24,
        render($el) {
            // The container is rebuilt on every render, so drop any stale map.
            if (this._map) { try { this._map.remove(); } catch (e) {} this._map = null; this._layer = null; }
            $el.html(
                '<div class="section-head"><h2>Traffic flows <span class="sub">apache · firewall · app logs</span></h2>' +
                '<div class="actions">' +
                '  <select id="trHours" class="btn ghost">' +
                '    <option value="1">Last 1h</option><option value="6">Last 6h</option>' +
                '    <option value="24" selected>Last 24h</option><option value="168">Last 7d</option>' +
                '  </select>' +
                (SM.admin ? '<button class="btn ghost" id="trIngest">⟳ Ingest now</button>' : '') +
                '</div></div>' +
                '<div class="grid cols-4" id="trStats"></div>' +
                '<div class="card" style="margin-top:16px;padding:0;overflow:hidden">' +
                '  <div id="trMap" style="height:440px;width:100%;background:#0d1526"></div></div>' +
                '<div class="grid cols-2" style="margin-top:16px">' +
                '  <div class="card"><h3>Top sources <span class="sub">by volume · ISP · country · URL</span></h3><div id="trSources"></div></div>' +
                '  <div class="card"><h3>By country</h3><div id="trCountries"></div></div>' +
                '</div>' +
                '<div class="grid cols-2" style="margin-top:16px">' +
                '  <div class="card"><h3>By ISP / network</h3><div id="trIsps"></div></div>' +
                '  <div class="card"><h3>By application</h3><div id="trApps"></div></div>' +
                '</div>'
            );
            $('#trHours').val(String(this._hours)).on('change', () => {
                this._hours = Number($('#trHours').val()) || 24;
                this.load();
            });
            $('#trIngest').on('click', () => {
                UI.toast('info', 'Ingesting traffic…');
                API.post('/traffic/ingest', {}).then((r) => {
                    const d = r.data || {};
                    const warns = d.warnings || [];
                    if (warns.length) {
                        UI.toast('warn', 'Ingest complete (with warnings)', warns.join(' • '));
                    } else {
                        UI.toast('success', 'Ingest complete',
                            'allow ' + (d.allow || 0) + ' · block ' + (d.block || 0) + ' · app ' + (d.app || 0));
                    }
                    this.load();
                }).catch(() => UI.toast('error', 'Ingest failed'));
            });
            this.initMap();
            this.load();
        },
        initMap() {
            if (typeof L === 'undefined') { return; }
            if (this._map) { setTimeout(() => this._map.invalidateSize(), 50); return; }
            const map = L.map('trMap', { worldCopyJump: true, minZoom: 1, attributionControl: false })
                .setView([25, 0], 2);
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                subdomains: 'abcd', maxZoom: 19
            }).addTo(map);
            this._map = map;
            this._layer = L.layerGroup().addTo(map);
            setTimeout(() => map.invalidateSize(), 50);
        },
        load() {
            const hours = this._hours;
            API.get('/traffic/summary?hours=' + hours).then((r) => {
                const s = r.data;
                $('#trStats').html(
                    statBox('Allowed requests', (s.allowed_requests || 0).toLocaleString()) +
                    statBox('Allowed volume', H.bytes(s.allowed_bytes)) +
                    statBox('Blocked volume', H.bytes(s.blocked_bytes), s.blocked_bytes > 0 ? 'crit' : '') +
                    statBox('Sources · countries', (s.sources || 0) + ' · ' + (s.countries || 0))
                );
            });
            this.loadMap(hours);
            API.get('/traffic/sources?hours=' + hours + '&limit=25').then((r) => {
                $('#trSources').html('<div class="table-wrap"><table class="data"><thead><tr>' +
                    '<th>IP</th><th>Country</th><th>ISP</th><th>Top URL</th><th>Reqs</th><th>Volume</th></tr></thead><tbody>' +
                    (r.data.length ? r.data.map((x) => (
                        '<tr><td class="mono">' + H.esc(x.src_ip) + (Number(x.blocked_bytes) > 0 ? ' <span class="badge failed">blocked</span>' : '') + '</td>' +
                        '<td>' + H.esc(x.city ? x.city + ', ' : '') + H.esc(x.country || '—') + '</td>' +
                        '<td class="muted">' + H.esc(x.isp || '—') + '</td>' +
                        '<td class="mono" title="' + H.esc(x.apps || '') + '">' + H.esc((x.top_path || x.apps || '—')) + '</td>' +
                        '<td class="mono">' + (Number(x.requests) || 0).toLocaleString() + '</td>' +
                        '<td class="mono">' + H.bytes(x.bytes) + '</td></tr>'
                    )).join('') : '<tr><td colspan="6" class="muted">no traffic recorded yet</td></tr>') +
                    '</tbody></table></div>');
            });
            API.get('/traffic/countries?hours=' + hours).then((r) => {
                $('#trCountries').html(this.simpleTable(r.data, [
                    ['country', 'Country'], ['sources', 'Sources', true], ['requests', 'Reqs', true], ['bytes', 'Volume', 'bytes']
                ]));
            });
            API.get('/traffic/isps?hours=' + hours).then((r) => {
                $('#trIsps').html(this.simpleTable(r.data, [
                    ['isp', 'ISP / network'], ['sources', 'Sources', true], ['requests', 'Reqs', true], ['bytes', 'Volume', 'bytes']
                ]));
            });
            API.get('/traffic/apps?hours=' + hours).then((r) => {
                $('#trApps').html(this.simpleTable(r.data, [
                    ['app', 'Application'], ['sources', 'Sources', true], ['requests', 'Reqs', true],
                    ['errors', 'Errors', true], ['bytes', 'Volume', 'bytes']
                ]));
            });
        },
        loadMap(hours) {
            if (!this._map) { return; }
            API.get('/traffic/map?hours=' + hours).then((r) => {
                const d = r.data, layer = this._layer;
                layer.clearLayers();
                const srv = d.server;
                L.circleMarker([srv.lat, srv.lng], {
                    radius: 8, color: '#4f7cff', fillColor: '#4f7cff', fillOpacity: 0.9, weight: 2
                }).addTo(layer).bindPopup('<b>' + H.esc(srv.label) + '</b><br>this server');

                const maxBytes = Math.max(1, ...d.sources.map((s) => Number(s.bytes) || 0));
                d.sources.forEach((s) => {
                    const blocked = s.blocked;
                    const color = blocked ? '#ff5470' : '#33c48d';
                    const weight = 1 + 3 * Math.sqrt((Number(s.bytes) || 0) / maxBytes);
                    L.polyline(this.arc([s.lat, s.lng], [srv.lat, srv.lng]), {
                        color: color, weight: weight, opacity: 0.5
                    }).addTo(layer);
                    L.circleMarker([s.lat, s.lng], {
                        radius: 3 + 6 * Math.sqrt((Number(s.bytes) || 0) / maxBytes),
                        color: color, fillColor: color, fillOpacity: 0.7, weight: 1
                    }).addTo(layer).bindPopup(
                        '<b>' + H.esc(s.ip) + '</b><br>' +
                        H.esc((s.city ? s.city + ', ' : '') + (s.country || '')) + '<br>' +
                        H.esc(s.isp || '') + '<br>' +
                        (Number(s.requests) || 0).toLocaleString() + ' reqs · ' + H.bytes(s.bytes) +
                        (blocked ? '<br><span style="color:#ff5470">blocked traffic</span>' : '') +
                        (s.apps && s.apps.length ? '<br>apps: ' + H.esc(s.apps.join(', ')) : '')
                    );
                });
            });
        },
        // Quadratic curve between two lat/lng points for a nicer flow arc.
        arc(from, to) {
            const lat1 = from[0], lng1 = from[1], lat2 = to[0], lng2 = to[1];
            const mLat = (lat1 + lat2) / 2, mLng = (lng1 + lng2) / 2;
            const dx = lng2 - lng1, dy = lat2 - lat1;
            const cLat = mLat + dx * 0.15, cLng = mLng - dy * 0.15; // control point offset
            const pts = [];
            for (let t = 0; t <= 1.0001; t += 0.05) {
                const it = 1 - t;
                pts.push([
                    it * it * lat1 + 2 * it * t * cLat + t * t * lat2,
                    it * it * lng1 + 2 * it * t * cLng + t * t * lng2
                ]);
            }
            return pts;
        },
        simpleTable(rows, cols) {
            const head = cols.map((c) => '<th' + (c[2] ? ' class="num"' : '') + '>' + H.esc(c[1]) + '</th>').join('');
            const body = rows && rows.length ? rows.map((row) => '<tr>' + cols.map((c) => {
                let v = row[c[0]];
                if (c[2] === 'bytes') { v = H.bytes(v); }
                else if (c[2] === true) { v = (Number(v) || 0).toLocaleString(); }
                else { v = H.esc(v || '—'); }
                return '<td' + (c[2] ? ' class="mono"' : '') + '>' + v + '</td>';
            }).join('') + '</tr>').join('') : '<tr><td colspan="' + cols.length + '" class="muted">no data</td></tr>';
            return '<div class="table-wrap"><table class="data"><thead><tr>' + head + '</tr></thead><tbody>' + body + '</tbody></table></div>';
        }
    };

    // ---- Applications ------------------------------------------------
    Views.apps = {
        title: 'Applications',
        render($el) {
            $el.html(
                '<div class="section-head"><h2>Managed applications</h2><div class="actions">' +
                (SM.admin ? '<button class="btn ghost" id="discoverBtn">🔍 Discover</button><button class="btn ghost" id="pairBtn">🔗 Pair app</button><button class="btn" id="registerBtn">＋ Register app</button>' : '') +
                '</div></div>' +
                '<div class="card"><div id="appsTable"></div></div>' +
                '<div id="discoverResults"></div>'
            );
            $('#registerBtn').on('click', () => this.registerModal());
            $('#pairBtn').on('click', () => this.pairModal());
            $('#discoverBtn').on('click', () => this.discover());
            this.load();
        },
        load() {
            UI.loading($('#appsTable'));
            API.get('/apps').then((r) => {
                $('#appsTable').html('<div class="table-wrap"><table class="data"><thead><tr>' +
                    '<th>App</th><th>Path</th><th>Domain</th><th>Status</th><th>Health</th><th style="text-align:right">Actions</th></tr></thead><tbody>' +
                    (r.data.length ? r.data.map((a) => (
                        '<tr><td><strong>' + H.esc(a.name) + '</strong><br><span class="muted mono">' + H.esc(a.slug) + '</span></td>' +
                        '<td class="mono">' + H.esc(a.path) + '</td>' +
                        '<td>' + (a.domain ? H.esc(a.domain) : '<span class="muted">—</span>') + '</td>' +
                        '<td><span class="badge ' + H.esc(a.status) + '">' + H.esc(a.status) + '</span></td>' +
                        '<td>' + (a.last_health ? '<span class="badge ' + H.esc(a.last_health) + '">' + H.esc(a.last_health) + '</span>' : '<span class="muted">unknown</span>') + '</td>' +
                        '<td style="text-align:right"><button class="btn small ghost" data-health="' + a.id + '">Check</button>' +
                        (SM.admin ? ' <button class="btn small" data-edit="' + a.id + '">Edit</button>' : '') +
                        (SM.admin ? ' <button class="btn small danger" data-remove="' + a.id + '">Remove</button>' : '') + '</td></tr>'
                    )).join('') : '<tr><td colspan="6" class="muted">No apps registered. Use Discover to find apps under /var/www.</td></tr>') +
                    '</tbody></table></div>');
                $('#appsTable [data-health]').on('click', function () {
                    const id = $(this).data('health');
                    API.post('/apps/' + id + '/health').then((res) => {
                        UI.toast('success', 'Health', 'Status: ' + (res.data.status || 'unknown')); Views.apps.load();
                    });
                });
                $('#appsTable [data-edit]').on('click', function () {
                    const id = $(this).data('edit');
                    API.get('/apps/' + id).then((res) => Views.apps.editModal(res.data));
                });
                $('#appsTable [data-remove]').on('click', function () {
                    const id = $(this).data('remove');
                    UI.confirm('Remove this app from the registry?', () => API.del('/apps/' + id).then(() => { UI.toast('success', 'Removed'); Views.apps.load(); }));
                });
            });
        },
        discover() {
            UI.loading($('#discoverResults'));
            API.get('/apps/discover').then((r) => {
                const found = r.data.discovered || [];
                $('#discoverResults').html('<div class="card" style="margin-top:16px"><h3>Discovered unmanaged apps <span class="sub">' + r.data.root + '</span></h3>' +
                    (found.length ? '<div class="table-wrap"><table class="data"><thead><tr><th>Name</th><th>Path</th><th>Stack</th><th>Git</th><th>Helper</th><th></th></tr></thead><tbody>' +
                        found.map((f) => (
                            '<tr><td>' + H.esc(f.name) + '</td><td class="mono">' + H.esc(f.path) + '</td>' +
                            '<td>' + f.detected.map((s) => '<span class="badge info">' + H.esc(s) + '</span>').join(' ') + '</td>' +
                            '<td>' + (f.has_git ? '✔' : '—') + '</td><td>' + (f.has_helper ? '✔' : '—') + '</td>' +
                            '<td style="text-align:right"><button class="btn small" data-adopt=\'' + H.esc(JSON.stringify({ name: f.name, path: f.path })) + '\'>Adopt</button></td></tr>'
                        )).join('') + '</tbody></table></div>'
                        : '<p class="muted">No unmanaged apps found.</p>') + '</div>');
                $('#discoverResults [data-adopt]').on('click', function () {
                    const info = JSON.parse($(this).attr('data-adopt'));
                    Views.apps.registerModal(info);
                });
            });
        },
        registerModal(prefill) {
            prefill = prefill || {};
            UI.modal('Register application',
                '<div class="field"><label>Name</label><input name="name" value="' + H.esc(prefill.name || '') + '"></div>' +
                '<div class="field"><label>Path</label><input name="path" value="' + H.esc(prefill.path || '/var/www/') + '"></div>' +
                '<div class="field"><label>Domain</label><input name="domain" placeholder="app.mcnutt.cloud"></div>' +
                '<div class="field"><label>Helper URL <span class="muted">(full URL to helper.php)</span></label>' +
                '<input name="helper_url" placeholder="https://app.mcnutt.cloud/srvmgr/helper.php"></div>' +
                '<div class="field"><label>Repo URL</label><input name="repo_url" placeholder="git@…"></div>' +
                '<div class="field"><label>Database name</label><input name="db_name"></div>' +
                '<div class="field"><label>Health URL</label><input name="health_url" placeholder="https://app.mcnutt.cloud/health"></div>' +
                '<div class="field"><label>Helper token <span class="muted">(or pair instead)</span></label><input name="helper_token" placeholder="shared secret for helper.php"></div>',
                (d, close) => {
                    if (!d.name || !d.path) { UI.toast('warn', 'Name and path required'); return; }
                    API.post('/apps', d).then((res) => {
                        if (res.data.ok) { UI.toast('success', 'Registered', d.name); close(); Views.apps.load(); $('#discoverResults').empty(); }
                        else UI.toast('error', 'Failed', res.data.error);
                    });
                }, 'Register');
        },
        editModal(app) {
            app = app || {};
            const sel = (v, cur) => 'value="' + v + '"' + (cur === v ? ' selected' : '');
            UI.modal('Edit ' + (app.name || 'application'),
                '<div class="field"><label>Name</label><input name="name" value="' + H.esc(app.name || '') + '"></div>' +
                '<div class="field"><label>Slug <span class="muted">(identity — read only)</span></label>' +
                '<input value="' + H.esc(app.slug || '') + '" disabled></div>' +
                '<div class="field"><label>Description</label><input name="description" value="' + H.esc(app.description || '') + '"></div>' +
                '<div class="field"><label>Path</label><input name="path" value="' + H.esc(app.path || '') + '"></div>' +
                '<div class="field"><label>Domain</label><input name="domain" value="' + H.esc(app.domain || '') + '" placeholder="app.mcnutt.cloud"></div>' +
                '<div class="field"><label>Repo URL</label><input name="repo_url" value="' + H.esc(app.repo_url || '') + '"></div>' +
                '<div class="field"><label>Database name</label><input name="db_name" value="' + H.esc(app.db_name || '') + '"></div>' +
                '<div class="field"><label>Service name</label><input name="service_name" value="' + H.esc(app.service_name || '') + '"></div>' +
                '<div class="field"><label>Health URL</label><input name="health_url" value="' + H.esc(app.health_url || '') + '"></div>' +
                '<div class="field"><label>Helper URL <span class="muted">(full URL to helper.php)</span></label>' +
                '<input name="helper_url" value="' + H.esc(app.helper_url || '') + '" placeholder="https://app.mcnutt.cloud/srvmgr/helper.php"></div>' +
                '<div class="field"><label>Status</label><select name="status">' +
                    '<option ' + sel('active', app.status) + '>active</option>' +
                    '<option ' + sel('disabled', app.status) + '>disabled</option>' +
                    '<option ' + sel('maintenance', app.status) + '>maintenance</option>' +
                '</select></div>' +
                '<div class="field"><label>Helper token <span class="muted">(leave blank to keep current)</span></label>' +
                '<input name="helper_token" placeholder="•••••• set — unchanged"></div>',
                (d, close) => {
                    if (!d.name) { UI.toast('warn', 'Name required'); return; }
                    API.post('/apps/' + app.id, d).then((res) => {
                        if (res.data.ok) { UI.toast('success', 'Saved', d.name); close(); Views.apps.load(); }
                        else UI.toast('error', 'Failed', res.data.error);
                    });
                }, 'Save');
        },
        pairModal() {
            API.get('/apps').then((r) => {
                const apps = (r.data || []).filter((a) => a && a.slug);
                const opts = ['<option value="">— New app —</option>'].concat(
                    apps.map((a) => '<option value="' + a.id + '">' + H.esc(a.name || a.slug) +
                        (a.domain ? ' (' + H.esc(a.domain) + ')' : '') +
                        (a.helper_token ? ' • paired' : '') + '</option>')
                ).join('');
                UI.modal('Pair application',
                    '<div class="card" style="margin:0 0 14px;padding:12px 14px">' +
                    '<strong>Step 1 — choose the app</strong>' +
                    '<p class="muted" style="margin:6px 0">Pick an existing registration to attach the secret to, ' +
                    'or start a new one. Pairing writes the shared secret into the selected app.</p>' +
                    '<div class="field"><select id="pairAppSelect">' + opts + '</select></div>' +
                    '<input type="hidden" name="slug"></div>' +
                    '<div class="card" style="margin:0 0 14px;padding:12px 14px">' +
                    '<strong>Step 2 — unlock the app</strong>' +
                    '<p class="muted" style="margin:6px 0">Generate a one-time unlock code, then enter it on the app\'s ' +
                    'helper page (<span class="mono">https://&lt;app&gt;/srvmgr/helper.php</span>). ' +
                    'That proves you\'re acting from this manager and reveals the app\'s enrollment key.</p>' +
                    '<button class="btn small" id="genCodeBtn" type="button">Generate unlock code</button>' +
                    '<div id="unlockCodeBox" style="margin-top:8px"></div></div>' +
                    '<div class="card" style="margin:0;padding:12px 14px">' +
                    '<strong>Step 3 — finish pairing</strong>' +
                    '<p class="muted" style="margin:6px 0">Paste the enrollment key the app showed after unlocking.</p>' +
                    '<div class="field"><label>Enrollment key <span class="muted">(auto-fills URL + challenge)</span></label>' +
                    '<input name="enroll_key" placeholder="base64 enrollment key from the helper page"></div>' +
                    '<div class="field"><label>…or Helper URL + Challenge</label>' +
                    '<input name="helper_url" placeholder="https://app.mcnutt.cloud/srvmgr/helper.php"></div>' +
                    '<div class="field"><label>Challenge key</label><input name="challenge" placeholder="XXXX-XXXX-XXXX-XXXX"></div>' +
                    '<div class="field"><label>Name</label><input name="name" placeholder="My app"></div>' +
                    '<div class="field"><label>Path</label><input name="path" value="/var/www/"></div>' +
                    '<div class="field"><label>Health URL <span class="muted">(optional)</span></label>' +
                    '<input name="health_url" placeholder="https://app.mcnutt.cloud/health"></div></div>',
                    (d, close) => {
                        if (!d.enroll_key && !d.challenge) { UI.toast('warn', 'Enrollment or challenge key required'); return; }
                        if (!d.path) { UI.toast('warn', 'Path required'); return; }
                        UI.toast('info', 'Pairing…', 'Contacting the app helper');
                        API.post('/apps/enroll', d).then((res) => {
                            if (res.data.ok) { UI.toast('success', 'Paired', d.name || res.data.app && res.data.app.slug || 'app'); close(); Views.apps.load(); $('#discoverResults').empty(); }
                            else UI.toast('error', 'Pairing failed', res.data.error);
                        });
                    }, 'Pair');
                // Selecting an existing registration pre-fills the pairing fields.
                $('#pairAppSelect').on('change', function () {
                    const app = apps.find((a) => String(a.id) === String($(this).val()));
                    const $m = $(this).closest('.modal');
                    if (!app) { $m.find('[name=slug]').val(''); return; }
                    $m.find('[name=slug]').val(app.slug || '');
                    $m.find('[name=name]').val(app.name || '');
                    $m.find('[name=path]').val(app.path || '/var/www/');
                    $m.find('[name=helper_url]').val(app.helper_url || '');
                    $m.find('[name=health_url]').val(app.health_url || '');
                });
                $('#genCodeBtn').on('click', function () {
                    const $btn = $(this).prop('disabled', true).text('Generating…');
                    API.post('/apps/pair/code', {}).then((res) => {
                        $btn.prop('disabled', false).text('Regenerate unlock code');
                        if (res.data && res.data.code) {
                            const mins = Math.round((res.data.expires_in || 900) / 60);
                            $('#unlockCodeBox').html('<div class="mono" style="font-size:20px;letter-spacing:2px;background:#1c1c1c;border:1px solid #333;border-radius:8px;padding:12px 14px;color:#7dd3fc">' +
                                H.esc(res.data.code) + '</div><span class="muted">Enter this on the app\'s helper page — valid for ' + mins + ' min.</span>');
                        } else {
                            UI.toast('error', 'Could not issue code', (res.data && res.data.error) || '');
                        }
                    });
                });
            });
        }
    };

    // ---- Logs --------------------------------------------------------
    Views.logs = {
        title: 'Logs & Usage',
        render($el) {
            $el.html(
                '<div class="grid cols-3" id="logStats"></div>' +
                '<div class="grid cols-2" style="margin-top:16px">' +
                '  <div class="card"><h3>HTTP status codes</h3><div class="chart-box"><canvas id="statusChart"></canvas></div></div>' +
                '  <div class="card"><h3>Top requested paths</h3><div id="topPaths"></div></div>' +
                '</div>' +
                '<div class="card" style="margin-top:16px"><h3>Log viewer ' +
                '<span class="sub"><select id="logSource"></select> ' +
                '<button class="btn small ghost" id="logRefresh">↻</button>' +
                (SM.admin ? ' <button class="btn small warn" id="scanBtn">Run threat scan</button>' : '') +
                '</span></h3><div class="terminal" id="logView"></div></div>'
            );
            API.get('/logs/sources').then((r) => {
                $('#logSource').html(r.data.map((s) => '<option>' + H.esc(s) + '</option>').join(''));
                this.tail();
            });
            $('#logRefresh, #logSource').on('click change', () => this.tail());
            $('#scanBtn').on('click', () => {
                API.post('/logs/scan').then((res) => UI.toast('success', 'Scan complete',
                    res.data.events + ' events, ' + (res.data.auto_blocked || []).length + ' auto-blocked'));
            });
            this.summary();
        },
        tail() {
            const src = $('#logSource').val() || 'syslog';
            $('#logView').text('loading…');
            API.get('/logs/tail?source=' + encodeURIComponent(src) + '&lines=200').then((r) => {
                $('#logView').text((r.data.lines || []).join('\n') || '(empty)');
                const el = document.getElementById('logView'); if (el) el.scrollTop = el.scrollHeight;
            });
        },
        summary() {
            API.get('/logs/access-summary').then((r) => {
                const d = r.data;
                if (!d.ok) { $('#logStats').html('<div class="card muted">Access log not available.</div>'); return; }
                $('#logStats').html(
                    statBox('Requests', d.requests.toLocaleString()) +
                    statBox('Transferred', H.bytes(d.bytes)) +
                    statBox('Error rate', d.error_rate + '%', d.error_rate > 5 ? 'crit' : '')
                );
                const ctx = document.getElementById('statusChart');
                if (ctx) {
                    if (charts.status) charts.status.destroy();
                    charts.status = new Chart(ctx, {
                        type: 'doughnut',
                        data: {
                            labels: Object.keys(d.status_counts),
                            datasets: [{ data: Object.values(d.status_counts), backgroundColor: ['#2ecc71', '#4f8cff', '#8a5cff', '#f5a623', '#ff5964', '#8b98b4'] }]
                        },
                        options: { plugins: { legend: { labels: { color: '#8b98b4' } } }, maintainAspectRatio: false }
                    });
                }
                $('#topPaths').html('<div class="table-wrap"><table class="data"><thead><tr><th>Path</th><th style="text-align:right">Hits</th></tr></thead><tbody>' +
                    Object.entries(d.top_paths).map(([p, c]) => '<tr><td class="mono">' + H.esc(p) + '</td><td style="text-align:right">' + c + '</td></tr>').join('') +
                    '</tbody></table></div>');
            });
        }
    };

    // ---- CLI Runner --------------------------------------------------
    Views.runner = {
        title: 'CLI Runner',
        render($el) {
            $el.html(
                '<div class="card"><h3>Whitelisted command runner <span class="sub">executes via protected Python runner</span></h3>' +
                '<div class="toolbar"><select id="runAction" style="min-width:200px"></select>' +
                '<input id="runArgs" class="search" placeholder=\'args JSON e.g. {"service":"apache2"}\' style="flex:1">' +
                '<button class="btn" id="runExec">▶ Execute</button></div>' +
                '<div class="terminal" id="runOut">Ready. Select an action and execute.\n</div></div>' +
                '<div class="card" style="margin-top:16px"><h3>Execution history</h3><div id="runHistory"></div></div>'
            );
            API.get('/runner/actions').then((r) => {
                $('#runAction').html(r.data.map((a) => '<option>' + H.esc(a) + '</option>').join(''));
            });
            $('#runExec').on('click', () => this.exec());
            this.history();
        },
        exec() {
            if (!SM.admin) { UI.toast('warn', 'Admin required'); return; }
            const action = $('#runAction').val();
            let args = {};
            const raw = $('#runArgs').val().trim();
            if (raw) { try { args = JSON.parse(raw); } catch (e) { UI.toast('error', 'Invalid JSON args'); return; } }
            const $out = $('#runOut');
            $out.append($('<div class="cmd"></div>').text('$ ' + action + ' ' + raw));
            API.post('/runner/exec', { action: action, args: args }).then((r) => {
                const d = r.data;
                $out.append($('<div></div>').addClass(d.ok ? 'ok' : 'err').text('exit=' + d.exit_code));
                if (d.stdout) $out.append(document.createTextNode(d.stdout + '\n'));
                if (d.stderr) $out.append($('<div class="err"></div>').text(d.stderr));
                if (d.data && Object.keys(d.data).length) $out.append(document.createTextNode(JSON.stringify(d.data, null, 2) + '\n'));
                $out[0].scrollTop = $out[0].scrollHeight;
                this.history();
            });
        },
        history() {
            API.get('/runner/history').then((r) => {
                $('#runHistory').html('<div class="table-wrap"><table class="data"><thead><tr><th>Time</th><th>Actor</th><th>Command</th><th>Exit</th><th>ms</th></tr></thead><tbody>' +
                    r.data.map((h) => (
                        '<tr><td class="muted">' + H.ago(h.created_at) + '</td><td>' + H.esc(h.actor) + '</td>' +
                        '<td class="mono">' + H.esc(h.command_key) + '</td>' +
                        '<td><span class="badge ' + (h.exit_code === 0 ? 'active' : 'failed') + '">' + h.exit_code + '</span></td>' +
                        '<td>' + (h.duration_ms || 0) + '</td></tr>'
                    )).join('') + '</tbody></table></div>');
            });
        }
    };

    // ---- Audit -------------------------------------------------------
    Views.audit = {
        title: 'Audit',
        render($el) {
            $el.html('<div class="card"><h3>Audit trail <span class="sub">last 200 privileged actions</span></h3><div id="auditTable"></div></div>');
            this.load();
        },
        load() {
            UI.loading($('#auditTable'));
            API.get('/audit').then((r) => {
                $('#auditTable').html('<div class="table-wrap"><table class="data"><thead><tr>' +
                    '<th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th><th>IP</th></tr></thead><tbody>' +
                    r.data.map((a) => (
                        '<tr><td class="muted">' + H.ago(a.created_at) + '</td><td>' + H.esc(a.actor) + '</td>' +
                        '<td class="mono">' + H.esc(a.action) + '</td><td class="mono">' + H.esc(a.target || '') + '</td>' +
                        '<td><span class="badge ' + H.esc(a.result) + '">' + H.esc(a.result) + '</span></td>' +
                        '<td class="mono muted">' + H.esc(a.ip_address || '') + '</td></tr>'
                    )).join('') + '</tbody></table></div>');
            });
        }
    };

    // -----------------------------------------------------------------
    // Shared render helpers
    // -----------------------------------------------------------------
    function statBox(label, value, cls) {
        return '<div class="card"><div class="stat"><span class="label">' + H.esc(label) + '</span>' +
            '<span class="value ' + (cls || '') + '" style="' + (cls === 'crit' ? 'color:var(--crit)' : '') + '">' + H.esc(value) + '</span></div></div>';
    }
    function ds(label, data, color) {
        return { label: label, data: data, borderColor: color, backgroundColor: color + '22', tension: 0.35, fill: true, pointRadius: 0, borderWidth: 2 };
    }
    function chartOpts() {
        return {
            maintainAspectRatio: false,
            interaction: { intersect: false, mode: 'index' },
            scales: {
                x: { ticks: { color: '#8b98b4', maxTicksLimit: 8 }, grid: { color: '#26324f33' } },
                y: { ticks: { color: '#8b98b4' }, grid: { color: '#26324f33' }, min: 0, max: 100 }
            },
            plugins: { legend: { labels: { color: '#8b98b4' } } }
        };
    }

    // -----------------------------------------------------------------
    // Router + lifecycle
    // -----------------------------------------------------------------
    function switchView(name) {
        if (!Views[name]) name = 'overview';
        currentView = name;
        $('.nav-item').removeClass('active').filter('[data-view="' + name + '"]').addClass('active');
        $('.view').addClass('hidden');
        const $el = $('#view-' + name).removeClass('hidden');
        $('#viewTitle').text(Views[name].title);
        Views[name].render($el);
    }

    function refreshCurrent() {
        const v = Views[currentView];
        if (v && typeof v.load === 'function') v.load();
        // overview also refreshes host pill/health
        if (currentView === 'overview') { /* handled by load */ }
    }

    function startAutoRefresh() {
        stopAutoRefresh();
        refreshTimer = setInterval(() => {
            if ($('#autoRefresh').is(':checked')) refreshCurrent();
        }, 15000);
    }
    function stopAutoRefresh() { if (refreshTimer) clearInterval(refreshTimer); }

    $(function () {
        // nav
        $('.nav-item').on('click', function (e) {
            e.preventDefault();
            switchView($(this).data('view'));
            $('.sidebar').removeClass('open');
        });
        $('#refreshBtn').on('click', refreshCurrent);
        $('#menuToggle').on('click', () => $('.sidebar').toggleClass('open'));

        // hash routing
        const initial = (location.hash || '#overview').slice(1);
        switchView(initial);

        // keep the health badge/host pill fresh globally
        setInterval(() => {
            if (currentView !== 'overview') {
                API.get('/system/metrics').then((r) => {
                    const s = r.data;
                    $('#hostPill').text(s.hostname + ' · ' + s.os);
                    $('#healthBadge').attr('class', 'health-badge ' + s.health.status).text(s.health.status);
                });
            }
        }, 20000);

        startAutoRefresh();
    });

})(jQuery);
