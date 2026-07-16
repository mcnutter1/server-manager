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
        modal(title, contentHtml, onSubmit, submitLabel, opts) {
            opts = opts || {};
            const $bk = $('<div class="modal-backdrop"></div>');
            const $m = $('<div class="modal' + (opts.size === 'wide' ? ' modal-wide' : '') + '"></div>')
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
                '</div>' +
                '<div class="section-head" style="margin-top:16px"><h2>Never block <span class="sub">allowlist · IPv4 · IPv6 · CIDR</span></h2>' +
                (SM.admin ? '<div class="actions"><button class="btn" id="neverBlockBtn">＋ Add address</button></div>' : '') + '</div>' +
                '<div class="card"><p class="muted" style="margin-top:0">These addresses and ranges are never auto-blocked or manually blocked, protecting your own control-plane, monitoring and office IPs.</p><div id="neverBlockTable"></div></div>'
            );
            $('#blockBtn').on('click', () => this.blockModal());
            if (SM.admin) { $('#neverBlockBtn').on('click', () => this.neverBlockModal()); }
            this.load();
        },
        load() {
            API.get('/nids/stats').then((r) => {
                const n = r.data, ti = n.threat_intel || {};
                $('#nidsStats').html(
                    statBox('Active blocks', n.active_blocks) +
                    statBox('Permanent', n.permanent) +
                    statBox('Events 24h', n.events_24h) +
                    statBox('Critical 24h', n.critical_24h, n.critical_24h > 0 ? 'crit' : '') +
                    statBox('Malicious IPs', ti.malicious_known || 0, (ti.malicious_known || 0) > 0 ? 'crit' : '')
                );
            });
            UI.loading($('#blocksTable'));
            API.get('/nids/blocks').then((r) => {
                $('#blocksTable').html('<div class="table-wrap"><table class="data"><thead><tr>' +
                    '<th>IP</th><th>Reason</th><th>Source</th><th>Hits</th><th>Expires</th><th>By</th>' + (SM.admin ? '<th></th>' : '') + '</tr></thead><tbody>' +
                    (r.data.length ? r.data.map((b) => (
                        '<tr class="clickable" data-nidsip="' + H.esc(b.ip_address) + '"><td class="mono">' + H.esc(b.ip_address) + '</td>' +
                        '<td>' + H.esc(b.reason || '—') + '</td>' +
                        '<td><span class="badge info">' + H.esc(b.source) + '</span></td>' +
                        '<td class="mono">' + (b.hits || 0).toLocaleString() + '</td>' +
                        '<td>' + (b.permanent == 1 ? '<span class="badge failed">permanent</span>' : H.dur(b.remaining_seconds)) + '</td>' +
                        '<td class="muted">' + H.esc(b.created_by || '') + '</td>' +
                        (SM.admin ? '<td style="text-align:right"><button class="btn small ghost" data-unblock="' + H.esc(b.ip_address) + '">Unblock</button></td>' : '') +
                        '</tr>'
                    )).join('') : '<tr><td colspan="7" class="muted">no active blocks</td></tr>') +
                    '</tbody></table></div>');
                $('#blocksTable tr[data-nidsip]').on('click', function () { Views.nids.openIp($(this).data('nidsip')); });
                $('#blocksTable [data-unblock]').on('click', function (e) {
                    e.stopPropagation();
                    const ip = $(this).data('unblock');
                    UI.confirm('Unblock ' + ip + '?', () => API.post('/nids/unblock', { ip: ip }).then(() => {
                        UI.toast('success', 'Unblocked', ip); Views.nids.load();
                    }));
                });
            });
            API.get('/nids/offenders').then((r) => {
                $('#offenders').html('<div class="table-wrap"><table class="data"><thead><tr><th>IP</th><th>Events</th><th>Worst</th><th>Last</th>' + (SM.admin ? '<th></th>' : '') + '</tr></thead><tbody>' +
                    r.data.map((o) => (
                        '<tr class="clickable" data-nidsip="' + H.esc(o.src_ip) + '"><td class="mono">' + H.esc(o.src_ip) + '</td><td>' + o.events + '</td>' +
                        '<td><span class="badge ' + H.esc(o.worst) + '">' + H.esc(o.worst) + '</span></td>' +
                        '<td class="muted">' + H.ago(o.last_seen) + '</td>' +
                        (SM.admin ? '<td style="text-align:right"><button class="btn small danger" data-quickblock="' + H.esc(o.src_ip) + '">Block</button></td>' : '') + '</tr>'
                    )).join('') + '</tbody></table></div>');
                $('#offenders tr[data-nidsip]').on('click', function () { Views.nids.openIp($(this).data('nidsip')); });
                $('#offenders [data-quickblock]').on('click', function (e) {
                    e.stopPropagation();
                    const ip = $(this).data('quickblock');
                    API.post('/nids/block', { ip: ip, reason: 'Manual block from offenders', minutes: 60, source: 'manual' })
                        .then(() => { UI.toast('success', 'Blocked', ip); Views.nids.load(); });
                });
            });
            API.get('/nids/events?limit=40').then((r) => {
                $('#nidsEvents').html('<div class="table-wrap"><table class="data"><thead><tr><th>Time</th><th>Src</th><th>Category</th><th>Sev</th></tr></thead><tbody>' +
                    r.data.map((e) => (
                        '<tr class="clickable" data-nidsip="' + H.esc(e.src_ip) + '"><td class="muted">' + H.ago(e.created_at) + '</td><td class="mono">' + H.esc(e.src_ip) + '</td>' +
                        '<td>' + H.esc(e.category) + '</td><td><span class="badge ' + H.esc(e.severity) + '">' + H.esc(e.severity) + '</span></td></tr>'
                    )).join('') + '</tbody></table></div>');
                $('#nidsEvents tr[data-nidsip]').on('click', function () { Views.nids.openIp($(this).data('nidsip')); });
            });
            this.loadNeverBlock();
        },
        loadNeverBlock() {
            UI.loading($('#neverBlockTable'));
            API.get('/nids/never-block').then((r) => {
                const entries = r.data.entries || [], cfg = r.data.config || [];
                const cfgRows = cfg.map((ip) => (
                    '<tr><td class="mono">' + H.esc(ip) + '</td><td class="muted">config baseline</td>' +
                    '<td class="muted">—</td>' + (SM.admin ? '<td class="muted" style="text-align:right">read-only</td>' : '') + '</tr>'
                )).join('');
                const rows = entries.map((e) => (
                    '<tr><td class="mono">' + H.esc(e.ip) + '</td>' +
                    '<td>' + (e.note ? H.esc(e.note) : '<span class="muted">—</span>') + '</td>' +
                    '<td class="muted">' + H.esc(e.added_by || '') + (e.added_at ? ' · ' + H.ago(e.added_at) : '') + '</td>' +
                    (SM.admin ? '<td style="text-align:right"><button class="btn small ghost" data-nbremove="' + H.esc(e.ip) + '">Remove</button></td>' : '') + '</tr>'
                )).join('');
                $('#neverBlockTable').html('<div class="table-wrap"><table class="data"><thead><tr>' +
                    '<th>Address / range</th><th>Note</th><th>Added</th>' + (SM.admin ? '<th></th>' : '') + '</tr></thead><tbody>' +
                    cfgRows + rows +
                    (!cfg.length && !entries.length ? '<tr><td colspan="4" class="muted">No allowlist entries.</td></tr>' : '') +
                    '</tbody></table></div>');
                $('#neverBlockTable [data-nbremove]').on('click', function () {
                    const ip = $(this).data('nbremove');
                    UI.confirm('Remove ' + ip + ' from the never-block list?', () => API.post('/nids/never-block/remove', { ip: String(ip) }).then((res) => {
                        if (res.data.ok) { UI.toast('success', 'Removed', String(ip)); Views.nids.loadNeverBlock(); }
                        else UI.toast('error', 'Remove failed', res.data.error);
                    }));
                });
            });
        },
        // ---- IP dossier drill-down -----------------------------------
        openIp(ip) { if (ip) { this.drill.open(ip); } },
        drill: {
            _bk: null, _ip: null, _data: null,
            open(ip) { this._ip = ip; this.ensure(); this.render(); },
            close() { if (this._bk) { this._bk.remove(); this._bk = null; } this._ip = null; this._data = null; },
            ensure() {
                if (this._bk) { return; }
                const self = this;
                const $bk = $('<div class="modal-backdrop"></div>');
                const $m = $('<div class="modal drill-modal"></div>')
                    .append('<div class="drill-head"><h3 id="nidsDrillTitle"></h3><button class="btn ghost sm" id="nidsDrillClose">\u2715</button></div>')
                    .append('<div class="modal-body" id="nidsDrillBody"></div>');
                $bk.append($m).on('click', (e) => { if (e.target === $bk[0]) { self.close(); } });
                $('body').append($bk);
                this._bk = $bk;
                $m.on('click', '#nidsDrillClose', () => self.close());
                $m.on('click', '[data-nidsblock]', function () {
                    const ip = String($(this).data('nidsblock'));
                    API.post('/nids/block', { ip: ip, reason: 'Manual block from dossier', minutes: 60, source: 'manual' })
                        .then((res) => {
                            if (res.data.ok) { UI.toast('success', 'Blocked', ip); Views.nids.load(); self.render(); }
                            else UI.toast('error', 'Block failed', res.data.error);
                        });
                });
                $m.on('click', '[data-nidsunblock]', function () {
                    const ip = String($(this).data('nidsunblock'));
                    UI.confirm('Unblock ' + ip + '?', () => API.post('/nids/unblock', { ip: ip }).then(() => {
                        UI.toast('success', 'Unblocked', ip); Views.nids.load(); self.render();
                    }));
                });
                $m.on('click', '#nidsRecheck', function () {
                    const ip = self._ip;
                    UI.toast('info', 'Querying threat feeds\u2026', ip);
                    API.post('/nids/ip/recheck', { ip: ip }).then(() => { UI.toast('success', 'Re-checked', ip); self.render(); })
                        .catch(() => UI.toast('error', 'Re-check failed', ip));
                });
            },
            render() {
                const self = this, ip = this._ip;
                $('#nidsDrillTitle').text('IP \u00b7 ' + ip);
                const $b = $('#nidsDrillBody'); UI.loading($b);
                API.get('/nids/ip?ip=' + encodeURIComponent(ip) + '&hours=24')
                    .then((r) => { self._data = r.data; $b.html(Views.nids.renderDossier(r.data)); })
                    .catch(() => $b.html('<p class="muted">failed to load</p>'));
            }
        },
        renderDossier(d) {
            const V = Views.traffic;
            const g = d.geo || {}, a = d.activity || {}, intel = d.intel || {}, ev = d.events || {}, es = ev.summary || {};
            const loc = [g.city, g.region, g.country].filter(Boolean).map(H.esc).join(', ') || '\u2014';
            const net = [];
            if (g.is_datacenter) { net.push('data center'); }
            if (g.is_proxy) { net.push('proxy / VPN'); }
            if (g.is_mobile) { net.push('mobile carrier'); }

            let intelBadge;
            if (intel.status === 'private') { intelBadge = '<span class="badge clean">private / internal</span>'; }
            else if (intel.status === 'disabled') { intelBadge = '<span class="badge">intel disabled</span>'; }
            else if (intel.is_malicious) { intelBadge = '<span class="badge failed">malicious \u00b7 score ' + Number(intel.score || 0) + '</span>'; }
            else if (Number(intel.score) > 0) { intelBadge = '<span class="badge flag">suspicious \u00b7 score ' + Number(intel.score) + '</span>'; }
            else if ((intel.sources || []).length || intel.checked_at) { intelBadge = '<span class="badge clean">no listings</span>'; }
            else { intelBadge = '<span class="badge">not checked</span>'; }

            const statusBadges =
                (d.blocked_now ? '<span class="badge failed">blocked now</span> ' : '') +
                (d.whitelisted ? '<span class="badge active">never-block</span> ' : '');

            const actions = SM.admin
                ? '<div class="drill-actions">' +
                    (d.blocked_now
                        ? '<button class="btn small ghost" data-nidsunblock="' + H.esc(d.ip) + '">Unblock</button>'
                        : (d.whitelisted ? '' : '<button class="btn small danger" data-nidsblock="' + H.esc(d.ip) + '">Block 60m</button>')) +
                    '<button class="btn small ghost" id="nidsRecheck">\u21bb Re-check threat feeds</button>' +
                  '</div>'
                : '';

            let html = actions + '<div class="drill-meta">' +
                V.metaCell('IP', '<span class="mono">' + H.esc(d.ip) + '</span> ' + statusBadges) +
                V.metaCell('Location', loc) +
                V.metaCell('ISP / network', H.esc(g.isp || '\u2014') + (g.org && g.org !== g.isp ? '<div class="muted" style="font-size:12px">' + H.esc(g.org) + '</div>' : '')) +
                V.metaCell('ASN', H.esc(g.asn || '\u2014')) +
                V.metaCell('Network type', net.length ? net.map(H.esc).join(', ') : 'residential / other') +
                V.metaCell('Threat intel', intelBadge) +
                V.metaCell('NIDS events', (es.events || 0).toLocaleString() + (es.severe ? ' \u00b7 <span class="badge crit">' + es.severe + ' severe</span>' : '') + (es.auth_events ? ' \u00b7 ' + es.auth_events + ' auth' : '')) +
                V.metaCell('Traffic', (a.requests || 0).toLocaleString() + ' reqs \u00b7 ' + H.bytes(a.bytes) + (a.blocked_bytes ? ' \u00b7 ' + H.bytes(a.blocked_bytes) + ' blocked' : '')) +
                '</div>';

            // Threat intelligence.
            html += '<div class="drill-section"><h4>Threat intelligence' + (intel.checked_at ? ' <span class="sub">checked ' + H.ago(intel.checked_at) + (intel.stale ? ' \u00b7 stale' : '') + '</span>' : '') + '</h4>';
            const srcs = intel.sources || [];
            if (intel.status === 'private') {
                html += '<p class="muted">Private / internal address \u2014 not checked against public feeds.</p>';
            } else if (intel.status === 'disabled') {
                html += '<p class="muted">Threat-intel lookups are disabled in config.</p>';
            } else if (srcs.length) {
                html += '<div class="intel-grid">' + srcs.map((s) => {
                    if (s.provider === 'AbuseIPDB') {
                        return '<div class="intel-src bad"><div class="isrc-name">AbuseIPDB</div>' +
                            '<div class="isrc-detail">confidence ' + Number(s.confidence || 0) + '% \u00b7 ' + Number(s.reports || 0) + ' reports' +
                            (s.usage_type ? ' \u00b7 ' + H.esc(s.usage_type) : '') +
                            (s.last_report ? ' \u00b7 last ' + H.ago(s.last_report) : '') + '</div></div>';
                    }
                    return '<div class="intel-src bad"><div class="isrc-name">' + H.esc(s.provider || 'DNSBL') + '</div>' +
                        '<div class="isrc-detail">listed' + (s.zone ? ' <span class="muted">(' + H.esc(s.zone) + ')</span>' : '') + '</div></div>';
                }).join('') + '</div>' +
                (intel.categories ? '<p class="muted" style="margin:8px 0 0">Categories: ' + H.esc(intel.categories) + '</p>' : '');
            } else {
                html += '<p class="muted">No listings on any configured threat database' + (intel.checked_at ? '.' : ' yet \u2014 use Re-check to query the feeds now.') + '</p>';
            }
            html += '</div>';

            // Block history.
            html += '<div class="drill-section"><h4>Block history <span class="sub">why this IP was blocked</span></h4>';
            if ((d.blocks || []).length) {
                html += '<div class="table-wrap"><table class="data"><thead><tr>' +
                    '<th>When</th><th>Reason</th><th>Source</th><th>By</th><th>State</th><th>Expiry</th></tr></thead><tbody>' +
                    d.blocks.map((b) => (
                        '<tr' + (b.active ? ' class="err"' : '') + '><td class="muted">' + H.ago(b.blocked_at) + '</td>' +
                        '<td>' + H.esc(b.reason || '\u2014') + '</td>' +
                        '<td><span class="badge info">' + H.esc(b.source || '\u2014') + '</span></td>' +
                        '<td class="muted">' + H.esc(b.created_by || '\u2014') + '</td>' +
                        '<td>' + (b.active ? '<span class="badge failed">active</span>' : '<span class="badge">lifted</span>') + '</td>' +
                        '<td>' + (b.permanent ? '<span class="badge failed">permanent</span>' : (b.remaining_seconds != null ? H.dur(b.remaining_seconds) : (b.unblocked_at ? 'unblocked ' + H.ago(b.unblocked_at) : '\u2014'))) + '</td></tr>'
                    )).join('') +
                    '</tbody></table></div>';
            } else {
                html += '<p class="muted">This IP has never been blocked.</p>';
            }
            html += '</div>';

            // NIDS behaviour by category.
            html += V.miniTable('Behaviour by category', ev.by_category, [['source', 'Source'], ['category', 'Category'], ['severity', 'Severity'], ['hits', 'Hits', 'num'], ['events', 'Events', 'num'], ['last_seen', 'Last', 'ago']], 'no NIDS events recorded');

            // Authentication attempts.
            const auth = ev.auth || [];
            html += '<div class="drill-section"><h4>Authentication attempts <span class="sub">SSH / login</span></h4>';
            if (auth.length) {
                html += '<div class="table-wrap"><table class="data"><thead><tr>' +
                    '<th>Time</th><th>Category</th><th>Sev</th><th>Port</th><th>Log line</th></tr></thead><tbody>' +
                    auth.map((e) => (
                        '<tr><td class="muted">' + H.ago(e.created_at) + '</td>' +
                        '<td>' + H.esc(e.category || '\u2014') + (Number(e.count) > 1 ? ' <span class="muted">\u00d7' + Number(e.count) + '</span>' : '') + '</td>' +
                        '<td><span class="badge ' + H.esc(e.severity || '') + '">' + H.esc(e.severity || '\u2014') + '</span></td>' +
                        '<td class="mono">' + H.esc(e.dst_port || '\u2014') + '</td>' +
                        '<td class="errline" title="' + H.esc(e.raw || '') + '">' + (e.raw ? H.esc(String(e.raw)) : '<span class="em">\u2014</span>') + '</td></tr>'
                    )).join('') +
                    '</tbody></table></div>';
            } else {
                html += '<p class="muted">No authentication attempts recorded from this IP.</p>';
            }
            html += '</div>';

            // Ports, services/apps, endpoints (shared traffic shapes).
            html += V.miniTable('Ports probed', d.ports, [['port', 'Port'], ['category', 'Category'], ['severity', 'Severity'], ['hits', 'Hits', 'num'], ['last_seen', 'Last', 'ago']], 'no port-level activity recorded');
            html += V.miniTable('Applications / services accessed', d.services, [['service', 'Service'], ['requests', 'Reqs', 'num'], ['bytes', 'Volume', 'bytes'], ['errors', 'Errors', 'num']], 'no application traffic');
            html += V.miniTable('Top endpoints', d.endpoints, [['method', 'Method'], ['path', 'Path'], ['status', 'Status'], ['requests', 'Reqs', 'num'], ['bytes', 'Volume', 'bytes']], 'no endpoints recorded');

            // Recent NIDS event timeline.
            const rev = ev.recent || [];
            if (rev.length) {
                html += '<div class="drill-section"><h4>Recent NIDS events</h4><div class="table-wrap"><table class="data"><thead><tr>' +
                    '<th>Time</th><th>Source</th><th>Category</th><th>Sev</th><th>Detail</th></tr></thead><tbody>' +
                    rev.map((e) => (
                        '<tr><td class="muted">' + H.ago(e.created_at) + '</td>' +
                        '<td class="mono">' + H.esc(e.source || '\u2014') + '</td>' +
                        '<td>' + H.esc(e.category || '\u2014') + '</td>' +
                        '<td><span class="badge ' + H.esc(e.severity || '') + '">' + H.esc(e.severity || '\u2014') + '</span></td>' +
                        '<td class="errline" title="' + H.esc(e.raw || '') + '">' + H.esc(e.signature || e.raw || '\u2014') + '</td></tr>'
                    )).join('') +
                    '</tbody></table></div></div>';
            }

            // Recent per-app request lines.
            if (d.recent && d.recent.length) {
                html += V.miniTable('Recent requests', d.recent, [['at', 'Time', 'ago'], ['method', 'Method'], ['path', 'Path'], ['status_code', 'Status'], ['bytes', 'Bytes', 'bytes']]);
            }
            return html;
        },
        neverBlockModal() {
            UI.modal('Add to never-block list',
                '<div class="field"><label>IP address or CIDR range</label><input name="ip" placeholder="203.0.113.10  ·  2001:db8::/32"></div>' +
                '<div class="field"><label>Note <span class="muted">(optional)</span></label><input name="note" placeholder="Office uplink"></div>' +
                '<p class="muted">IPv4, IPv6 and CIDR ranges are supported. Any active block covered by this entry is lifted immediately.</p>',
                (d, close) => {
                    if (!d.ip) { UI.toast('warn', 'Address required'); return; }
                    API.post('/nids/never-block', { ip: d.ip, note: d.note })
                        .then((res) => {
                            if (res.data.ok) {
                                const un = (res.data.unblocked || []).length;
                                UI.toast('success', 'Added to never-block', d.ip + (un ? ' · unblocked ' + un : ''));
                                close(); Views.nids.load();
                            } else UI.toast('error', 'Add failed', res.data.error);
                        });
                }, 'Add');
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
        _filter: { tags: [], logic: 'and' },
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
                '<div class="filter-bar" id="trFilter"></div>' +
                '<div class="grid cols-4" id="trStats"></div>' +
                '<div class="card" style="margin-top:16px;padding:0;overflow:hidden">' +
                '  <div id="trMap" style="height:440px;width:100%;background:#0d1526"></div></div>' +
                '<div class="grid cols-2" style="margin-top:16px">' +
                '  <div class="card"><h3>Top sources <span class="sub">click a row → services · ports · apps</span></h3><div id="trSources"></div></div>' +
                '  <div class="card"><h3>By country <span class="sub">click → ISPs → IPs</span></h3><div id="trCountries"></div></div>' +
                '</div>' +
                '<div class="grid cols-2" style="margin-top:16px">' +
                '  <div class="card"><h3>By ISP / network <span class="sub">click → IPs → detail</span></h3><div id="trIsps"></div></div>' +
                '  <div class="card"><h3>By application <span class="sub">click a row → sources · endpoints</span></h3><div id="trApps"></div></div>' +
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
            this.renderFilterBar();
            this.initMap();
            this.load();
            // Delegated drill-down: click any IP / country / ISP / app row to open its detail.
            $el.on('click', 'tr[data-drill]', (e) => {
                const $tr = $(e.currentTarget);
                const kind = $tr.data('drill');
                const arr = kind === 'ip' ? this._sources : kind === 'country' ? this._countries
                    : kind === 'isp' ? this._isps : this._apps;
                const x = (arr || [])[Number($tr.data('idx'))];
                if (!x) { return; }
                if (kind === 'ip') { this.drill.openIp(x.src_ip); }
                else if (kind === 'country') { this.drill.openCountry(x.country_code, x.country); }
                else if (kind === 'isp') { this.drill.openIsp(x.isp); }
                else if (kind === 'app') { this.drill.openApp(x.app); }
            });
            // Delegated tag-add: clicking a 🏷 / flag badge pins a filter tag.
            this.bindTagClicks($el);
            // Delegated filter-bar controls (chip remove, logic toggle, clear).
            $el.on('click', '#trFilter [data-rm]', (e) => {
                e.stopPropagation();
                this.removeTag(Number($(e.currentTarget).data('rm')));
            });
            $el.on('click', '#trFilter [data-logic]', () => this.toggleLogic());
            $el.on('click', '#trFilter [data-clear]', () => this.clearTags());
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
            const qs = this._qs();
            API.get('/traffic/summary?hours=' + hours + qs).then((r) => {
                const s = r.data;
                $('#trStats').html(
                    statBox('Allowed requests', (s.allowed_requests || 0).toLocaleString()) +
                    statBox('Allowed volume', H.bytes(s.allowed_bytes)) +
                    statBox('Blocked volume', H.bytes(s.blocked_bytes), s.blocked_bytes > 0 ? 'crit' : '') +
                    statBox('Sources · countries', (s.sources || 0) + ' · ' + (s.countries || 0))
                );
            });
            this.loadMap(hours);
            API.get('/traffic/sources?hours=' + hours + '&limit=25' + qs).then((r) => {
                this._sources = r.data || [];
                $('#trSources').html('<div class="table-wrap"><table class="data"><thead><tr>' +
                    '<th>IP</th><th>Country</th><th>ISP</th><th>Top URL</th><th class="num">Reqs</th><th class="num">Volume</th></tr></thead><tbody>' +
                    (this._sources.length ? this._sources.map((x, i) => (
                        '<tr class="clickable" data-drill="ip" data-idx="' + i + '"><td class="mono">' + H.esc(x.src_ip) + this.tags(x) + this.tagBtn('ip', x.src_ip, x.src_ip) + '</td>' +
                        '<td>' + H.esc(x.city ? x.city + ', ' : '') + H.esc(x.country || '—') + this.tagBtn('country', x.country_code || 'Unknown', x.country || 'Unknown') + '</td>' +
                        '<td class="muted">' + H.esc(x.isp || '—') + this.tagBtn('isp', x.isp || 'Unknown', x.isp || 'Unknown') + '</td>' +
                        '<td class="mono" title="' + H.esc(x.apps || '') + '">' + H.esc((x.top_path || x.apps || '—')) + '</td>' +
                        '<td class="mono">' + (Number(x.requests) || 0).toLocaleString() + '</td>' +
                        '<td class="mono">' + H.bytes(x.bytes) + '</td></tr>'
                    )).join('') : '<tr><td colspan="6" class="muted">no traffic recorded yet</td></tr>') +
                    '</tbody></table></div>');
            });
            API.get('/traffic/countries?hours=' + hours + qs).then((r) => {
                this._countries = r.data || [];
                $('#trCountries').html('<div class="table-wrap"><table class="data"><thead><tr>' +
                    '<th>Country</th><th class="num">Sources</th><th class="num">Reqs</th><th class="num">Volume</th></tr></thead><tbody>' +
                    (this._countries.length ? this._countries.map((x, i) => (
                        '<tr class="clickable" data-drill="country" data-idx="' + i + '"><td>' + H.esc(x.country || 'Unknown') + this.tagBtn('country', x.country_code || 'Unknown', x.country || 'Unknown') + '</td>' +
                        '<td class="mono">' + (Number(x.sources) || 0).toLocaleString() + '</td>' +
                        '<td class="mono">' + (Number(x.requests) || 0).toLocaleString() + '</td>' +
                        '<td class="mono">' + H.bytes(x.bytes) + '</td></tr>'
                    )).join('') : '<tr><td colspan="4" class="muted">no data</td></tr>') +
                    '</tbody></table></div>');
            });
            API.get('/traffic/isps?hours=' + hours + qs).then((r) => {
                this._isps = r.data || [];
                $('#trIsps').html('<div class="table-wrap"><table class="data"><thead><tr>' +
                    '<th>ISP / network</th><th class="num">Sources</th><th class="num">Reqs</th><th class="num">Volume</th></tr></thead><tbody>' +
                    (this._isps.length ? this._isps.map((x, i) => (
                        '<tr class="clickable" data-drill="isp" data-idx="' + i + '"><td>' + H.esc(x.isp || 'Unknown') + this.tagBtn('isp', x.isp || 'Unknown', x.isp || 'Unknown') + '</td>' +
                        '<td class="mono">' + (Number(x.sources) || 0).toLocaleString() + '</td>' +
                        '<td class="mono">' + (Number(x.requests) || 0).toLocaleString() + '</td>' +
                        '<td class="mono">' + H.bytes(x.bytes) + '</td></tr>'
                    )).join('') : '<tr><td colspan="4" class="muted">no data</td></tr>') +
                    '</tbody></table></div>');
            });
            API.get('/traffic/apps?hours=' + hours + qs).then((r) => {
                this._apps = r.data || [];
                $('#trApps').html('<div class="table-wrap"><table class="data"><thead><tr>' +
                    '<th>Application</th><th class="num">Sources</th><th class="num">Reqs</th><th class="num">Errors</th><th class="num">Volume</th></tr></thead><tbody>' +
                    (this._apps.length ? this._apps.map((x, i) => (
                        '<tr class="clickable" data-drill="app" data-idx="' + i + '"><td>' + H.esc(x.app || 'server') + this.tagBtn('app', x.app || 'server', x.app || 'server') + '</td>' +
                        '<td class="mono">' + (Number(x.sources) || 0).toLocaleString() + '</td>' +
                        '<td class="mono">' + (Number(x.requests) || 0).toLocaleString() + '</td>' +
                        '<td class="mono">' + (Number(x.errors) || 0).toLocaleString() + '</td>' +
                        '<td class="mono">' + H.bytes(x.bytes) + '</td></tr>'
                    )).join('') : '<tr><td colspan="5" class="muted">no data</td></tr>') +
                    '</tbody></table></div>');
            });
        },
        loadMap(hours) {
            if (!this._map) { return; }
            API.get('/traffic/map?hours=' + hours + this._qs()).then((r) => {
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
                        (s.datacenter ? '<br><span style="color:#f5a623">data center</span>' : '') +
                        (s.proxy ? '<br><span style="color:#c99bff">proxy / VPN</span>' : '') +
                        (blocked ? '<br><span style="color:#ff5470">blocked traffic</span>' : '') +
                        (s.apps && s.apps.length ? '<br>apps: ' + H.esc(s.apps.join(', ')) : '') +
                        '<br><i style="opacity:.7">click for full detail</i>'
                    ).on('click', () => this.drill.openIp(s.ip));
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
        },

        // ---- Tag filter bar ------------------------------------------
        // Query-string suffix carrying the active filter tags + boolean logic.
        _qs() {
            if (!this._filter.tags.length) { return ''; }
            return '&tags=' + encodeURIComponent(JSON.stringify(this._filter.tags.map((t) => ({ t: t.t, v: t.v })))) +
                '&logic=' + this._filter.logic;
        },
        // A small 🏷 button that pins a filter tag when clicked.
        tagBtn(t, v, label, title) {
            if (v == null || v === '') { return ''; }
            return '<button class="tagbtn" title="' + H.esc(title || ('Filter by ' + label)) + '"' +
                ' data-tagt="' + H.esc(t) + '" data-tagv="' + H.esc(String(v)) + '"' +
                ' data-tagl="' + H.esc(String(label)) + '">&#127991;</button>';
        },
        // A network-type badge that doubles as a flag-filter button.
        flagBadge(flag, label, cls) {
            return ' <button class="badge ' + cls + ' tagflag" title="Filter by ' + H.esc(label) + '"' +
                ' data-tagt="flag" data-tagv="' + H.esc(flag) + '" data-tagl="' + H.esc(label) + '">' + H.esc(label) + '</button>';
        },
        // Bind delegated clicks for every 🏷 / flag badge inside a container.
        // Runs before row-drill handlers thanks to jQuery proximity ordering.
        bindTagClicks($c) {
            const self = this;
            $c.on('click', '.tagbtn, .tagflag', function (e) {
                e.stopPropagation();
                e.preventDefault();
                const d = this.dataset;
                self.addTag(d.tagt, d.tagv, d.tagl);
            });
        },
        addTag(t, v, label) {
            if (!t || v == null || v === '') { return; }
            const exists = this._filter.tags.some((x) => x.t === t && String(x.v) === String(v));
            if (!exists) {
                this._filter.tags.push({ t: t, v: String(v), label: label || String(v) });
                this.renderFilterBar();
                this.load();
                UI.toast('info', 'Filter added', label || String(v));
            }
        },
        removeTag(i) {
            this._filter.tags.splice(i, 1);
            this.renderFilterBar();
            this.load();
        },
        clearTags() {
            if (!this._filter.tags.length) { return; }
            this._filter.tags = [];
            this.renderFilterBar();
            this.load();
        },
        toggleLogic() {
            this._filter.logic = this._filter.logic === 'or' ? 'and' : 'or';
            this.renderFilterBar();
            this.load();
        },
        renderFilterBar() {
            const $f = $('#trFilter');
            if (!$f.length) { return; }
            const tags = this._filter.tags;
            const icons = { ip: '&#128225;', country: '&#127758;', isp: '&#127760;', app: '&#128230;', flag: '&#9873;' };
            if (!tags.length) {
                $f.removeClass('active').html('<span class="fhint">No filters — click a &#127991; icon on any IP, country, ISP, app or badge to filter.</span>');
                return;
            }
            const logic = this._filter.logic.toUpperCase();
            let html = '<span class="flabel">Filter</span>';
            tags.forEach((t, i) => {
                if (i > 0) {
                    html += '<button class="flogic" data-logic title="Toggle AND / OR">' + logic + '</button>';
                }
                html += '<span class="fchip fchip-' + H.esc(t.t) + '"><span class="fico">' + (icons[t.t] || '') + '</span>' +
                    '<span class="ftxt">' + H.esc(t.label || t.v) + '</span>' +
                    '<button class="frm" data-rm="' + i + '" title="Remove">&times;</button></span>';
            });
            html += '<button class="fclear" data-clear title="Clear all filters">Clear</button>';
            $f.addClass('active').html(html);
        },

        // ---- Entity drill-downs --------------------------------------
        // Inline badges for an IP-ish row (blocked / data center / proxy / mobile).
        tags(x) {
            let t = '';
            if (Number(x.blocked_bytes) > 0) { t += this.flagBadge('blocked', 'blocked', 'failed'); }
            if (x.is_datacenter || x.datacenter) { t += this.flagBadge('datacenter', 'DC', 'dc'); }
            if (x.is_proxy || x.proxy) { t += this.flagBadge('proxy', 'proxy', 'proxy'); }
            if (x.is_mobile) { t += this.flagBadge('mobile', 'mobile', 'mobile'); }
            return t;
        },
        metaCell(k, vHtml) {
            return '<div class="m"><div class="k">' + H.esc(k) + '</div><div class="v">' + vHtml + '</div></div>';
        },
        // Read-only table for a drill panel. cols: [key, label, fmt] where fmt is
        // 'num' | 'bytes' | 'ago' | undefined (plain, escaped).
        miniTable(title, rows, cols, empty) {
            const isNum = (c) => c[2] && c[2] !== 'ago';
            const head = cols.map((c) => '<th' + (isNum(c) ? ' class="num"' : '') + '>' + H.esc(c[1]) + '</th>').join('');
            const body = rows && rows.length ? rows.map((row) => '<tr>' + cols.map((c) => {
                let v = row[c[0]];
                if (c[2] === 'bytes') { v = H.bytes(v); }
                else if (c[2] === 'num') { v = (Number(v) || 0).toLocaleString(); }
                else if (c[2] === 'ago') { v = H.ago(v); }
                else { v = H.esc(v == null || v === '' ? '—' : v); }
                return '<td' + (isNum(c) ? ' class="mono"' : '') + '>' + v + '</td>';
            }).join('') + '</tr>').join('') : '<tr><td colspan="' + cols.length + '" class="muted">' + H.esc(empty || 'none') + '</td></tr>';
            return '<div class="drill-section"><h4>' + H.esc(title) + '</h4><div class="table-wrap"><table class="data"><thead><tr>' +
                head + '</tr></thead><tbody>' + body + '</tbody></table></div></div>';
        },
        renderIpDetail(d) {
            const g = d.geo || {}, rep = d.reputation || {}, a = d.activity || {};
            const loc = [g.city, g.region, g.country].filter(Boolean).map(H.esc).join(', ') || '—';
            const net = [];
            if (g.is_datacenter) { net.push('data center'); }
            if (g.is_proxy) { net.push('proxy / VPN'); }
            if (g.is_mobile) { net.push('mobile carrier'); }
            const repBadge = rep.flagged
                ? '<span class="badge flag">' + (rep.blocked_now ? 'blocked now' : (rep.ever_blocked ? 'previously blocked' : 'threat activity')) + '</span>'
                : '<span class="badge clean">no prior flags</span>';
            let html = '<div class="drill-meta">' +
                this.metaCell('Location', loc) +
                this.metaCell('ISP / network', H.esc(g.isp || '—') + (g.org && g.org !== g.isp ? '<div class="muted" style="font-size:12px">' + H.esc(g.org) + '</div>' : '')) +
                this.metaCell('ASN', H.esc(g.asn || '—')) +
                this.metaCell('Network type', net.length ? net.map(H.esc).join(', ') : 'residential / other') +
                this.metaCell('Reputation', repBadge) +
                this.metaCell('Activity', (a.requests || 0).toLocaleString() + ' reqs · ' + H.bytes(a.bytes) + (a.errors ? ' · ' + a.errors + ' err' : '') + (a.blocked_bytes ? ' · ' + H.bytes(a.blocked_bytes) + ' blocked' : '')) +
                '</div>';
            if (rep.flagged) {
                const bits = [];
                if (rep.block_count) { bits.push(rep.block_count + ' firewall block' + (rep.block_count > 1 ? 's' : '') + (rep.last_reason ? ' (' + H.esc(rep.last_reason) + ')' : '') + (rep.last_blocked_at ? ', last ' + H.ago(rep.last_blocked_at) : '')); }
                if (rep.threat_events) { bits.push(rep.threat_events + ' NIDS event' + (rep.threat_events > 1 ? 's' : '') + (rep.threat_severity ? ' [' + H.esc(rep.threat_severity) + ']' : '') + (rep.threat_categories ? ': ' + H.esc(rep.threat_categories) : '')); }
                if (bits.length) { html += '<div class="drill-section"><h4>Reputation</h4><p class="muted" style="margin:0">' + bits.join(' · ') + '</p></div>'; }
            }
            html += this.miniTable('Applications / services', d.services, [['service', 'Service'], ['requests', 'Reqs', 'num'], ['bytes', 'Volume', 'bytes'], ['errors', 'Errors', 'num']], 'no application traffic');
            html += this.miniTable('Ports probed (NIDS)', d.ports, [['port', 'Port'], ['category', 'Category'], ['severity', 'Severity'], ['hits', 'Hits', 'num']], 'no port-level activity recorded');
            html += this.miniTable('Top endpoints', d.endpoints, [['method', 'Method'], ['path', 'Path'], ['status', 'Status'], ['requests', 'Reqs', 'num'], ['bytes', 'Volume', 'bytes']], 'no endpoints recorded');
            if (d.recent && d.recent.length) {
                html += this.miniTable('Recent requests', d.recent, [['at', 'Time', 'ago'], ['method', 'Method'], ['path', 'Path'], ['status_code', 'Status'], ['bytes', 'Bytes', 'bytes']]);
            }
            return html;
        },
        renderIspList(d) {
            const rows = d.sources || [];
            let html = '<div class="drill-meta">' +
                this.metaCell('ISP / network', H.esc(d.isp || 'Unknown')) +
                this.metaCell('Source IPs', rows.length.toLocaleString()) +
                '</div>';
            html += '<div class="drill-section"><h4>Source IPs <span class="sub">click an IP for services · ports · apps</span></h4>' +
                '<div class="table-wrap"><table class="data"><thead><tr>' +
                '<th>IP</th><th>Location</th><th>Services</th><th class="num">Reqs</th><th class="num">Volume</th></tr></thead><tbody>' +
                (rows.length ? rows.map((x, i) => (
                    '<tr class="clickable" data-ipidx="' + i + '"><td class="mono">' + H.esc(x.src_ip) + this.tags(x) + (x.ever_blocked && !(Number(x.blocked_bytes) > 0) ? ' <span class="badge flag">flagged</span>' : '') + '</td>' +
                    '<td>' + H.esc([x.city, x.country].filter(Boolean).join(', ') || '—') + '</td>' +
                    '<td class="muted" title="' + H.esc(x.services || '') + '">' + H.esc(x.services || '—') + '</td>' +
                    '<td class="mono">' + (Number(x.requests) || 0).toLocaleString() + '</td>' +
                    '<td class="mono">' + H.bytes(x.bytes) + '</td></tr>'
                )).join('') : '<tr><td colspan="5" class="muted">no IPs in window</td></tr>') +
                '</tbody></table></div></div>';
            return html;
        },
        renderCountryList(d, name) {
            const rows = d.isps || [];
            let html = '<div class="drill-meta">' +
                this.metaCell('Country', H.esc(name || d.country_code || 'Unknown')) +
                this.metaCell('ISPs / networks', rows.length.toLocaleString()) +
                '</div>';
            html += '<div class="drill-section"><h4>ISPs / networks <span class="sub">click a network for its IPs</span></h4>' +
                '<div class="table-wrap"><table class="data"><thead><tr>' +
                '<th>ISP / network</th><th>ASN</th><th class="num">IPs</th><th class="num">Reqs</th><th class="num">Volume</th></tr></thead><tbody>' +
                (rows.length ? rows.map((x, i) => (
                    '<tr class="clickable" data-ispidx="' + i + '"><td>' + H.esc(x.isp || 'Unknown') + (x.is_datacenter ? ' <span class="badge dc">DC</span>' : '') + '</td>' +
                    '<td class="muted mono">' + H.esc(x.asn || '—') + '</td>' +
                    '<td class="mono">' + (Number(x.sources) || 0).toLocaleString() + '</td>' +
                    '<td class="mono">' + (Number(x.requests) || 0).toLocaleString() + '</td>' +
                    '<td class="mono">' + H.bytes(x.bytes) + '</td></tr>'
                )).join('') : '<tr><td colspan="5" class="muted">no ISPs in window</td></tr>') +
                '</tbody></table></div></div>';
            return html;
        },
        // Colored badge for an HTTP status code (2xx green … 5xx red).
        scBadge(code) {
            const n = Number(code);
            if (!n) { return '<span class="badge">—</span>'; }
            const cls = n >= 500 ? 'sc5' : n >= 400 ? 'sc4' : n >= 300 ? 'sc3' : 'sc2';
            return '<span class="badge ' + cls + '">' + H.esc(String(n)) + '</span>';
        },
        renderAppDetail(d) {
            const a = d.activity || {}, m = d.meta || null;
            const rows = d.sources || [];
            const errs = d.errors || [];
            const codes = d.status_codes || [];
            let html = '<div class="drill-meta">' +
                this.metaCell('Application', H.esc(d.app || 'server') + (m && m.status ? ' <span class="badge ' + H.esc(m.status) + '">' + H.esc(m.status) + '</span>' : '')) +
                this.metaCell('Domain', H.esc((m && m.domain) || '—')) +
                this.metaCell('Health', m && m.last_health ? '<span class="badge ' + H.esc(m.last_health) + '">' + H.esc(m.last_health) + '</span>' : '—') +
                this.metaCell('Source IPs', (a.sources || 0).toLocaleString()) +
                this.metaCell('Activity', (a.requests || 0).toLocaleString() + ' reqs · ' + H.bytes(a.bytes)) +
                this.metaCell('Errors', (a.errors ? '<span class="badge sc5">' + Number(a.errors).toLocaleString() + '</span>' : '<span class="badge sc2">0</span>') + (a.last_seen ? ' <span class="muted">· last ' + H.ago(a.last_seen) + '</span>' : '')) +
                '</div>';

            // Status-code distribution — quick health signal for the app.
            if (codes.length) {
                html += '<div class="drill-section"><h4>Status codes <span class="sub">' + (d.window_hours || 24) + 'h</span></h4><div class="sc-row">' +
                    codes.map((c) => this.scBadge(c.status_code) + ' <span class="muted" style="margin-right:12px">×' + Number(c.hits).toLocaleString() + '</span>').join('') +
                    '</div></div>';
            }

            // Errors & warnings — the actual message text so you can see WHAT failed.
            html += '<div class="drill-section"><h4>Errors &amp; warnings <span class="sub">last ' + (d.window_hours || 24) + 'h</span></h4>';
            if (errs.length) {
                html += '<div class="table-wrap"><table class="data"><thead><tr>' +
                    '<th>Time</th><th>Status</th><th>Method</th><th>Path</th><th>Detail</th></tr></thead><tbody>' +
                    errs.map((e) => (
                        '<tr class="err"><td class="muted">' + H.ago(e.at) + '</td>' +
                        '<td>' + (e.status_code != null ? this.scBadge(e.status_code) : (e.level ? '<span class="badge sc4">' + H.esc(String(e.level)) + '</span>' : '—')) + '</td>' +
                        '<td class="mono">' + H.esc(e.method || '—') + '</td>' +
                        '<td class="mono" title="' + H.esc(e.path || '') + '">' + H.esc(e.path || '—') + '</td>' +
                        '<td class="errline">' + (e.message ? H.esc(String(e.message)) : '<span class="em">no message</span>') +
                        (e.src_ip ? ' <span class="em">· ' + H.esc(e.src_ip) + '</span>' : '') + '</td></tr>'
                    )).join('') +
                    '</tbody></table></div>';
            } else {
                html += '<p class="muted">No errors or warnings logged in this window' +
                    (m ? '.' : ' (this app has no structured log feed — wire the helper’s <code>logs</code> action to capture error detail).') + '</p>';
            }
            html += '</div>';

            html += '<div class="drill-section"><h4>Top source IPs <span class="sub">click an IP for services · ports · apps</span></h4>' +
                '<div class="table-wrap"><table class="data"><thead><tr>' +
                '<th>IP</th><th>Location</th><th>ISP</th><th class="num">Reqs</th><th class="num">Volume</th></tr></thead><tbody>' +
                (rows.length ? rows.map((x, i) => (
                    '<tr class="clickable" data-ipidx="' + i + '"><td class="mono">' + H.esc(x.src_ip) + this.tags(x) + (x.ever_blocked && !(Number(x.blocked_bytes) > 0) ? ' <span class="badge flag">flagged</span>' : '') + '</td>' +
                    '<td>' + H.esc([x.city, x.country].filter(Boolean).join(', ') || '—') + '</td>' +
                    '<td class="muted">' + H.esc(x.isp || '—') + '</td>' +
                    '<td class="mono">' + (Number(x.requests) || 0).toLocaleString() + '</td>' +
                    '<td class="mono">' + H.bytes(x.bytes) + '</td></tr>'
                )).join('') : '<tr><td colspan="5" class="muted">no source IPs in window</td></tr>') +
                '</tbody></table></div></div>';
            html += this.miniTable('By country', d.countries, [['country', 'Country'], ['sources', 'IPs', 'num'], ['requests', 'Reqs', 'num'], ['bytes', 'Volume', 'bytes']], 'no country data');
            html += this.miniTable('Top endpoints', d.endpoints, [['method', 'Method'], ['path', 'Path'], ['status', 'Status'], ['requests', 'Reqs', 'num'], ['bytes', 'Volume', 'bytes']], 'no endpoints recorded');
            if (d.recent && d.recent.length) {
                html += '<div class="drill-section"><h4>Recent requests</h4><div class="table-wrap"><table class="data"><thead><tr>' +
                    '<th>Time</th><th>IP</th><th>Method</th><th>Path</th><th>Status</th><th>Detail</th></tr></thead><tbody>' +
                    d.recent.map((e) => {
                        const bad = Number(e.status_code) >= 400 || /warn|err|crit|alert|emerg|fatal/i.test(String(e.level || ''));
                        return '<tr' + (bad ? ' class="err"' : '') + '><td class="muted">' + H.ago(e.at) + '</td>' +
                            '<td class="mono">' + H.esc(e.src_ip || '—') + '</td>' +
                            '<td class="mono">' + H.esc(e.method || '—') + '</td>' +
                            '<td class="mono" title="' + H.esc(e.path || '') + '">' + H.esc(e.path || '—') + '</td>' +
                            '<td>' + (e.status_code != null ? this.scBadge(e.status_code) : '—') + '</td>' +
                            '<td class="errline">' + (e.message ? H.esc(String(e.message)) : '<span class="em">—</span>') + '</td></tr>';
                    }).join('') +
                    '</tbody></table></div></div>';
            }
            return html;
        },
        // Navigable drill-down overlay with a back stack (country -> ISP -> IP).
        drill: {
            stack: [], _bk: null, _ips: [], _networks: [],
            openIp(ip) { this.push({ title: 'IP · ' + ip, kind: 'ip', arg: ip }); },
            openIsp(isp) { this.push({ title: 'ISP · ' + isp, kind: 'isp', arg: isp }); },
            openApp(app) { this.push({ title: 'App · ' + (app || 'server'), kind: 'app', arg: app || 'server' }); },
            openCountry(code, name) { this.push({ title: 'Country · ' + (name || code || 'Unknown'), kind: 'country', arg: code, name: name }); },
            push(f) { this.stack.push(f); this.ensure(); this.render(); },
            back() { this.stack.pop(); if (!this.stack.length) { this.close(); return; } this.render(); },
            close() { this.stack = []; if (this._bk) { this._bk.remove(); this._bk = null; } },
            ensure() {
                if (this._bk) { return; }
                const self = this;
                const $bk = $('<div class="modal-backdrop"></div>');
                const $m = $('<div class="modal drill-modal"></div>')
                    .append('<div class="drill-head"><button class="btn ghost sm" id="drillBack">← Back</button><h3 id="drillTitle"></h3><button class="btn ghost sm" id="drillClose">✕</button></div>')
                    .append('<div class="modal-body" id="drillBody"></div>');
                $bk.append($m).on('click', (e) => { if (e.target === $bk[0]) { self.close(); } });
                $('body').append($bk);
                this._bk = $bk;
                $m.on('click', '#drillClose', () => self.close());
                $m.on('click', '#drillBack', () => self.back());
                // Tag-add handler is bound first so it wins over the row handlers below.
                Views.traffic.bindTagClicks($m);
                $m.on('click', 'tr[data-ipidx]', function () { const x = self._ips[Number($(this).data('ipidx'))]; if (x) { self.openIp(x.src_ip); } });
                $m.on('click', 'tr[data-ispidx]', function () { const x = self._networks[Number($(this).data('ispidx'))]; if (x) { self.openIsp(x.isp); } });
            },
            render() {
                const V = Views.traffic, f = this.stack[this.stack.length - 1];
                if (!f) { return; }
                $('#drillTitle').text(f.title);
                $('#drillBack').css('visibility', this.stack.length > 1 ? 'visible' : 'hidden');
                const $b = $('#drillBody'); UI.loading($b);
                const hrs = V._hours;
                if (f.kind === 'ip') {
                    API.get('/traffic/ip?ip=' + encodeURIComponent(f.arg) + '&hours=' + hrs)
                        .then((r) => { $b.html(V.renderIpDetail(r.data)); })
                        .catch(() => $b.html('<p class="muted">failed to load</p>'));
                } else if (f.kind === 'isp') {
                    API.get('/traffic/isp?isp=' + encodeURIComponent(f.arg) + '&hours=' + hrs)
                        .then((r) => { this._ips = r.data.sources || []; $b.html(V.renderIspList(r.data)); })
                        .catch(() => $b.html('<p class="muted">failed to load</p>'));
                } else if (f.kind === 'app') {
                    API.get('/traffic/app?app=' + encodeURIComponent(f.arg) + '&hours=' + hrs)
                        .then((r) => { this._ips = r.data.sources || []; $b.html(V.renderAppDetail(r.data)); })
                        .catch(() => $b.html('<p class="muted">failed to load</p>'));
                } else if (f.kind === 'country') {
                    API.get('/traffic/country?code=' + encodeURIComponent(f.arg || '') + '&hours=' + hrs)
                        .then((r) => { this._networks = r.data.isps || []; $b.html(V.renderCountryList(r.data, f.name)); })
                        .catch(() => $b.html('<p class="muted">failed to load</p>'));
                }
            }
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
                    '<th>App</th><th>Path</th><th>Domain</th><th>Status</th><th>Health</th><th>Checked</th><th style="text-align:right">Actions</th></tr></thead><tbody>' +
                    (r.data.length ? r.data.map((a) => (
                        '<tr><td><strong>' + H.esc(a.name) + '</strong><br><span class="muted mono">' + H.esc(a.slug) + '</span></td>' +
                        '<td class="mono">' + H.esc(a.path) + '</td>' +
                        '<td>' + (a.domain ? H.esc(a.domain) : '<span class="muted">—</span>') + '</td>' +
                        '<td><span class="badge ' + H.esc(a.status) + '">' + H.esc(a.status) + '</span></td>' +
                        '<td>' + (a.last_health ? '<span class="badge ' + H.esc(a.last_health) + '">' + H.esc(a.last_health) + '</span>' : '<span class="muted">unknown</span>') + '</td>' +
                        '<td class="muted">' + (a.last_checked ? H.ago(a.last_checked) : 'never') + '</td>' +
                        '<td style="text-align:right"><button class="btn small ghost" data-report="' + a.id + '">Report</button>' +
                        ' <button class="btn small ghost" data-health="' + a.id + '">Check</button>' +
                        (SM.admin ? ' <button class="btn small" data-edit="' + a.id + '">Edit</button>' : '') +
                        (SM.admin ? ' <button class="btn small danger" data-remove="' + a.id + '">Remove</button>' : '') + '</td></tr>'
                    )).join('') : '<tr><td colspan="7" class="muted">No apps registered. Use Discover to find apps under /var/www.</td></tr>') +
                    '</tbody></table></div>');
                $('#appsTable [data-health]').on('click', function () {
                    const id = $(this).data('health');
                    const $btn = $(this).prop('disabled', true).text('Checking…');
                    API.post('/apps/' + id + '/health').then((res) => {
                        Views.apps.healthModal(res.data);
                        Views.apps.load();
                    }).catch(() => { UI.toast('error', 'Health check failed'); $btn.prop('disabled', false).text('Check'); });
                });
                $('#appsTable [data-report]').on('click', function () {
                    const id = $(this).data('report');
                    API.get('/apps/' + id + '/health').then((res) => Views.apps.healthModal(res.data));
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
        healthModal(rep) {
            if (!rep || !rep.app) { UI.toast('error', 'No health data'); return; }
            const a = rep.app, auto = rep.auto || {}, hist = rep.history || [];
            const logs = rep.logs || {};
            const latest = hist[0] || null;
            const d = (latest && latest.detail) || {};
            const overall = (latest && latest.status) || a.last_health || 'unknown';
            const summary = d.summary || {};
            const probes = summary.probes || Object.keys(d).filter((k) => ['http', 'helper', 'version', 'stats'].indexOf(k) >= 0);
            const version = d.version || null;

            // --- Metrics band: at-a-glance what the check covered ---
            const metric = (k, v) => '<div class="m"><div class="k">' + k + '</div><div class="v">' + v + '</div></div>';
            const httpBadge = d.http ? '<span class="badge ' + (d.http.ok ? 'healthy' : 'unhealthy') + '">' + (d.http.status != null ? H.esc(String(d.http.status)) : (d.http.ok ? 'ok' : 'fail')) + '</span>' : '—';
            const helperBadge = d.helper ? '<span class="badge healthy">ok</span>' : (d.helper_error ? '<span class="badge unhealthy">error</span>' : '—');
            let html = '<div class="drill-meta">' +
                metric('Overall', '<span class="badge ' + H.esc(overall) + '">' + H.esc(overall) + '</span>') +
                metric('Last checked', a.last_checked ? H.ago(a.last_checked) : 'never') +
                metric('Trigger', latest ? '<span class="badge ' + (latest.trigger_type === 'auto' ? 'info' : 'clean') + '">' + H.esc(latest.trigger_type) + '</span>' : '—') +
                metric('HTTP probe', httpBadge) +
                metric('Helper', helperBadge) +
                metric('Response', d.http && d.http.time_ms != null ? H.esc(String(d.http.time_ms)) + ' ms' : '—') +
                metric('Version', version ? H.esc(String(typeof version === 'object' ? (version.version || JSON.stringify(version)) : version)) : '—') +
                metric('Checks run', probes.length ? H.esc(probes.join(', ')) : '—') +
                metric('Logs 24h', (logs.total_24h != null ? Number(logs.total_24h).toLocaleString() : '0') +
                    (logs.errors_24h ? ' <span class="badge failed">' + logs.errors_24h + ' err</span>' : '')) +
                '</div>';

            // --- Auto / last-ran note ---
            html += '<p class="muted" style="margin-top:-4px">' + (auto.enabled
                ? 'Checks run automatically every <strong>' + H.esc(String(auto.interval_min)) + ' min</strong> via the monitor worker.'
                : '<strong>Manual checks only</strong> — automatic checks are disabled.') +
                (a.health_url ? ' · probe <span class="mono">' + H.esc(a.health_url) + '</span>' : '') + '</p>';

            if (!latest) {
                html += '<p class="muted">No checks have run yet. Click “Check” to run one now.</p>';
            }

            html += '<div class="detail-grid">';

            // --- HTTP probe ---
            if (d.http) {
                html += '<div class="drill-section full"><h4>HTTP probe ' +
                    '<span class="badge ' + (d.http.ok ? 'healthy' : 'unhealthy') + '">' + (d.http.ok ? 'ok' : 'fail') + '</span></h4>' +
                    '<table class="data kv"><tbody>' +
                    '<tr><th>Endpoint</th><td class="mono">' + H.esc(a.health_url || '—') + '</td></tr>' +
                    '<tr><th>HTTP status</th><td class="mono">' + H.esc(String(d.http.status)) + '</td></tr>' +
                    '<tr><th>Response time</th><td class="mono">' + H.esc(String(d.http.time_ms)) + ' ms</td></tr>' +
                    (d.http.content_type ? '<tr><th>Content type</th><td class="mono">' + H.esc(d.http.content_type) + '</td></tr>' : '') +
                    (d.http.size_bytes != null ? '<tr><th>Payload size</th><td class="mono">' + H.bytes(d.http.size_bytes) + '</td></tr>' : '') +
                    (d.http.redirects ? '<tr><th>Redirects</th><td class="mono">' + H.esc(String(d.http.redirects)) + '</td></tr>' : '') +
                    (d.http.error ? '<tr><th>Error</th><td class="mono">' + H.esc(String(d.http.error)) + '</td></tr>' : '') +
                    '</tbody></table>' +
                    (d.http.body_snippet ? '<div class="kv-head" style="margin-top:8px">Response body</div><pre class="payload">' + H.esc(d.http.body_snippet) + '</pre>' : '') +
                    '</div>';
            }

            // --- Helper health payload ---
            if (d.helper) {
                html += '<div class="drill-section"><h4>Helper health ' +
                    '<span class="badge info">' + H.esc(String(d.helper.status || 'ok')) + '</span></h4>' +
                    Views.apps._kvTable(d.helper) + '</div>';
            }
            if (d.helper_error) {
                html += '<div class="drill-section"><h4>Helper health ' +
                    '<span class="badge unhealthy">error</span></h4>' +
                    '<p class="muted">' + H.esc(String(d.helper_error)) + '</p></div>';
            }

            // --- Application stats (elements the app reports on) ---
            if (d.stats && Object.keys(d.stats).length) {
                html += '<div class="drill-section"><h4>Application metrics <span class="sub">' +
                    Object.keys(d.stats).length + ' element' + (Object.keys(d.stats).length === 1 ? '' : 's') + '</span></h4>' +
                    Views.apps._kvTable(d.stats) + '</div>';
            }

            // --- Log activity ---
            html += '<div class="drill-section"><h4>Log activity <span class="sub">24h</span></h4>';
            const byLevel = logs.by_level || [];
            if (logs.total_24h) {
                html += '<table class="data kv"><tbody>' +
                    '<tr><th>Total lines</th><td class="mono">' + Number(logs.total_24h).toLocaleString() + '</td></tr>' +
                    '<tr><th>5xx errors</th><td class="mono">' + Number(logs.errors_24h || 0).toLocaleString() + '</td></tr>' +
                    (logs.last_logged ? '<tr><th>Last log</th><td>' + H.ago(logs.last_logged) + '</td></tr>' : '') +
                    '</tbody></table>' +
                    (byLevel.length ? '<div class="kv-head" style="margin-top:8px">By level</div>' +
                        '<table class="data"><thead><tr><th>Level</th><th>Count</th></tr></thead><tbody>' +
                        byLevel.map((l) => '<tr><td>' + H.esc(l.level) + '</td><td class="mono">' + Number(l.count).toLocaleString() + '</td></tr>').join('') +
                        '</tbody></table>' : '');
            } else {
                html += '<p class="muted">No app log lines in the last 24h. Wire the helper’s <code>logs</code> action to populate this.</p>';
            }
            html += '</div>';

            html += '</div>'; // close .detail-grid

            // --- Advanced: full raw payload ---
            if (latest && d && Object.keys(d).length) {
                html += '<div class="drill-section"><details><summary class="adv-toggle">Advanced — raw payload</summary>' +
                    '<pre class="payload">' + H.esc(JSON.stringify(d, null, 2)) + '</pre></details></div>';
            }

            // --- History ---
            html += '<div class="drill-section"><h4>Recent checks</h4>';
            if (hist.length) {
                html += '<div class="table-wrap"><table class="data"><thead><tr>' +
                    '<th>Time</th><th>Trigger</th><th>Status</th><th>HTTP</th><th>Response</th></tr></thead><tbody>' +
                    hist.map((h) => (
                        '<tr><td class="muted">' + H.ago(h.checked_at) + '</td>' +
                        '<td><span class="badge ' + (h.trigger_type === 'auto' ? 'info' : 'clean') + '">' + H.esc(h.trigger_type) + '</span></td>' +
                        '<td><span class="badge ' + H.esc(h.status) + '">' + H.esc(h.status) + '</span></td>' +
                        '<td class="mono">' + (h.http_status != null ? H.esc(String(h.http_status)) : '—') + '</td>' +
                        '<td class="mono">' + (h.http_time_ms != null ? H.esc(String(h.http_time_ms)) + ' ms' : '—') + '</td></tr>'
                    )).join('') + '</tbody></table></div>';
            } else {
                html += '<p class="muted">No history yet.</p>';
            }
            html += '</div>';

            UI.modal('Health — ' + (a.name || a.slug), html, (_d, close) => close(), 'Close', { size: 'wide' });
        },
        _kvTable(obj) {
            const fmt = (v) => {
                if (v === true) { return '<span class="badge sc2">yes</span>'; }
                if (v === false) { return '<span class="badge sc4">no</span>'; }
                if (v === null || v === undefined || v === '') { return '<span class="muted">—</span>'; }
                if (typeof v === 'number') { return '<span class="kv-metric">' + v.toLocaleString() + '</span>'; }
                if (Array.isArray(v)) {
                    if (!v.length) { return '<span class="muted">none</span>'; }
                    if (typeof v[0] !== 'object') { return H.esc(v.join(', ')); }
                    return '<div class="subkv">' + v.map((it, i) => '<div class="r"><span class="sk">#' + i + '</span><span>' + fmt(it) + '</span></div>').join('') + '</div>';
                }
                if (typeof v === 'object') {
                    const ks = Object.keys(v);
                    if (!ks.length) { return '<span class="muted">—</span>'; }
                    return '<div class="subkv">' + ks.map((k) => '<div class="r"><span class="sk">' + H.esc(k) + '</span><span>' + fmt(v[k]) + '</span></div>').join('') + '</div>';
                }
                return H.esc(String(v));
            };
            const keys = Object.keys(obj).filter((k) => k !== 'summary');
            if (!keys.length) { return '<p class="muted">Empty payload.</p>'; }
            const rows = keys.map((k) => '<tr><th>' + H.esc(k) + '</th><td>' + fmt(obj[k]) + '</td></tr>').join('');
            return '<table class="data kv"><tbody>' + rows + '</tbody></table>';
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
                    '<p class="muted" style="margin:6px 0">Generate a one-time, signed unlock token, then paste it on the app\'s ' +
                    'helper page (<span class="mono">https://&lt;app&gt;/srvmgr/helper.php</span>). ' +
                    'The app verifies this manager\'s signature offline, then reveals a single enrollment payload.</p>' +
                    '<button class="btn small" id="genCodeBtn" type="button">Generate unlock token</button>' +
                    '<div id="unlockCodeBox" style="margin-top:8px"></div></div>' +
                    '<div class="card" style="margin:0;padding:12px 14px">' +
                    '<strong>Step 3 — finish pairing</strong>' +
                    '<p class="muted" style="margin:6px 0">Paste the single enrollment payload the app showed after unlocking. ' +
                    'It carries the URL, challenge and signing key — nothing else to type.</p>' +
                    '<div class="field"><label>Enrollment payload <span class="muted">(the whole block from the app)</span></label>' +
                    '<textarea name="enroll_payload" rows="3" placeholder="signed enrollment payload from the helper page"></textarea></div>' +
                    '<details style="margin:6px 0 10px"><summary class="muted" style="cursor:pointer">Enter fields manually instead</summary>' +
                    '<div class="field" style="margin-top:8px"><label>Helper URL</label>' +
                    '<input name="helper_url" placeholder="https://app.mcnutt.cloud/srvmgr/helper.php"></div>' +
                    '<div class="field"><label>Challenge key</label><input name="challenge" placeholder="XXXX-XXXX-XXXX-XXXX"></div></details>' +
                    '<div class="field"><label>Name</label><input name="name" placeholder="My app"></div>' +
                    '<div class="field"><label>Path</label><input name="path" value="/var/www/"></div>' +
                    '<div class="field"><label>Health URL <span class="muted">(optional)</span></label>' +
                    '<input name="health_url" placeholder="https://app.mcnutt.cloud/health"></div></div>',
                    (d, close) => {
                        if (!d.enroll_payload && !d.challenge) { UI.toast('warn', 'Enrollment payload or challenge required'); return; }
                        if (!d.path) { UI.toast('warn', 'Path required'); return; }
                        UI.toast('info', 'Pairing…', 'Verifying payload and contacting the app helper');
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
                        $btn.prop('disabled', false).text('Regenerate unlock token');
                        const token = res.data && (res.data.token || res.data.code);
                        if (token) {
                            const mins = Math.round((res.data.expires_in || 900) / 60);
                            $('#unlockCodeBox').html('<textarea readonly rows="3" onclick="this.select()" ' +
                                'style="font:600 13px ui-monospace,monospace;width:100%;box-sizing:border-box;background:#1c1c1c;border:1px solid #333;border-radius:8px;padding:12px 14px;color:#7dd3fc;word-break:break-all;resize:vertical">' +
                                H.esc(token) + '</textarea><span class="muted">Paste this on the app\'s helper page — valid for ' + mins + ' min, single use.</span>');
                        } else {
                            UI.toast('error', 'Could not issue token', (res.data && res.data.error) || '');
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
