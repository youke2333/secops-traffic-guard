/**
 * api.js —— 大屏数据层
 *
 * 三种运行形态，自动降级，保证大屏在任何环境都能出图：
 *   1. SSE 实时流（/stream/metrics + /stream/events）：真实后端，毫秒级刷新；
 *   2. 轮询（/overview、/blocks、/alerts/feed ...）：SSE 不可用时退化为 1~5s 轮询；
 *   3. 本地仿真（js/mock.js）：后端未启动（例如直接双击打开 index.html）时生成同结构数据，
 *      用于演示与联调，界面会显式标注「演示数据」。
 */
(function (global) {
    'use strict';

    var LISTENERS = {};

    function resolveBase() {
        try {
            var params = new URLSearchParams(global.location.search);
            var override = params.get('api') || global.localStorage.getItem('secops.apiBase');
            if (override) {
                return String(override).replace(/\/+$/, '');
            }
        } catch (e) { /* 忽略 */ }
        if (global.location.protocol === 'file:') {
            return 'http://127.0.0.1:8000/api/v1';
        }
        return '/api/v1';
    }

    var SecApi = {
        base: resolveBase(),
        token: '',
        csrf: '',
        user: null,
        mode: 'unknown',       // live | polling | mock
        status: {},
        connected: false,
        _esMetrics: null,
        _esEvents: null,
        _timers: [],

        /* -------------------- 事件总线（极简发布订阅） -------------------- */
        on: function (topic, handler) {
            (LISTENERS[topic] = LISTENERS[topic] || []).push(handler);
            return this;
        },
        emit: function (topic, payload) {
            (LISTENERS[topic] || []).forEach(function (handler) {
                try {
                    handler(payload);
                } catch (err) {
                    console.error('[SecApi] 处理 ' + topic + ' 事件出错:', err);
                }
            });
        },

        /* -------------------- HTTP 封装（演示数据模式下由 SecMock 接管） -------------------- */
        request: function (method, path, body) {
            var self = this;
            if (this.mode === 'mock' && global.SecMock && global.SecMock.canHandle(path)) {
                return global.SecMock.handle(method, path, body);
            }
            var options = {
                method: method,
                credentials: 'same-origin',
                headers: { 'Accept': 'application/json' },
                cache: 'no-store'
            };
            if (body !== undefined) {
                options.headers['Content-Type'] = 'application/json';
                options.body = JSON.stringify(body);
            }
            if (this.token) {
                options.headers['X-API-Token'] = this.token;
            }
            if (this.csrf && method !== 'GET' && method !== 'HEAD') {
                options.headers['X-CSRF-Token'] = this.csrf;
            }
            return fetch(this.base + path, options).then(function (response) {
                if (response.status === 401) {
                    if (global.location.protocol !== 'file:') {
                        var here = global.location.pathname + global.location.search;
                        global.location.replace('/login.html?next=' + encodeURIComponent(here));
                    }
                    throw new Error('会话已过期，请先登录');
                }
                if (!response.ok) {
                    return response.text().then(function (text) {
                        /* 演示模式下页面初始化可能早于 /health 探测：
                           此时静态服务器对 /api/v1/* 返回的是 HTML 404 页，
                           直接交给演示数据接管，避免概览页停在"加载失败"。
                           注意：/health 与 /auth/me 是模式探测本身，必须保持原样，
                           否则会把演示模式误判成 live。 */
                        var probe = path === '/health' || path === '/auth/me';
                        if (response.status === 404 && !probe && self.mode !== 'live'
                                && /^\s*</.test(text) && global.SecMock
                                && global.SecMock.canHandle(path)) {
                            /* 演示数据必须先播种再取：否则首页首屏拿到的是空列表 */
                            if (!global.SecMock.started) { global.SecMock.start(self); }
                            return global.SecMock.handle(method, path, body);
                        }
                        throw new Error('HTTP ' + response.status + ' ' + text.slice(0, 160));
                    });
                }
                if (response.status === 204) {
                    return null;
                }
                return response.json();
            });
        },
        get: function (path) { return this.request('GET', path); },
        post: function (path, body) { return this.request('POST', path, body || {}); },
        del: function (path) { return this.request('DELETE', path); },

        /* -------------------- 启动与降级 -------------------- */
        ensureAuth: function () {
            var self = this;
            return self.get('/auth/me').then(function (data) {
                self.user = data.user || null;
                self.csrf = data.csrf_token || '';
                return data;
            }).catch(function () {
                /* 未启用登录（auth_enabled=false）或接口不可用时继续尝试 /health */
                return null;
            });
        },
        start: function () {
            var self = this;
            return self.ensureAuth().then(function () {
                return self.get('/health');
            }).then(function (health) {
                self.status = health;
                self.mode = 'live';
                self.emit('status', health);
                self._startStream();
                self.refreshAll();
                self._timers.push(setInterval(function () { self.refreshAll(); }, 5000));
            }).catch(function (error) {
                console.warn('[SecApi] 后端不可用，切换为演示数据模式：', error.message);
                self.mode = 'mock';
                self.emit('status', {
                    status: 'mock', capture_mode: 'demo', dry_run: true,
                    firewall_backend: 'none', version: '-', message: error.message
                });
                global.SecMock.start(self);
            });
        },

        _startStream: function () {
            var self = this;
            if (!global.EventSource) {
                self._startPolling();
                return;
            }
            try {
                self._esMetrics = new global.EventSource(self.base + '/stream/metrics');
                self._esMetrics.addEventListener('metrics', function (event) {
                    self.connected = true;
                    self.emit('metrics', JSON.parse(event.data));
                });
                self._esMetrics.onerror = function () {
                    self.emit('connection', { metrics: false });
                };

                self._esEvents = new global.EventSource(self.base + '/stream/events');
                self._esEvents.addEventListener('alert', function (event) {
                    self.emit('alert', JSON.parse(event.data));
                });
                /* v2：AI 研判完成事件（抽屉无需轮询即可刷新） */
                self._esEvents.addEventListener('alert_enriched', function (event) {
                    self.emit('alert_enriched', JSON.parse(event.data));
                });
                /* v2：被抑制的信号事件（聚合抑制可见，禁止静默丢弃） */
                self._esEvents.addEventListener('signal', function (event) {
                    self.emit('signal', JSON.parse(event.data));
                });
            } catch (err) {
                console.warn('[SecApi] SSE 初始化失败，退化为轮询', err);
                self._startPolling();
            }
        },

        _startPolling: function () {
            var self = this;
            self.mode = 'polling';
            self._timers.push(setInterval(function () {
                self.get('/metrics/portfolio').then(function (data) {
                    self.emit('metrics', data.latest || {});
                    self.emit('overview', data.overview || {});
                }).catch(function () { /* 静默重试 */ });
            }, 1000));
        },

        /* -------------------- 周期刷新（列表类数据） -------------------- */
        refreshAll: function () {
            var self = this;
            var fetchList = function (path, topic) {
                self.get(path).then(function (data) { self.emit(topic, data); });
            };
            fetchList('/overview', 'overview');
            fetchList('/blocks?active_only=true&limit=20', 'blocks');
            fetchList('/alerts/feed?limit=15', 'alerts');
            fetchList('/alerts/stats?hours=24', 'alertStats');
            fetchList('/assets/summary', 'assetSummary');
            fetchList('/assets?limit=12', 'assets');
            fetchList('/vulns/summary', 'vulnSummary');
            fetchList('/vulns?limit=12&status=open', 'vulns');
            fetchList('/disposals?limit=12', 'disposals');
        },

        /* -------------------- 操作类接口（各模块页面的处置动作） -------------------- */
        block: function (ip, reason, ttlSec) {
            return this.post('/blocks', {
                ip: ip, reason: reason || '人工封禁', category: 'manual',
                severity: 'high', ttl_sec: ttlSec || 1800, operator: 'dashboard'
            });
        },
        unblock: function (ip) {
            return this.del('/blocks/' + encodeURIComponent(ip) + '?operator=dashboard');
        },
        extendBlock: function (ip, ttlSec) {
            return this.post('/blocks/' + encodeURIComponent(ip) + '/extend?ttl_sec='
                + (ttlSec || 1800) + '&operator=dashboard');
        },
        reapBlocks: function () {
            return this.post('/blocks/reap');
        },
        whitelist: function (cidr, note) {
            return this.post('/whitelist', { cidr: cidr, note: note || '页面添加', operator: 'dashboard' });
        },
        removeWhitelist: function (cidr) {
            return this.del('/whitelist/' + encodeURIComponent(cidr) + '?operator=dashboard');
        },
        scan: function (targets, ports) {
            return this.post('/vulns/scan', { targets: targets || [], ports: ports || '', use_nmap: true });
        },
        scanJob: function (jobId) {
            return this.get('/vulns/scan/' + jobId);
        },
        scanJobs: function (limit) {
            return this.get('/vulns/scan/jobs?limit=' + (limit || 10));
        },
        rescanAsset: function (ip, useNmap) {
            return this.post('/assets/' + encodeURIComponent(ip) + '/rescan?use_nmap='
                + (useNmap === false ? 'false' : 'true'));
        },
        /* 按攻击流量证据研判应用层漏洞（只读回放已捕获的请求/响应，不发起攻击） */
        inferAssetVulns: function (ip, useAi) {
            return this.post('/assets/' + encodeURIComponent(ip) + '/vuln-infer?use_ai='
                + (useAi === false ? 'false' : 'true'));
        },
        updateVulnStatus: function (id, status) {
            return this.request('PATCH', '/vulns/' + id + '?status=' + status);
        },
        alertDetail: function (id) {
            return this.get('/alerts/' + id);
        },
        ackAlert: function (id) {
            return this.post('/alerts/' + id + '/ack?operator=dashboard');
        },
        blockAlertSource: function (id, ttlSec) {
            return this.post('/alerts/' + id + '/block?ttl_sec=' + (ttlSec || 1800) + '&operator=dashboard');
        },
        portBaseline: function () {
            return this.get('/metrics/ports/baseline');
        },
        sessions: function (top) {
            return this.get('/metrics/sessions?top=' + (top || 20));
        },
        cveKb: function () {
            return this.get('/cve/kb');
        },
        webKb: function (category) {
            return this.get('/web/kb' + (category ? '?category=' + encodeURIComponent(category) : ''));
        },
        webStats: function () {
            return this.get('/web/stats');
        },
        webInspect: function (payload) {
            return this.post('/web/inspect', payload || {});
        },
        /* -------------------- v2：评分 / 信号 / 阈值 / 规则来源 / AI 研判 -------------------- */
        scoringConfig: function () {
            return this.get('/scoring/config');
        },
        signals: function (params) {
            var query = [];
            if (params && params.source_ip) { query.push('source_ip=' + encodeURIComponent(params.source_ip)); }
            if (params && params.category) { query.push('category=' + encodeURIComponent(params.category)); }
            if (params && params.suppressed_only) { query.push('suppressed_only=true'); }
            query.push('limit=' + ((params && params.limit) || 50));
            return this.get('/signals?' + query.join('&'));
        },
        signalWindow: function (sourceIp) {
            return this.get('/signals/window/' + encodeURIComponent(sourceIp));
        },
        thresholds: function () {
            return this.get('/thresholds');
        },
        thresholdsStatic: function () {
            return this.get('/thresholds/static');
        },
        recomputeThresholds: function (lookbackDays) {
            return this.post('/thresholds/recompute'
                + (lookbackDays ? '?lookback_days=' + lookbackDays : ''));
        },
        overrideThreshold: function (id, value, reason) {
            return this.request('PATCH', '/thresholds/' + id, {
                threshold_value: value, reason: reason || '页面人工覆盖', operator: 'dashboard'
            });
        },
        ruleSources: function () {
            return this.get('/rules/sources');
        },
        /* -------------------- v3：AI 流量研判 / Web 应用漏扫 / AI 修复建议 -------------------- */
        aiStatus: function () {
            return this.get('/ai/status');
        },
        trafficReview: function (windowMinutes) {
            return this.get('/ai/traffic/review?window_minutes=' + (windowMinutes || 10));
        },
        webappScan: function (url, port) {
            return this.post('/scanner/webapp', { url: url, port: port || null });
        },
        vulnAdvice: function (id, force) {
            // force=true 对应「重新生成」：后端会再打一次模型（temperature 抬高），
            // 不带该参数时按 temperature=0 求稳定输出
            return this.post('/vulns/' + id + '/ai-advice' + (force ? '?force=true' : ''));
        },
        rules: function (params) {
            var query = [];
            if (params && params.source) { query.push('source=' + encodeURIComponent(params.source)); }
            if (params && params.direct_only) { query.push('direct_only=true'); }
            query.push('limit=' + ((params && params.limit) || 200));
            return this.get('/rules?' + query.join('&'));
        },
        reloadRules: function () {
            return this.post('/rules/reload');
        },
        reanalyzeAlert: function (id) {
            return this.post('/alerts/' + id + '/reanalyze?operator=dashboard');
        },
        notifyTest: function () {
            return this.post('/notify/test');
        },
        /* -------------------- v6：登录 / 威胁告警 / 报告 / 规则包 -------------------- */
        authMe: function () { return this.get('/auth/me'); },
        logout: function () { return this.post('/auth/logout'); },
        threats: function (params) {
            return this.get('/threats?' + this.query(params));
        },
        threatDetail: function (id) { return this.get('/threats/' + id); },
        threatFacets: function (params) {
            var query = [];
            if (params && params.start) { query.push('start=' + encodeURIComponent(params.start)); }
            if (params && params.end) { query.push('end=' + encodeURIComponent(params.end)); }
            return this.get('/threats/facets' + (query.length ? '?' + query.join('&') : ''));
        },
        threatStats: function (hours) { return this.get('/threats/stats?hours=' + (hours || 24)); },
        blockThreat: function (id, ttlSec) {
            return this.post('/threats/' + id + '/block?ttl_sec=' + (ttlSec || 1800));
        },
        threatExportUrl: function (params) {
            return this.base + '/threats/export?' + this.query(params);
        },
        query: function (params) {
            var query = [];
            params = params || {};
            Object.keys(params).forEach(function (key) {
                var value = params[key];
                if (value === undefined || value === null || value === '') { return; }
                if (Array.isArray(value)) {
                    value.forEach(function (item) {
                        if (item !== '') { query.push(encodeURIComponent(key) + '=' + encodeURIComponent(item)); }
                    });
                } else {
                    query.push(encodeURIComponent(key) + '=' + encodeURIComponent(value));
                }
            });
            return query.join('&');
        },
        reports: function (limit) { return this.get('/reports?limit=' + (limit || 50)); },
        createReport: function (ip) { return this.post('/blocks/' + encodeURIComponent(ip) + '/report'); },
        reportUrl: function (id) { return this.base + '/reports/' + id; },
        rulePacks: function () { return this.get('/rules/packs'); },
        ruleEngine: function () { return this.get('/rules/engine'); },
        updateRuleTiers: function (tiers, shadowMode) {
            return this.request('PATCH', '/rules/packs/intrusion', {
                tiers: tiers, shadow_mode: shadowMode
            });
        },
        switchBackend: function (backend) {
            return this.post('/rules/engine/backend', { backend: backend });
        },
        users: function () { return this.get('/users'); },
        createUser: function (payload) { return this.post('/users', payload); },
        updateUser: function (id, payload) {
            return this.request('PATCH', '/users/' + id, payload);
        },
        disableUser: function (id) { return this.del('/users/' + id); },
        resetUserPassword: function (id) { return this.post('/users/' + id + '/reset-password'); }
    };

    global.SecApi = SecApi;
})(window);

