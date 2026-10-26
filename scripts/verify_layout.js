/**
 * verify_layout.js —— 各业务页面的图表布局配置自动检查
 *
 * 为什么需要它：图表的"观感问题"（坐标轴标签被裁切、饼图标签与图例互相压盖、
 * 图例挡住曲线）无法用后端测试覆盖，也无法靠肉眼看完全部页面。
 * 本脚本在 Node 里用 stub 的 DOM + echarts + fetch 真实执行每个页面的初始化代码，
 * 然后对生成的 ECharts option 做规则断言，把"观感问题"变成可自动检查的规则：
 *
 *   规则 A：所有直角坐标系图表必须 containLabel:true（否则轴标签会被裁切 / 压住曲线）
 *   规则 B：所有饼图/环形图必须隐藏引导线标签（label.show=false + labelLine.show=false），
 *           并把图例放在底部（legend.orient='horizontal'）—— 窄面板下这是唯一不重叠的排布
 *   规则 C：饼图必须 avoidLabelOverlap:true
 *   规则 D：每个页面预期的图表容器都必须被初始化（防止改布局时漏掉某个图）
 *
 * 用法：node scripts/verify_layout.js
 * 退出码：0=全部通过，1=存在问题
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const DASHBOARD = path.join(__dirname, '..', 'dashboard');
const SHARED = ['js/api.js', 'js/mock.js', 'js/ui.js'];

const PAGES = [
    { name: '监控大屏', file: 'js/dashboard.js',
      charts: ['chartTrend', 'chartPorts', 'chartCategories', 'chartSources'] },
    { name: '流量监控', file: 'js/page-traffic.js', charts: ['trendChart', 'portChart'] },
    { name: '异常端口检测', file: 'js/page-anomaly.js', charts: ['typeChart'] },
    { name: '封禁管理', file: 'js/page-block.js', charts: [] },
    { name: '威胁告警', file: 'js/page-threat.js', charts: [] },
    { name: '规则管理', file: 'js/page-rules.js', charts: [] },
    { name: '漏洞提醒', file: 'js/page-vuln.js', charts: [] },
    { name: '资产管理', file: 'js/page-asset.js', charts: ['riskChart', 'portChart'] }
];

let passed = 0;
const failures = [];

function check(name, condition, detail) {
    if (condition) {
        passed += 1;
        console.log('[PASS] ' + name);
    } else {
        failures.push(name + (detail ? ' —— ' + detail : ''));
        console.log('[FAIL] ' + name + (detail ? '  ' + detail : ''));
    }
}

/* ------------------------------------------------------------------ */
/* 最小 DOM / ECharts / 网络 stub：让页面脚本在 Node 里真实跑一遍        */
/* ------------------------------------------------------------------ */
/* 最小 DOM stub：classList 用真实集合实现、appendChild 会注册节点，
   这样才能真的断言「详情浮窗默认没有 open 类」 */
function makeElement(id, registry) {
    const classes = new Set();
    return {
        id: id || 'el',
        style: {},
        /* 容器尺寸可被测试改写：用于模拟"布局变化后图表需要重新 resize" */
        clientWidth: 600,
        clientHeight: 300,
        offsetWidth: 600,
        offsetHeight: 300,
        className: '',
        innerHTML: '',
        textContent: '',
        value: '',
        checked: false,
        disabled: false,
        classList: {
            add(name) { classes.add(name); },
            remove(name) { classes.delete(name); },
            contains(name) { return classes.has(name); },
            toggle(name) {
                if (classes.has(name)) { classes.delete(name); } else { classes.add(name); }
            }
        },
        addEventListener() { },
        removeEventListener() { },
        setAttribute() { },
        getAttribute() { return ''; },
        appendChild(child) {
            if (child && child.id && registry) { registry[child.id] = child; }
        },
        removeChild(child) {
            if (child && child.id && registry) { delete registry[child.id]; }
        },
        contains() { return false; },
        closest() { return null; },
        remove() { },
        click() { },
        querySelector() { return makeElement('sub', registry); },
        querySelectorAll() { return []; },
        getElementsByTagName() { return []; },
        getElementsByClassName() { return []; }
    };
}

function createSandbox() {
    const elements = {};
    const charts = {};
    let sequence = 0;

    const make = function (id) { return makeElement(id, elements); };

    const echartsStub = {
        init(el) {
            sequence += 1;
            const key = (el && el.id) ? el.id : 'chart-' + sequence;
            const record = { id: key, option: {}, resizeCount: 0, disposed: false };
            charts[key] = record;
            return {
                setOption(option) {
                    Object.keys(option || {}).forEach(function (key) {
                        const value = option[key];
                        if (key === 'series' && Array.isArray(value)) {
                            /* 模拟 ECharts 的按索引增量合并：后续只传 {data} 时不能丢掉 {type} */
                            const base = Array.isArray(record.option.series)
                                ? record.option.series.slice() : [];
                            value.forEach(function (item, index) {
                                base[index] = Object.assign({}, base[index] || {}, item);
                            });
                            record.option.series = base;
                        } else if (Array.isArray(value) || typeof value !== 'object' || value === null) {
                            record.option[key] = value;
                        } else {
                            record.option[key] = Object.assign({}, record.option[key] || {}, value);
                        }
                    });
                },
                resize() { record.resizeCount += 1; },
                dispose() { record.disposed = true; },
                getDom() { return el; },
                isDisposed() { return record.disposed; },
                on() { }, off() { }, clear() { }
            };
        },
        graphic: { LinearGradient: function LinearGradient() { return {}; } }
    };

    /* ResizeObserver 桩：记录被观察的容器，测试里可手动触发一次"尺寸变化"回调，
       用于验证页面是否真的会在布局变化后自动 resize（刷新后错位问题的核心防线） */
    const resizeObservers = [];
    const windowResizeListeners = [];
    function ResizeObserverStub(callback) {
        this.observe = function (el) { resizeObservers.push({ el: el, callback: callback }); };
        this.unobserve = function () { };
        this.disconnect = function () { };
    }

    const sandbox = {
        charts, elements, console,
        document: {
            readyState: 'complete',
            documentElement: { style: {} },
            body: make('body'),
            hidden: false,
            getElementById(id) {
                if (!elements[id]) { elements[id] = make(id); }
                return elements[id];
            },
            querySelector(selector) { return make(selector); },
            querySelectorAll() { return []; },
            createElement(tag) { return make(tag); },
            addEventListener() { },
            removeEventListener() { }
        },
        location: { protocol: 'http:', search: '', href: 'http://127.0.0.1:8000/' },
        localStorage: { getItem() { return null; }, setItem() { }, removeItem() { } },
        navigator: { userAgent: 'node' },
        innerWidth: 1920,
        innerHeight: 1080,
        /* 同步执行 rAF：页面脚本里只用于"下一帧再校正一次尺寸"，同步执行让断言可确定 */
        requestAnimationFrame(callback) { callback(0); return 0; },
        cancelAnimationFrame() { },
        ResizeObserver: ResizeObserverStub,
        __fireResizeObservers() {
            resizeObservers.forEach(function (item) { item.callback([{ target: item.el }]); });
        },
        __resizeObserverCount() { return resizeObservers.length; },
        __observedElements() {
            return resizeObservers.map(function (item) { return item.el; });
        },
        /* 记录 window.resize 监听器，测试里可手动触发，验证"窗口缩放"路径同样能自动 resize */
        addEventListener(type, handler) {
            if (type === 'resize') { windowResizeListeners.push(handler); }
        },
        removeEventListener() { },
        __fireWindowResize() {
            windowResizeListeners.slice().forEach(function (handler) { handler({ type: 'resize' }); });
        },
        setInterval() { return 0; },
        clearInterval() { },
        setTimeout() { return 0; },
        clearTimeout() { },
        confirm() { return false; },
        alert() { },
        URLSearchParams,
        Blob: function Blob() { },
        URL: { createObjectURL() { return 'blob:'; }, revokeObjectURL() { } },
        EventSource: function EventSource() {
            this.addEventListener = function () { };
            this.close = function () { };
        },
        echarts: echartsStub,
        fetch(url) { return Promise.resolve(makeResponse(String(url))); }
    };
    sandbox.window = sandbox;
    sandbox.globalThis = sandbox;
    return sandbox;
}

/* 让渲染链路真实执行：为各接口返回结构正确的样例数据 */
function makeResponse(url) {
    return {
        ok: true,
        status: 200,
        json() { return Promise.resolve(fixture(url)); },
        text() { return Promise.resolve(''); }
    };
}

function fixture(url) {
    const now = Date.now() / 1000;
    const series = [];
    for (let i = 60; i > 0; i -= 1) { series.push([now - i, 1200000 + i * 1000]); }

    if (url.indexOf('/health') >= 0) {
        return { status: 'ok', version: '1.0.0', capture_mode: 'demo', firewall_backend: 'iptables',
                 dry_run: true, channels: ['log'], interval_ms: 500 };
    }
    if (url.indexOf('/metrics/trend') >= 0) {
        return { window_sec: 60, interval_ms: 500, bps_in: series, bps_out: series,
                 pps_in: series, pps_out: series, conns: series };
    }
    if (url.indexOf('/metrics/ports/baseline') >= 0) {
        return {
            total: 2, threshold: 4, window_sec: 10, standard_ports: [80, 443],
            items: [
                { port: 4444, protocol: 'TCP', pps: 260, bps: 120000, conns: 12, is_standard: false,
                  top_source: '45.33.32.156', baseline_mean_pps: 12, zscore: 9.1,
                  deviation_ratio: 21, anomaly: true },
                { port: 443, protocol: 'TCP', pps: 900, bps: 9000000, conns: 30, is_standard: true,
                  top_source: '10.20.0.11', baseline_mean_pps: 880, zscore: 0.2,
                  deviation_ratio: 1.02, anomaly: false }
            ]
        };
    }
    if (url.indexOf('/metrics/sessions') >= 0) {
        return { total: 1, conn_table: 1, items: [{ src_ip: '10.20.0.11', src_port: 44120,
            dst_ip: '192.168.1.10', dst_port: 443, protocol: 'TCP', duration_sec: 30, idle_sec: 1,
            packets: 100, bytes: 20480, bps: 5400, pps: 3.3, is_internal: true }] };
    }
    if (url.indexOf('/metrics/ports') >= 0) {
        return { total: 2, items: [
            { port: 443, protocol: 'TCP', pps: 900, bps: 9000000, conns: 30, is_standard: true,
              top_source: '10.20.0.11' },
            { port: 4444, protocol: 'TCP', pps: 260, bps: 120000, conns: 12, is_standard: false,
              top_source: '45.33.32.156' }] };
    }
    if (url.indexOf('/metrics/portfolio') >= 0) {
        return { overview: fixture('/overview'), trend: fixture('/metrics/trend'), ports: [], latest: {} };
    }
    if (url.indexOf('/overview') >= 0) {
        return { bps: 1000, pps: 100, conns: 10, bandwidth_util: 12.5, packets_total: 1000,
                 bytes_total: 2048, unique_src: 3, unique_dst_ports: 5, alerts_total: 4, alerts_open: 2,
                 blocked_total: 1, blocked_active: 1, assets_total: 5, vulns_open: 2, risk_score: 30,
                 firewall_backend: 'iptables', dry_run: true, capture_mode: 'demo', channels: ['log'] };
    }
    if (url.indexOf('/alerts/stats') >= 0) {
        return { window_hours: 24, total: 4, blocked: 2,
                 by_category: [{ category_text: '端口扫描探测', count: 2 },
                               { category_text: '非标准端口高频访问', count: 1 },
                               { category_text: '突发流量峰值', count: 1 }],
                 by_severity: [{ severity: 'high', severity_text: '高危', count: 3 }],
                 top_sources: [{ ip: '203.0.113.66', count: 2 }, { ip: '45.33.32.156', count: 1 }] };
    }
    if (url.indexOf('/alerts/feed') >= 0) {
        return { total: 1, items: [{ id: 1, ts: new Date().toISOString(), source_ip: '203.0.113.66',
            dest_port: 4444, category: 'port_scan', category_text: '端口扫描探测', severity: 'high',
            severity_text: '高危', message: '样例事件', blocked: false }] };
    }
    /* 告警详情（含 v2 字段）：抽屉里要渲染 AI 研判 / 窗口 signals / 直达标记 */
    if (/\/alerts\/\d+/.test(url)) {
        return {
            id: 1, ts: new Date().toISOString(), source_ip: '203.0.113.66',
            dest_ip: '192.168.1.10', dest_port: 4444, protocol: 'TCP',
            category: 'web_command_injection', category_text: 'Web-命令注入',
            severity: 'critical', severity_text: '紧急', score: 0.95,
            message: '样例事件（直达告警）', evidence: { rule_ids: ['WEB-CMDI-001'], hits: 1 },
            status: 'open', blocked: true, region: '互联网', suggestion: '立即隔离主机取证。',
            risk_score: 6.0, contributing_rules: ['WEB-CMDI-001'], direct_alert: true,
            signal_window_id: 'win-2', signal_count: 1,
            aggregation: { direct_alert: true, risk_score: 6.0, threshold: 6.0, signal_count: 1,
                           categories: ['web_command_injection'] },
            signals: [{ id: 9002, ts: new Date().toISOString(), rule_id: 'WEB-CMDI-001',
                        category: 'web_command_injection', severity: 'critical', confidence: 'high',
                        weight: 6.0, direct_alert: true, suppressed: false }],
            llm_analysis: { source: 'deepseek_v4_flash', verdict: 'confirm', confidence: 0.92,
                            suggestion: 'block', degraded: false, direct_alert: true,
                            reason: '命中单条高置信度致命攻击规则（直达机制），建议立即封禁并取证。',
                            evidence_refs: ['risk_score=6.0', 'rules=WEB-CMDI-001'] },
            llm_source: 'deepseek_v4_flash', llm_ready: true
        };
    }
    if (url.indexOf('/alerts') >= 0) {
        return [{ id: 1, ts: new Date().toISOString(), source_ip: '203.0.113.66', dest_ip: '192.168.1.10',
                  dest_port: 4444, protocol: 'TCP', category: 'port_scan', category_text: '端口扫描探测',
                  severity: 'high', severity_text: '高危', score: 0.8, message: '样例事件', evidence: {},
                  status: 'open', blocked: false, region: '互联网' }];
    }
    if (url.indexOf('/blocks') >= 0) {
        return { total: 1, items: [{ id: 1, ip: '203.0.113.66', reason: '样例', category: 'port_scan',
            severity: 'high', backend: 'iptables', source: 'auto', operator: 'system',
            created_at: new Date().toISOString(), expires_at: new Date().toISOString(), active: true,
            hits: 1, dry_run: true, remaining_sec: 900 }] };
    }
    if (url.indexOf('/whitelist') >= 0) {
        return { total: 1, items: [{ id: 1, cidr: '127.0.0.1/32', note: '内置', operator: 'system',
            created_at: new Date().toISOString(), source: 'config' }] };
    }
    if (url.indexOf('/disposals') >= 0) {
        return { total: 1, items: [{ id: 1, ts: new Date().toISOString(), action: 'block',
            target: '203.0.113.66', detail: '样例', operator: 'system', success: true }] };
    }
    if (url.indexOf('/notify/channels') >= 0) {
        return { channels: ['log'], stats: { sent: 1, failed: 0 }, history: [] };
    }
    if (url.indexOf('/assets/summary') >= 0) {
        return { total: 5, risk_distribution: { critical: 1, high: 2, medium: 1, low: 1 },
                 top_ports: [{ port: 22, count: 5 }, { port: 443, count: 4 }], tags: {},
                 updated_at: new Date().toISOString() };
    }
    if (url.indexOf('/assets/') >= 0) {
        return { id: 1, ip: '192.168.1.10', hostname: 'srv-10', os_guess: 'Linux', risk_level: 'high',
                 open_ports: [22, 443], services: [{ port: 22, name: 'ssh', product: 'OpenSSH',
                 version: '8.2', banner: 'SSH-2.0' }], tags: ['Web'], bytes_in: 1024, bytes_out: 512,
                 alert_count: 1, vuln_count: 1, first_seen: new Date().toISOString(),
                 last_seen: new Date().toISOString(), alerts: [], vulnerabilities: [] };
    }
    if (url.indexOf('/assets') >= 0) {
        return [{ id: 1, ip: '192.168.1.10', hostname: 'srv-10', os_guess: 'Linux', risk_level: 'high',
                  open_ports: [22, 443], services: [], tags: ['Web'], bytes_in: 1024, bytes_out: 512,
                  alert_count: 1, vuln_count: 1, first_seen: new Date().toISOString(),
                  last_seen: new Date().toISOString() }];
    }
    if (url.indexOf('/web/kb') >= 0) {
        const keys = ['sql_injection', 'sql_injection_blind', 'xss_reflected', 'xss_stored',
            'command_injection', 'file_inclusion', 'file_upload', 'brute_force', 'csrf',
            'insecure_captcha', 'path_traversal', 'ssrf', 'xxe', 'webshell', 'ssti',
            'ldap_nosql_injection', 'crlf_injection'];
        const categories = keys.map(function (key) {
            return { key: key, name: '样例-' + key, cwe: 'CWE-89', owasp: 'A03:2021 Injection',
                     severity: 'high', rule_count: 3, description: '样例说明' };
        });
        const rules = keys.map(function (key, index) {
            return { id: 'WEB-SAMPLE-' + index, category: key, category_name: '样例-' + key,
                     title: '样例规则 ' + index, severity: 'high', confidence: 'high',
                     cwe: 'CWE-89', owasp: 'A03:2021 Injection', pattern_count: 2,
                     examples: ['sample-' + index] };
        });
        return {
            stats: { version: 'test', rules: rules.length, categories: categories.length,
                     by_category: { sql_injection: 1 }, path: 'test' },
            categories: categories, rules: rules, field_help: { patterns: '正则说明' },
            source: { name: 'demo', description: '样例' }
        };
    }
    if (url.indexOf('/web/stats') >= 0) {
        return { enabled: true, source_name: 'demo', analyzed_requests: 12, alerts_emitted: 2,
                 suppressed: 1, cooldown_sec: 60, categories: { sql_injection: 2 },
                 kb: { rules: 17, categories: 17, version: 'test' } };
    }
    if (url.indexOf('/vulns/scan') >= 0) {
        return url.indexOf('/jobs') >= 0
            ? { total: 1, stats: {}, items: [{ id: 'scan-1', status: 'done', progress: 1, total: 1,
                percent: 100, duration_sec: 2, started_at: now,
                summary: { services_found: 1, vulns_found: 1 } }] }
            : { id: 'scan-1', status: 'done', progress: 1, total: 1, percent: 100, duration_sec: 1,
                started_at: now, summary: { services_found: 1, vulns_found: 1 }, details: [] };
    }
    if (url.indexOf('/vulns/summary') >= 0) {
        return { total: 1, open: 1, distribution: { critical: 0, high: 1, medium: 0, low: 0 },
                 kb: { rules: 18, version: 'test' }, nmap_available: false };
    }
    if (url.indexOf('/vulns') >= 0) {
        return [{ id: 1, asset_ip: '192.168.1.10', port: 22, service: 'OpenSSH 8.2',
                  cve: 'CVE-2023-38408', title: 'OpenSSH agent 转发导致 RCE', severity: 'high',
                  cvss: 9.8, evidence: '样例', recommendation: '升级到 9.3p2', fixed_version: '9.3p2',
                  status: 'open', found_at: new Date().toISOString() }];
    }
    if (url.indexOf('/cve/kb') >= 0) {
        return { stats: { rules: 1, version: 'test' },
                 rules: [{ cve: 'CVE-2023-38408', title: '样例', severity: 'high', cvss: 9.8,
                           fixed_version: '9.3p2' }] };
    }
    if (url.indexOf('/status') >= 0) {
        return { running: true, capture_mode: 'demo', iface: 'demo0', ticks: 100, conn_table: 1 };
    }
    /* ---- v2：评分 / 信号 / 阈值 / 规则来源 ---- */
    if (url.indexOf('/scoring/config') >= 0) {
        return {
            window_sec: 300, threshold: 6.0, direct_alert_enabled: true,
            direct_alert_weight: 6.0, cooldown_sec: 60, max_signals_per_window: 1000,
            bonus: { multi_category_2: 1.2, multi_category_3: 1.5, critical: 1.3 },
            weight_table: { critical: 5.0, high: 3.0, medium: 1.5, low: 0.5 },
            confidence_factor: { high: 1.2, medium: 1.0, low: 0.8 },
            stats: { alert_emitted: 4, alert_suppressed: 3,
                     aggregator: { threshold: 6.0, 'signals.direct': 2 },
                     enricher: { chain: { enabled: true, model: 'deepseek-v4-flash' } } },
            note: '直达机制（direct_alert）不参与自适应阈值调整。'
        };
    }
    if (url.indexOf('/signals/window') >= 0) {
        return { source_ip: '203.0.113.66', window_sec: 300, threshold: 6.0, total: 1,
                 items: [{ rule_id: 'STAT-PORT-SCAN', category: 'port_scan', severity: 'high',
                           weight: 3.6, direct_alert: false, suppressed: true,
                           suppressed_reason: 'below_threshold', ts: new Date().toISOString() }] };
    }
    if (url.indexOf('/signals') >= 0) {
        return [
            { id: 9001, ts: new Date().toISOString(), source_ip: '203.0.113.66',
              rule_id: 'STAT-PORT-SCAN', category: 'port_scan', severity: 'high', weight: 3.6,
              direct_alert: false, suppressed: true, suppressed_reason: 'below_threshold',
              score_contribution: 3.6, signal_window_id: 'win-1' },
            { id: 9002, ts: new Date().toISOString(), source_ip: '198.51.100.23',
              rule_id: 'WEB-CMDI-001', category: 'web_command_injection', severity: 'critical',
              weight: 6.0, direct_alert: true, suppressed: false, suppressed_reason: '',
              score_contribution: 6.0, signal_window_id: 'win-2' }
        ];
    }
    if (url.indexOf('/thresholds/static') >= 0) {
        return {
            enabled: true, adaptive_types: ['traffic_spike', 'nonstandard_port', 'port_scan',
                                            'brute_force'],
            static_base: { traffic_spike: 3.5, nonstandard_port: 4.0, port_scan: 60, brute_force: 40 },
            bounds: { min_factor: 0.5, max_factor: 2.0, fp_high: 0.5, fp_low: 0.1, min_samples: 5 },
            last_recompute_at: null,
            last_recompute: { lookback_days: 14, dimensions: 1, updated: [], skipped: [] },
            note: '直达机制（direct_alert）不参与自适应调整。'
        };
    }
    if (url.indexOf('/thresholds') >= 0) {
        return {
            total: 1,
            items: [{ id: 1, detection_type: 'nonstandard_port', asset_class: 'server',
                      time_bucket: 'workhour', static_value: 4.0, threshold_value: 5.2,
                      sample_count: 12, false_positive_count: 9, true_positive_count: 3,
                      false_positive_rate: 0.75, manual_override: false, override_reason: '',
                      last_updated: new Date().toISOString() }],
            overview: fixture('/thresholds/static'), updated_at: new Date().toISOString()
        };
    }
    if (url.indexOf('/rules/sources') >= 0) {
        return {
            loaded_at: now, direct_alert_total: 19,
            sources: [
                { source: 'native', label: '内置知识库', enabled: true, rules: 81, web_rules: 63,
                  mapped_to_web_category: 63, direct_alert: 16, by_category: {}, by_severity: {} },
                { source: 'sigma', label: 'Sigma YAML', enabled: true, rules: 5, web_rules: 5,
                  mapped_to_web_category: 5, direct_alert: 3, by_category: {}, by_severity: {} },
                { source: 'et', label: 'Suricata / ET Open', enabled: true, rules: 6, web_rules: 6,
                  mapped_to_web_category: 6, direct_alert: 3, by_category: {}, by_severity: {} },
                { source: 'cve_ext', label: '扩展 CVE', enabled: true, rules: 8, web_rules: 0,
                  mapped_to_web_category: 0, direct_alert: 0, by_category: {}, by_severity: {} }
            ],
            errors: [],
            web_kb: { version: 'test', rules: 63, categories: 17, external_rules: 0,
                      direct_alert_rules: 16 },
            direct_alert_categories: ['command_injection', 'webshell']
        };
    }
    if (url.indexOf('/rules') >= 0) {
        return { total: 1, items: [{ id: 'WEB-CMDI-001', source: 'native',
                                     category: 'command_injection', direct_alert: true }],
                 stats: { native_web: 63, direct_alert: 16 } };
    }
    return {};
}

/* ------------------------------------------------------------------ */
/* 2) 布局规则断言                                                     */
/* ------------------------------------------------------------------ */
function isPie(option) {
    return (option.series || []).some(function (item) { return item && item.type === 'pie'; });
}

function isCartesian(option) {
    return Boolean(option.xAxis && option.yAxis);
}

function inspectCharts(pageName, charts) {
    let cartesian = 0;
    let pie = 0;
    Object.keys(charts).forEach(function (id) {
        const option = charts[id].option || {};
        if (isCartesian(option)) {
            cartesian += 1;
            const grid = option.grid || {};
            check(pageName + ' 「' + id + '」 直角坐标系使用 containLabel',
                grid.containLabel === true, 'grid=' + JSON.stringify(grid));
        }
        if (isPie(option)) {
            pie += 1;
            const series = (option.series || []).filter(function (item) {
                return item && item.type === 'pie';
            })[0] || {};
            const legend = option.legend || {};
            check(pageName + ' 「' + id + '」 隐藏引导线标签（避免与图例压盖）',
                series.label && series.label.show === false
                && series.labelLine && series.labelLine.show === false,
                'label=' + JSON.stringify(series.label) + ' labelLine=' + JSON.stringify(series.labelLine));
            check(pageName + ' 「' + id + '」 图例横排放置在底部',
                legend.orient === 'horizontal' && legend.bottom !== undefined,
                'legend=' + JSON.stringify({ orient: legend.orient, bottom: legend.bottom }));
            check(pageName + ' 「' + id + '」 开启 avoidLabelOverlap',
                series.avoidLabelOverlap === true, 'avoidLabelOverlap=' + series.avoidLabelOverlap);
        }
    });
    return { cartesian: cartesian, pie: pie };
}

/* ------------------------------------------------------------------ */
/* 2.1) 详情浮窗：默认必须收起，只有调用 open()（点「详情」）后才显示       */
/* ------------------------------------------------------------------ */
function checkDrawerBehaviour(pageName, sandbox) {
    const UI = sandbox.UI;
    if (!UI || !UI.drawer || typeof UI.drawer.open !== 'function') {
        check(pageName + ' 详情浮窗 API 可用（UI.drawer.open/close/isOpen）', false,
            'sandbox.UI.drawer 缺失');
        return;
    }
    const drawer = sandbox.document.getElementById('drawer');
    const mask = sandbox.document.getElementById('drawerMask');

    check(pageName + ' 详情浮窗默认不显示（初始化后无 open 类）',
        !drawer.classList.contains('open') && !mask.classList.contains('open')
        && UI.drawer.isOpen() === false,
        'drawer=' + drawer.className + ' mask=' + mask.className);

    UI.drawer.open('详情自检', '<dl><dt>k</dt><dd>v</dd></dl>');
    check(pageName + ' 点击「详情」后才滑入显示（抽屉与遮罩同时生效）',
        UI.drawer.isOpen() && drawer.classList.contains('open') && mask.classList.contains('open'),
        'isOpen=' + UI.drawer.isOpen());
    check(pageName + ' 详情浮窗标题按点击的那条数据写入',
        String(sandbox.elements.drawerTitle.textContent) === '详情自检',
        'title=' + sandbox.elements.drawerTitle.textContent);

    UI.drawer.close();
    check(pageName + ' 关闭后详情浮窗复位为隐藏状态',
        UI.drawer.isOpen() === false && !drawer.classList.contains('open')
        && !mask.classList.contains('open'),
        'isOpen=' + UI.drawer.isOpen());
}

/* ------------------------------------------------------------------ */
/* 2.2) 图表尺寸自适应：初始化后必须校正一次；布局变化必须自动 resize        */
/*      （"刷新后图形重叠、缩放窗口才恢复"就是这条规则缺失导致的）           */
/* ------------------------------------------------------------------ */
function checkChartAutoResize(pageName, sandbox, chartIds) {
    const entries = chartIds.map(function (id) {
        return { id: id, record: sandbox.charts[id], dom: sandbox.elements[id] };
    }).filter(function (item) { return Boolean(item.record); });
    if (!entries.length) { return; }

    function counts() {
        return entries.map(function (item) { return item.record.resizeCount; });
    }

    check(pageName + ' 图表初始化后立即校正尺寸（防刷新后错位）',
        entries.every(function (item) { return item.record.resizeCount >= 1; }),
        entries.map(function (item) { return item.id + '=' + item.record.resizeCount; }).join(' '));

    const observed = sandbox.__observedElements ? sandbox.__observedElements() : [];
    check(pageName + ' 图表容器已接入 ResizeObserver（布局变化自动跟随）',
        entries.every(function (item) { return observed.indexOf(item.dom) >= 0; }),
        'observed=' + observed.length + ' / charts=' + entries.length);

    /* 模拟容器自身尺寸变化（rem 基准变化 / 标签页展开 / 滚动条出现） */
    const beforeObserver = counts();
    entries.forEach(function (item) {
        item.dom.clientWidth += 40;
        item.dom.clientHeight += 24;
    });
    if (sandbox.__fireResizeObservers) { sandbox.__fireResizeObservers(); }
    const afterObserver = counts();
    check(pageName + ' 容器尺寸变化后自动 resize（无需手动缩放窗口）',
        afterObserver.every(function (value, index) { return value > beforeObserver[index]; }),
        'before=' + beforeObserver.join(',') + ' after=' + afterObserver.join(','));

    /* 模拟浏览器窗口 resize */
    const beforeWindow = counts();
    entries.forEach(function (item) { item.dom.clientWidth += 30; });
    if (sandbox.__fireWindowResize) { sandbox.__fireWindowResize(); }
    const afterWindow = counts();
    check(pageName + ' 窗口 resize 时图表自动跟随（统一在自适应实现里处理）',
        afterWindow.every(function (value, index) { return value > beforeWindow[index]; }),
        'before=' + beforeWindow.join(',') + ' after=' + afterWindow.join(','));
}

/* ------------------------------------------------------------------ */
/* 2.3) Web 攻击知识库：大类/告警中文名/页面接入/演示模式可用性            */
/*      （知识库在 backend/data/web_attack_rules.json，前端必须能完整展示） */
/* ------------------------------------------------------------------ */
const WEB_CATEGORY_KEYS = ['sql_injection', 'sql_injection_blind', 'xss_reflected', 'xss_stored',
    'command_injection', 'file_inclusion', 'file_upload', 'brute_force', 'csrf',
    'insecure_captcha', 'path_traversal', 'ssrf', 'xxe', 'webshell', 'ssti',
    'ldap_nosql_injection', 'crlf_injection'];

function checkWebAttackKnowledge(sandbox) {
    const categoryTable = readFile('js/ui.js');
    const missing = WEB_CATEGORY_KEYS.filter(function (key) {
        return categoryTable.indexOf('web_' + key) < 0;
    });
    check('Web 攻击知识库：17 类攻击在前端类别表都有中文名（告警列表不显示英文 key）',
        missing.length === 0, '缺少：' + missing.join(','));

    check('Web 攻击知识库：漏洞页接入 /web/kb（存在 SecApi.webKb 调用）',
        readFile('js/page-vuln.js').indexOf('SecApi.webKb') > 0);

    const vulnHtml = readFile('vuln.html');
    check('Web 攻击知识库：漏洞页提供 Web 规则数 KPI 与规则抽屉按钮',
        vulnHtml.indexOf('kWebRules') > 0 && vulnHtml.indexOf('btnWebKb') > 0);

    check('Web 攻击知识库：异常端口页统计 Web 攻击告警（kpi + web_ 前缀过滤）',
        readFile('anomaly.html').indexOf('kWebAlerts') > 0
        && readFile('js/page-anomaly.js').indexOf("'web_'") > 0);

    const mock = readFile('js/mock.js');
    check('Web 攻击知识库：演示模式（无后端）同样提供 /web/kb 与 /web/stats',
        mock.indexOf("'/web/kb'") > 0 && mock.indexOf("'/web/stats'") > 0);

    if (sandbox) {
        const rules = String(sandbox.elements.kWebRules ? sandbox.elements.kWebRules.textContent : '');
        check('Web 攻击知识库：漏洞页加载后写入规则数 KPI',
            rules !== '' && rules !== '0', 'kWebRules=' + rules);
    }
}

/* ------------------------------------------------------------------ */
/* 2.4) 评分 / 直达 / 阈值 / AI 研判（v2）：前端必须把"看不见的机制"显式呈现 */
/*      （硬约束：降级必须可见 —— 直达徽标、抑制计数、AI 研判来源都要有）    */
/* ------------------------------------------------------------------ */
function checkScoringAndAiUi(sandbox) {
    const html = readFile('anomaly.html');
    const kpiIds = ['kDirectAlerts', 'kSuppressed', 'kScoreThreshold'];
    const missingKpi = kpiIds.filter(function (id) { return html.indexOf(id) < 0; });
    check('评分机制：异常端口页提供直达告警 / 抑制信号 / 聚合阈值 KPI',
        missingKpi.length === 0, '缺少：' + missingKpi.join(','));

    check('评分机制：异常端口页提供阈值与信号表格（signalBody）',
        html.indexOf('signalBody') > 0 && html.indexOf('权重') > 0
        && html.indexOf('是否直达') > 0);

    const buttons = ['btnThresholds', 'btnSignals', 'btnSuppressed', 'btnRecompute',
                     'btnRuleSources'];
    const missingButtons = buttons.filter(function (id) { return html.indexOf(id) < 0; });
    check('阈值管理：页面提供阈值管理 / 信号 / 抑制 / 重算 / 规则来源按钮',
        missingButtons.length === 0, '缺少：' + missingButtons.join(','));

    const script = readFile('js/page-anomaly.js');
    check('评分机制：告警列表渲染「风险分」列与直达徽标',
        script.indexOf("risk_score") > 0 && script.indexOf("'直达'") > 0
        && script.indexOf("'聚合'") > 0);
    check('AI 研判：详情抽屉调用 /alerts/{id}/reanalyze 并提供来源标签',
        script.indexOf('SecApi.reanalyzeAlert') > 0
        && script.indexOf('deepseek_v4_flash') > 0
        && script.indexOf('本地规则判定') > 0
        && script.indexOf('待人工研判') > 0);
    check('AI 研判：降级时展示提示条（当前 API 不可用 → 已降级）',
        script.indexOf('已降级到') > 0);
    check('阈值管理：抽屉展示维度化阈值（静态基准 / 生效阈值 / 误报率 / 人工覆盖）',
        script.indexOf('false_positive_rate') > 0 && script.indexOf('生效阈值') > 0
        && script.indexOf('人工覆盖') > 0);
    check('规则来源：抽屉展示各来源规则数与直达规则数',
        script.indexOf('SecApi.ruleSources') > 0 && script.indexOf('直达规则共') > 0);
    check('抑制可见：信号表区分「未达阈值 / 冷却期抑制」并显示权重',
        script.indexOf('未达阈值') > 0 && script.indexOf('冷却期抑制') > 0);

    const mock = readFile('js/mock.js');
    const mockEndpoints = ["'/scoring/config'", "'/signals'", "'/thresholds'",
                           "'/rules/sources'", 'reanalyze'];
    const missingMock = mockEndpoints.filter(function (item) { return mock.indexOf(item) < 0; });
    check('演示模式：提供 /scoring/config、/signals、/thresholds、/rules/sources、reanalyze',
        missingMock.length === 0, '缺少：' + missingMock.join(','));

    const api = readFile('js/api.js');
    check('前端数据层：SecApi 暴露评分/信号/阈值/规则来源/重新研判接口',
        api.indexOf('scoringConfig:') > 0 && api.indexOf('signals:') > 0
        && api.indexOf('thresholds:') > 0 && api.indexOf('ruleSources:') > 0
        && api.indexOf('reanalyzeAlert:') > 0);

    if (sandbox) {
        const threshold = String(sandbox.elements.kScoreThreshold
            ? sandbox.elements.kScoreThreshold.textContent : '');
        check('评分机制：页面加载后写入聚合阈值 KPI',
            threshold.indexOf('≥') === 0, 'kScoreThreshold=' + threshold);
        const suppressCell = String(sandbox.elements.signalBody
            ? sandbox.elements.signalBody.innerHTML : '');
        check('抑制可见：信号表渲染出「已告警 / 抑制」两类状态',
            suppressCell.indexOf('未达阈值') > 0 && suppressCell.indexOf('已告警') > 0,
            suppressCell.slice(0, 160));
    }
}

function runPage(page) {
    const sandbox = createSandbox();
    const context = vm.createContext(sandbox);
    SHARED.concat([page.file]).forEach(function (relative) {
        const code = fs.readFileSync(path.join(DASHBOARD, relative), 'utf8');
        vm.runInContext(code, context, { filename: relative });
    });
    return new Promise(function (resolve) {
        setTimeout(function () {
            page.charts.forEach(function (id) {
                check(page.name + ' 初始化图表「' + id + '」', Boolean(sandbox.charts[id]),
                    '实际已初始化：' + Object.keys(sandbox.charts).join(',') || '无');
            });
            const stats = inspectCharts(page.name, sandbox.charts);
            console.log('       ' + page.name + '：直角坐标系图 ' + stats.cartesian
                + ' 个、饼图 ' + stats.pie + ' 个');
            checkDrawerBehaviour(page.name, sandbox);
            checkChartAutoResize(page.name, sandbox, page.charts);
            if (page.file === 'js/page-vuln.js') {
                checkWebAttackKnowledge(sandbox);
            }
            if (page.file === 'js/page-anomaly.js') {
                checkScoringAndAiUi(sandbox);
            }
            resolve();
        }, 40);
    });
}

/* ------------------------------------------------------------------ */
/* 3) 静态结构与样式规则（观感修正的样式层同样要能被验证）                */
/* ------------------------------------------------------------------ */
function readFile(relative) {
    return fs.readFileSync(path.join(DASHBOARD, relative), 'utf8');
}

function cssBlock(css, selector) {
    const start = css.indexOf(selector);
    if (start < 0) { return ''; }
    const open = css.indexOf('{', start);
    const close = css.indexOf('}', open);
    return open < 0 || close < 0 ? '' : css.slice(open, close);
}

/* 拆出所有「选择器 { 声明 }」块（顶层规则；带嵌套的 @media 由内层规则覆盖，足够本用途）
   解析前先剥掉注释，否则选择器会带上注释文字，导致按类名匹配失败 */
function cssBlocks(css) {
    const blocks = [];
    const source = css.replace(/\/\*[\s\S]*?\*\//g, '\n');
    const pattern = /([^{}]+)\{([^{}]*)\}/g;
    let match = pattern.exec(source);
    while (match !== null) {
        blocks.push({ selector: match[1].replace(/\s+/g, ' ').trim(), body: match[2].trim() });
        match = pattern.exec(source);
    }
    return blocks;
}

/* 选择器列表里是否精确包含某个类（.drawer 命中 .drawer 与 .drawer.open，
   但不会误命中 .drawer-body / .drawer-mask） */
function selectorContains(selectorList, name) {
    return selectorList.split(',').some(function (part) {
        const value = part.trim();
        return value === name || value.indexOf(name + '.') === 0
            || value.indexOf(name + ':') === 0 || value.indexOf(name + ' ') === 0;
    });
}

function checkStaticRules() {
    const css = readFile('css/dashboard.css');
    const index = readFile('index.html');
    const traffic = readFile('traffic.html');
    const anomaly = readFile('anomaly.html');
    const asset = readFile('asset.html');

    /* 观感修正都在文件末尾的"v1.1 观感修正层"里，断言语义以覆盖层为准 */
    const mark = css.indexOf('v1.1 观感修正层');
    check('样式：存在统一观感修正层（文件末尾覆盖）', mark > 0, 'marker@' + mark);
    const override = mark > 0 ? css.slice(mark) : css;

    const overlay = cssBlock(override, 'body::before');
    check('样式：存在全屏背景遮罩层 body::before（避免背景图干扰文字）',
        overlay.indexOf('radial-gradient') >= 0, overlay.replace(/\s+/g, ' ').slice(0, 90));

    const panel = cssBlock(override, '.panel {');
    check('样式：面板提高不透明度 + 轻微模糊，文字与背景分层',
        /rgba\(6,\s*26,\s*46,\s*0\.8/.test(panel) && panel.indexOf('backdrop-filter') >= 0,
        panel.replace(/\s+/g, ' ').slice(0, 110));

    const nav = cssBlock(override, '.dash-nav {');
    check('样式：模块导航改为布局内横排（消除与饼图重叠）',
        nav.indexOf('position: static') >= 0 && nav.indexOf('flex-direction: row') >= 0,
        nav.replace(/\s+/g, ' ').slice(0, 110));

    const ellipsisGroup = override.slice(override.indexOf('/* ---- 2)'),
        override.indexOf('/* ---- 3)'));
    check('样式：数值/标题统一单行省略（长文本不再撑破栅格）',
        ellipsisGroup.indexOf('.kpi .value') >= 0 && ellipsisGroup.indexOf('text-overflow: ellipsis') >= 0,
        'group length=' + ellipsisGroup.length);

    check('样式：饼图容器专用高度 .chart-box.pie', override.indexOf('.chart-box.pie') > 0);
    check('样式：条形图容器专用高度 .chart-box.ports', override.indexOf('.chart-box.ports') > 0);
    const assetSide = cssBlock(override, '.asset-side .chart-box');
    check('样式：侧栏图表自适应面板高度（避免上下两块错位）',
        assetSide.indexOf('flex: 1') >= 0, assetSide.replace(/\s+/g, ' ').slice(0, 90));

    const navPos = index.indexOf('class="dash-nav"');
    const contentPos = index.indexOf('<div class="content"');
    check('结构：大屏模块导航位于布局流内（在内容区之前）',
        navPos > 0 && contentPos > navPos, 'nav@' + navPos + ' content@' + contentPos);
    check('结构：大屏模块导航只出现一次（无残留浮层）',
        (index.split('class="dash-nav"').length - 1) === 1);

    check('结构：流量页端口图使用 ports 高度类', traffic.indexOf('chart-box ports') > 0);
    check('结构：异常端口页饼图使用 pie 高度类', anomaly.indexOf('chart-box pie') > 0);
    check('结构：资产页右侧统计区使用 asset-side 布局类', asset.indexOf('class="asset-side"') > 0);

    /* ---- 详情浮窗：默认不显示，只有点击「详情」按钮才浮出 ---- */
    const overlayNames = ['.toast', '.modal', '.drawer', '.drawer-mask'];
    /* 这一条扫全量 CSS：任何位置出现「把浮层改成 relative」的规则都要被拦下 */
    const relativeOverlays = cssBlocks(css).filter(function (block) {
        return /position:\s*relative/.test(block.body)
            && overlayNames.some(function (name) { return selectorContains(block.selector, name); });
    });
    check('样式：浮层（toast/modal/drawer/drawer-mask）保持 position:fixed，不得被改成 relative',
        relativeOverlays.length === 0,
        relativeOverlays.map(function (item) { return item.selector; }).join(' | '));

    function bodiesOf(name, onlyClosed) {
        const blocks = cssBlocks(override);
        return blocks.filter(function (block) {
            if (!selectorContains(block.selector, name)) { return false; }
            return onlyClosed ? !/\.open/.test(block.selector) : true;
        }).map(function (block) { return block.body; }).join('\n');
    }

    const drawerDefault = bodiesOf('.drawer', true);
    check('样式：详情浮窗默认隐藏（visibility:hidden + 指针屏蔽 + 移出视口三重保险）',
        /visibility:\s*hidden/.test(drawerDefault) && /pointer-events:\s*none/.test(drawerDefault)
        && /translateX\(102%\)/.test(drawerDefault),
        drawerDefault.replace(/\s+/g, ' ').slice(0, 120));

    const drawerOpen = bodiesOf('.drawer.open', false);
    check('样式：详情浮窗仅在 .open 状态可见（visibility:visible + 滑回视口）',
        /visibility:\s*visible/.test(drawerOpen) && /translateX\(0\)/.test(drawerOpen),
        drawerOpen.replace(/\s+/g, ' ').slice(0, 120));

    const maskDefault = bodiesOf('.drawer-mask', true);
    check('样式：遮罩默认不可见且不拦截点击',
        maskDefault.indexOf('position: fixed') >= 0 && maskDefault.indexOf('visibility: hidden') >= 0,
        maskDefault.replace(/\s+/g, ' ').slice(0, 120));

    const uiJs = readFile('js/ui.js');
    check('脚本：抽屉节点创建时不带 open 类（默认收起）',
        uiJs.indexOf("drawer.className = 'drawer';") > 0);
    const ensureBody = uiJs.slice(uiJs.indexOf('ensure: function'));
    check('脚本：UI.drawer.ensure() 初始化后立即复位关闭（兜底不显示）',
        ensureBody.indexOf('UI.drawer.close();') > 0 && ensureBody.indexOf('Escape') > 0);

    const detailAttrs = { 'js/page-anomaly.js': 'data-alert-detail', 'js/page-asset.js': 'data-asset-detail',
        'js/page-vuln.js': 'data-vuln-detail' };
    Object.keys(detailAttrs).forEach(function (file) {
        const source = readFile(file);
        check('结构：' + file + ' 的「详情」按钮通过 ' + detailAttrs[file] + ' 触发浮窗',
            source.indexOf(detailAttrs[file]) > 0 && source.indexOf('UI.drawer.open') > 0);
    });

    /* ---- 图表尺寸自适应：顺序 + 职责（防止再次出现"刷新后图形重叠"） ---- */
    const remFallback = cssBlock(override, 'html {');
    check('样式：CSS 层给出 rem 基准兜底（JS 生效前图表容器不会按 16px 计算）',
        /font-size:\s*calc\(100vw\s*\/\s*22\)/.test(remFallback),
        remFallback.replace(/\s+/g, ' ').slice(0, 90));
    check('样式：图表容器高度仍为 rem 单位（依赖 rem 基准，故必须先定基准再 init）',
        /height:\s*[0-9.]+rem/.test(cssBlock(override, '.chart-box {')),
        cssBlock(override, '.chart-box {').replace(/\s+/g, ' ').slice(0, 90));

    const chartPages = ['js/dashboard.js', 'js/page-traffic.js', 'js/page-anomaly.js', 'js/page-asset.js'];
    chartPages.forEach(function (file) {
        const source = readFile(file);
        const body = startBody(source);
        const fitIndex = body.indexOf('fitRem()');
        const initIndex = body.search(/init[A-Za-z]*\s*\(/);
        check('结构：' + file + ' 在 start() 里先设定 rem 基准再初始化图表',
            fitIndex >= 0 && initIndex > fitIndex,
            'fitRem@' + fitIndex + ' init@' + initIndex);
        check('结构：' + file + ' 图表尺寸自适应走统一实现（不再手写 window.resize → resize()）',
            /autoResize|bindChartAutoResize/.test(source)
            && !/addEventListener\('resize',[\s\S]{0,80}?\.resize\(\)/.test(source));
    });
}

/* 取出 start() 函数的前若干字符，用于判断"调用顺序"（定义顺序在文件里是反的） */
function startBody(source) {
    const start = source.indexOf('function start()');
    if (start < 0) { return ''; }
    const end = source.indexOf('\n    }', start);
    return source.slice(start, end < 0 ? start + 1200 : end);
}

/* ------------------------------------------------------------------ */
/* 4) 主流程                                                          */
/* ------------------------------------------------------------------ */
(async function main() {
    console.log('=== 页面观感与布局自动检查（真实执行页面脚本 + 静态结构与样式断言）===\n');
    console.log('--- 静态结构与样式规则 ---');
    checkStaticRules();
    checkWebAttackKnowledge();
    console.log('');

    for (const page of PAGES) {
        console.log('--- ' + page.name + '（' + page.file + '）---');
        try {
            await runPage(page);
        } catch (error) {
            failures.push(page.name + ' 脚本执行异常 —— ' + error.message);
            console.log('[FAIL] ' + page.name + ' 脚本执行异常：' + error.message);
        }
        console.log('');
    }
    console.log('===== 结果：' + passed + ' 项通过 / ' + failures.length + ' 项失败 =====');
    failures.forEach(function (item) { console.log('  [x] ' + item); });
    process.exit(failures.length ? 1 : 0);
})();




