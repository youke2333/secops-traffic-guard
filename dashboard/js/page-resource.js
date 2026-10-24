/**
 * page-resource.js —— 硬件资源占用（大屏「硬件资源」功能页）
 *
 * 数据：GET /system/resources（CPU / 内存 / 磁盘 / 网卡，2s 轮询，自带 5 分钟趋势）。
 * 着色：统一走 UI.loadColor()，即网络安全标准色标
 *       红(≥85%) 橙(≥70%) 黄(≥50%) 绿(<50%)，越限即在标题右侧标注「异常」。
 *
 * 说明：本页签在未激活时是 display:none，容器宽高为 0，
 *      因此图表延迟到首次进入该功能时才初始化，切回时统一 resize。
 */
(function (global) {
    'use strict';

    var MAX_POINTS = 150;                 // 2s × 150 ≈ 5 分钟
    var THRESHOLDS = { low: 50, medium: 70, high: 85 };
    var charts = { cpu: null, mem: null, disk: null, trend: null };
    var series = { labels: [], cpu: [], mem: [], disk: [] };
    var timer = null;
    var mounted = false;
    var lastSnapshot = null;

    function el(id) { return document.getElementById(id); }
    function num(value) {
        var parsed = Number(value);
        return isFinite(parsed) ? parsed : null;
    }
    function bytes(value) {
        var size = num(value);
        if (size === null) { return '-'; }
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var index = 0;
        while (size >= 1024 && index < units.length - 1) { size /= 1024; index += 1; }
        return size.toFixed(index === 0 ? 0 : 1) + ' ' + units[index];
    }
    function duration(seconds) {
        var total = Math.max(0, Math.round(num(seconds) || 0));
        var day = Math.floor(total / 86400);
        var hour = Math.floor(total % 86400 / 3600);
        var minute = Math.floor(total % 3600 / 60);
        if (day) { return day + '天' + hour + '小时'; }
        if (hour) { return hour + '小时' + minute + '分'; }
        return minute + '分钟';
    }
    function clock(ts) {
        var text = String(ts || '');
        return text.length >= 19 ? text.slice(11, 19) : text;
    }

    /* ---------------- 仪表盘 ---------------- */
    /* 大屏整体按 rem 缩放，图表内字号必须跟随根字号，否则小屏会显得过小 */
    function fs(ratio, min, max) {
        var root = parseFloat(global.getComputedStyle(document.documentElement).fontSize) || 16;
        return Math.round(Math.min(max, Math.max(min, root * ratio)));
    }

    function gaugeOption(value) {
        var has = value !== null;
        var color = has ? UI.loadColor(value, THRESHOLDS) : '#5f7d95';
        /* 环宽随根字号缩放：太细看不清分段，太粗在窄卡片里会糊成一圈 */
        var ring = fs(0.2, 12, 22);
        /* 底环按安全色标分四段（正常/中危/高危/紧急），指针落点即风险档位。
           色值与 UI.loadColor 同源，避免出现"指针是橙色、却指在红色段"的自相矛盾。
           alpha 压在半透明档，让实色指针始终是视觉焦点。 */
        var band = [
            [THRESHOLDS.low / 100, 'rgba(67,160,71,0.42)'],
            [THRESHOLDS.medium / 100, 'rgba(253,216,53,0.45)'],
            [THRESHOLDS.high / 100, 'rgba(251,140,0,0.5)'],
            [1, 'rgba(229,57,53,0.55)']
        ];
        return {
            animationDuration: 600,
            series: [{
                type: 'gauge',
                startAngle: 215,
                endAngle: -35,
                min: 0,
                max: 100,
                radius: '86%',
                center: ['50%', '56%'],
                /* 不画进度弧：本方案靠"指针落在哪一段色带"表达风险，叠进度会盖住分段 */
                progress: { show: false },
                axisLine: { lineStyle: { width: ring, color: band } },
                pointer: {
                    /* 无数据时不画指针：停在 0 位再加个灰针会被误读成"负载 0%" */
                    show: has,
                    length: '62%',
                    width: fs(0.06, 4, 8),
                    /* 本项目用的是 ECharts 4.0.4，指针取色走 data[i].itemStyle.color，
                       这里的 itemStyle 在该版本会被忽略（实测确认），保留仅作新版本兼容 */
                    itemStyle: { color: color, shadowBlur: 6, shadowColor: 'rgba(0,0,0,0.45)' }
                },
                anchor: {
                    show: has,
                    showAbove: true,
                    size: fs(0.12, 8, 14),
                    itemStyle: { color: color, borderColor: '#0a1622', borderWidth: 2 }
                },
                axisTick: { show: false },
                splitLine: { show: false },
                axisLabel: {
                    color: '#8fb6cf',
                    fontSize: fs(0.135, 11, 16),
                    distance: -Math.round(ring * 1.5)
                },
                detail: {
                    valueAnimation: true,
                    formatter: function (val) { return has ? val.toFixed(1) + '%' : '--'; },
                    color: color,
                    fontSize: fs(0.36, 24, 42),
                    offsetCenter: [0, '46%']
                },
                title: { show: false },
                /* 指针与锚点的实际着色入口：ECharts 4 按数据项 itemStyle 给指针上色 */
                data: [{ value: has ? value : 0, itemStyle: { color: color } }]
            }]
        };
    }

    /* ---------------- 趋势 ---------------- */
    function trendOption() {
        return {
            animation: false,
            grid: { left: 10, right: 58, top: 34, bottom: 4, containLabel: true },
            tooltip: {
                trigger: 'axis',
                backgroundColor: 'rgba(6,30,55,0.92)',
                borderColor: '#1ba7c9',
                textStyle: { color: '#e6f4ff', fontSize: fs(0.14, 11, 16) }
            },
            legend: {
                top: 2, itemWidth: 14, itemHeight: 8, itemGap: 14,
                textStyle: { color: '#9fd8ff', fontSize: fs(0.14, 11, 16) }
            },
            xAxis: {
                type: 'category',
                boundaryGap: false,
                data: series.labels,
                axisLine: { lineStyle: { color: '#2b6f9b' } },
                axisLabel: { color: '#9fd8ff', fontSize: fs(0.14, 11, 16), hideOverlap: true },
                axisTick: { show: false }
            },
            yAxis: {
                type: 'value', min: 0, max: 100, name: '%',
                nameTextStyle: { color: '#9fd8ff', fontSize: fs(0.14, 11, 16) },
                axisLabel: { color: '#9fd8ff', fontSize: fs(0.14, 11, 16) },
                splitLine: { lineStyle: { color: 'rgba(43,111,155,0.28)' } }
            },
            series: [
                { name: 'CPU', type: 'line', smooth: true, showSymbol: false, data: series.cpu,
                  lineStyle: { width: 2, color: '#e53935' },
                  areaStyle: { color: 'rgba(229,57,53,0.12)' },
                  /* 阈值线标签只写数字，避免长文案在小屏被图表右边界裁切 */
                  markLine: { silent: true, symbol: 'none', data: [{ yAxis: 85 }],
                              lineStyle: { color: '#fb8c00', type: 'dashed', width: 1 },
                              label: { position: 'end', formatter: '阈值 {c}%',
                                       color: '#fb8c00', fontSize: fs(0.12, 10, 14) } } },
                { name: '内存', type: 'line', smooth: true, showSymbol: false, data: series.mem,
                  lineStyle: { width: 2, color: '#fdd835' } },
                { name: '磁盘', type: 'line', smooth: true, showSymbol: false, data: series.disk,
                  lineStyle: { width: 2, color: '#4fc3f7' } }
            ]
        };
    }

    function ensureCharts() {
        if (charts.trend) { return; }
        if (!global.echarts) { return; }
        charts.cpu = echarts.init(el('resCpuGauge'));
        charts.mem = echarts.init(el('resMemGauge'));
        charts.disk = echarts.init(el('resDiskGauge'));
        charts.trend = echarts.init(el('resTrend'));
        charts.cpu.setOption(gaugeOption(null));
        charts.mem.setOption(gaugeOption(null));
        charts.disk.setOption(gaugeOption(null));
        charts.trend.setOption(trendOption());
        UI.autoResize([charts.cpu, charts.mem, charts.disk, charts.trend]);
    }

    function resize() {
        Object.keys(charts).forEach(function (key) {
            var chart = charts[key];
            if (chart && !(chart.isDisposed && chart.isDisposed())) {
                try { chart.resize(); } catch (error) { /* 忽略 */ }
            }
        });
    }

    /* ---------------- 文案渲染 ---------------- */
    function setFlag(id, value) {
        var node = el(id);
        if (!node) { return; }
        var has = value !== null;
        var level = has ? UI.loadLevel(value, THRESHOLDS) : 'unknown';
        node.textContent = has ? (level === 'safe' ? '正常' : '异常') : '--';
        node.className = 'res-flag ' + level;
    }

    function detailRow(label, value, extra) {
        return '<div class="res-kv"><span>' + UI.esc(label) + '</span><b>'
            + UI.esc(value) + '</b>' + (extra || '') + '</div>';
    }

    function renderDetail(data) {
        var box = el('resDetail');
        if (!box) { return; }
        var cpu = data.cpu || {};
        var mem = data.memory || {};
        var disk = data.disk || {};
        var net = data.network || {};
        var load = cpu.load || {};
        var rows = [
            detailRow('运行环境', (data.platform || '-') + ' / ' + (data.host || '-')),
            detailRow('运行时长', duration(data.uptime_sec)),
            detailRow('CPU 核心', (cpu.cores || '-') + ' 核'),
            detailRow('系统负载(1m)', load['1m'] === null || load['1m'] === undefined ? '不可用'
                : String(load['1m'])),
            detailRow('内存', bytes(mem.used) + ' / ' + bytes(mem.total), UI.abnTag(mem.percent, THRESHOLDS)),
            detailRow('磁盘 ' + (disk.path || ''), bytes(disk.used) + ' / ' + bytes(disk.total),
                UI.abnTag(disk.percent, THRESHOLDS)),
            detailRow('网卡吞吐', UI.fmt.bps(net.rx_bps) + ' ↓ / ' + UI.fmt.bps(net.tx_bps) + ' ↑',
                UI.abnTag(net.util, { low: 40, medium: 65, high: 85 })),
            detailRow('采样来源', data.source || '-')
        ];
        box.innerHTML = rows.join('');
    }

    function renderLegend() {
        var box = el('resLegend');
        if (!box) { return; }
        var items = [
            { color: UI.SEVERITY_COLOR.critical, text: '紧急 / 越限', desc: '≥ 85%' },
            { color: UI.SEVERITY_COLOR.high, text: '高危', desc: '≥ 70%' },
            { color: UI.SEVERITY_COLOR.medium, text: '中危', desc: '≥ 50%' },
            { color: UI.SEVERITY_COLOR.low, text: '低危', desc: '参考' },
            { color: UI.SEVERITY_COLOR.safe, text: '正常', desc: '< 50%' }
        ];
        box.innerHTML = items.map(function (item) {
            return '<div class="res-legend-item" style="--abn:' + item.color + '">'
                + '<i style="background:' + item.color + '"></i>'
                + '<b>' + item.text + '</b><span>' + item.desc + '</span></div>';
        }).join('') + '<p class="res-note">色标与告警等级一致：红=紧急、橙=高危、黄=中危、蓝=低危、绿=正常。</p>';
    }

    function apply(data) {
        lastSnapshot = data;
        var cpu = data.cpu || {};
        var mem = data.memory || {};
        var disk = data.disk || {};
        var cpuValue = num(cpu.percent);
        var memValue = num(mem.percent);
        var diskValue = num(disk.percent);

        if (charts.cpu) { charts.cpu.setOption(gaugeOption(cpuValue)); }
        if (charts.mem) { charts.mem.setOption(gaugeOption(memValue)); }
        if (charts.disk) { charts.disk.setOption(gaugeOption(diskValue)); }

        setFlag('resCpuFlag', cpuValue);
        setFlag('resMemFlag', memValue);
        setFlag('resDiskFlag', diskValue);

        UI.setText('resCpuMeta', (cpu.cores || '-') + ' 核 ｜ 负载 '
            + (cpu.load && cpu.load['1m'] !== null && cpu.load['1m'] !== undefined
                ? cpu.load['1m'] : '不可用'));
        UI.setText('resMemMeta', bytes(mem.used) + ' / ' + bytes(mem.total));
        UI.setText('resDiskMeta', '分区 ' + (disk.path || '-') + ' ｜ 可用 ' + bytes(disk.free));

        series.labels.push(clock(data.ts));
        series.cpu.push(cpuValue === null ? null : cpuValue);
        series.mem.push(memValue === null ? null : memValue);
        series.disk.push(diskValue === null ? null : diskValue);
        while (series.labels.length > MAX_POINTS) {
            series.labels.shift();
            series.cpu.shift();
            series.mem.shift();
            series.disk.shift();
        }
        if (charts.trend) {
            charts.trend.setOption({
                xAxis: { data: series.labels },
                series: [{ data: series.cpu }, { data: series.mem }, { data: series.disk }]
            });
        }

        renderDetail(data);
    }

    /* ---------------- 数据拉取 ---------------- */
    function load() {
        return SecApi.get('/system/resources').then(apply).catch(function () {
            var box = el('resDetail');
            if (box && !lastSnapshot) {
                box.innerHTML = '<div class="res-empty">资源接口不可用（后端未启动或版本过旧）</div>';
            }
        });
    }

    function startPolling() {
        if (timer) { return; }
        load();
        timer = setInterval(load, 2000);
    }

    function stopPolling() {
        if (timer) { clearInterval(timer); timer = null; }
    }

    /* ---------------- 视图切换 ---------------- */
    function show(visible) {
        var pane = el('resourcePane');
        var overview = el('overviewPane');
        if (!pane || !overview) { return; }
        try {
            global.sessionStorage.setItem('secops.view:index', visible ? 'resource' : 'overview');
        } catch (error) { /* 隐私模式忽略 */ }
        if (visible) {
            ensureCharts();
            overview.style.display = 'none';
            pane.style.display = '';
            resize();
            setTimeout(resize, 60);
            setTimeout(resize, 240);
            startPolling();
            renderLegend();
        } else {
            pane.style.display = 'none';
            overview.style.display = '';
            stopPolling();
            /* 大屏图表在隐藏期间尺寸为 0，切回后必须重算 */
            UI.resizeCharts();
            setTimeout(UI.resizeCharts, 60);
            setTimeout(UI.resizeCharts, 240);
        }
    }

    function bind() {
        var box = el('viewSwitch');
        if (!box) { return; }
        box.addEventListener('click', function (event) {
            var button = event.target.closest('[data-view]');
            if (!button) { return; }
            var view = button.getAttribute('data-view');
            Array.prototype.forEach.call(box.querySelectorAll('[data-view]'), function (node) {
                node.classList.toggle('active', node === button);
            });
            show(view === 'resource');
        });
    }

    function start() {
        bind();
        renderLegend();
        /* 支持 index.html#resource 深链直达硬件资源页 */
        var hash = String(global.location.hash || '').replace(/^#\/?/, '').toLowerCase();
        /* 再次进入页面时若上次停留在资源页，恢复到该功能 */
        var saved = '';
        try { saved = global.sessionStorage.getItem('secops.view:index') || ''; } catch (error) { saved = ''; }
        if (hash === 'resource' || hash === 'hardware' || hash === 'overview' || saved === 'resource') {
            var want = (hash === 'overview') ? 'overview' : 'resource';
            if (hash === 'overview' || hash === 'resource' || hash === 'hardware') {
                /* 深链优先级最高，忽略历史记忆 */
                var target = document.querySelector('#viewSwitch [data-view="' + want + '"]');
                if (target) { target.click(); }
                return;
            }
            var button = document.querySelector('#viewSwitch [data-view="resource"]');
            if (button) { button.click(); }
        }
    }

    global.SecResource = { start: start, show: show };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})(window);
