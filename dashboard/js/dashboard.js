/**
 * dashboard.js —— 大屏渲染层
 *
 * 职责：ECharts 图表初始化与增量更新、列表渲染、交互（解封/封禁/扫描/确认告警），
 *       以及「检测 → 告警弹窗 → 一键隔离」的可视化闭环。
 *
 * 数据来源统一由 SecApi 事件驱动，因此 SSE / 轮询 / 演示数据三种模式共用同一套渲染逻辑。
 */
(function (global) {
    'use strict';

    /* 网络安全标准色标：红=紧急、橙=高危、黄=中危、蓝=低危、绿=正常（与 ui.js 保持一致） */
    var SEVERITY_COLOR = {
        critical: '#e53935', high: '#fb8c00', medium: '#fdd835', low: '#4fc3f7', safe: '#43a047'
    };
    var CATEGORY_COLOR = ['#e53935', '#fb8c00', '#fdd835', '#4fc3f7', '#43a047', '#9b7bff'];

    var charts = {};
    var trendBuffer = { bpsIn: [], bpsOut: [], pps: [] };
    var MAX_POINTS = 240;
    var soundEnabled = false;

    /* ---------------- 工具函数 ---------------- */
    function formatBps(value) {
        if (!value) { return '0 bps'; }
        if (value >= 1e9) { return (value / 1e9).toFixed(2) + ' Gbps'; }
        if (value >= 1e6) { return (value / 1e6).toFixed(2) + ' Mbps'; }
        if (value >= 1e3) { return (value / 1e3).toFixed(1) + ' Kbps'; }
        return value.toFixed(0) + ' bps';
    }
    function formatCount(value) {
        var number = Number(value || 0);
        if (number >= 100000000) { return (number / 100000000).toFixed(2) + ' 亿'; }
        if (number >= 10000) { return (number / 10000).toFixed(2) + ' 万'; }
        return String(Math.round(number));
    }
    function formatBytes(value) {
        var size = Number(value || 0);
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var index = 0;
        while (size >= 1024 && index < units.length - 1) { size /= 1024; index += 1; }
        return size.toFixed(2) + ' ' + units[index];
    }
    function timeText(seconds) {
        if (seconds === null || seconds === undefined) { return '永久'; }
        var minutes = Math.floor(seconds / 60);
        var rest = Math.floor(seconds % 60);
        return minutes + '分' + (rest < 10 ? '0' : '') + rest + '秒';
    }
    /** 坐标轴用的紧凑带宽格式（"1.2G" / "120M" / "8.5K"），避免轴标签过长挤压绘图区 */
    function shortBps(value) {
        var number = Number(value || 0);
        if (number >= 1e9) { return (number / 1e9).toFixed(1) + 'G'; }
        if (number >= 1e6) { return (number / 1e6).toFixed(0) + 'M'; }
        if (number >= 1e3) { return (number / 1e3).toFixed(0) + 'K'; }
        return String(Math.round(number));
    }
    function shortCount(value) {
        var number = Number(value || 0);
        if (number >= 10000) { return (number / 10000).toFixed(1) + 'w'; }
        if (number >= 1000) { return (number / 1000).toFixed(1) + 'k'; }
        return String(Math.round(number));
    }
    function setText(id, text) {
        var node = document.getElementById(id);
        if (node) { node.textContent = text; }
    }
    /** 告警详情里的攻击特征着色：优先用 ui.js 的 UI.hl（同一套特征库），
     *  极端情况下（ui.js 未加载）退化为纯文本转义，保证弹窗永不空白、也不引入 XSS。 */
    function highlight(text) {
        if (global.UI && typeof UI.hl === 'function') { return UI.hl(text); }
        return escapeHtml(text);
    }
    function escapeHtml(text) {
        return String(text === undefined || text === null ? '' : text)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    /* ---------------- 主趋势图（毫秒级滚动） ---------------- */
    function initTrendChart() {
        var dom = document.getElementById('chartTrend');
        if (!dom) { return; }
        charts.trend = echarts.init(dom);
        charts.trend.setOption({
            tooltip: { trigger: 'axis', backgroundColor: 'rgba(6,30,55,0.92)', borderColor: '#00d8ff',
                       textStyle: { color: '#fff' } },
            legend: { data: ['入站带宽', '出站带宽', '包速率'], textStyle: { color: '#9fd8ff', fontSize: 13 },
                      top: 2, itemWidth: 14, itemHeight: 8, itemGap: 12 },
            /* containLabel：坐标轴标签参与布局计算，彻底避免标签被裁切 / 压住曲线 */
            grid: { left: 8, right: 12, top: 34, bottom: 6, containLabel: true },
            xAxis: {
                type: 'time', boundaryGap: false,
                axisLine: { lineStyle: { color: '#2b6f9b' } },
                axisLabel: { color: '#9fd8ff', fontSize: 12, hideOverlap: true },
                splitLine: { show: false }
            },
            yAxis: [
                { type: 'value', name: '带宽', nameTextStyle: { color: '#9fd8ff', fontSize: 12 },
                  nameGap: 10, axisLabel: { color: '#9fd8ff', fontSize: 12,
                                            formatter: function (value) { return shortBps(value); } },
                  splitLine: { lineStyle: { color: 'rgba(43,111,155,0.3)' } } },
                { type: 'value', name: '包速率', nameTextStyle: { color: '#febe12', fontSize: 12 },
                  nameGap: 10, axisLabel: { color: '#febe12', fontSize: 12,
                                            formatter: function (value) { return shortCount(value); } },
                  splitLine: { show: false } }
            ],
            series: [
                { name: '入站带宽', type: 'line', smooth: true, showSymbol: false, yAxisIndex: 0,
                  lineStyle: { width: 2, color: '#00ffff' },
                  areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                      { offset: 0, color: 'rgba(0,255,255,0.45)' },
                      { offset: 1, color: 'rgba(0,255,255,0.02)' }]) },
                  data: [] },
                { name: '出站带宽', type: 'line', smooth: true, showSymbol: false, yAxisIndex: 0,
                  lineStyle: { width: 2, color: '#7bdd43' },
                  areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                      { offset: 0, color: 'rgba(123,221,67,0.35)' },
                      { offset: 1, color: 'rgba(123,221,67,0.02)' }]) },
                  data: [] },
                { name: '包速率', type: 'line', smooth: true, showSymbol: false, yAxisIndex: 1,
                  lineStyle: { width: 1.5, color: '#febe12', type: 'dashed' }, data: [] }
            ]
        });
    }

    /* ---------------- 异常端口 TOP（非标准端口高亮） ---------------- */
    function initPortChart() {
        var dom = document.getElementById('chartPorts');
        if (!dom) { return; }
        charts.ports = echarts.init(dom);
        charts.ports.setOption({
            tooltip: {
                trigger: 'axis', axisPointer: { type: 'shadow' },
                backgroundColor: 'rgba(6,30,55,0.92)', textStyle: { color: '#fff' },
                formatter: function (params) {
                    var item = params[0];
                    var row = (item.data && item.data.row) || {};
                    return '端口 ' + item.name + '<br/>流量 ' + formatBps(row.bps || 0)
                        + '<br/>包速率 ' + formatCount(row.pps || 0) + ' pps'
                        + '<br/>来源 ' + escapeHtml(row.top_source || '-')
                        + '<br/>类型 ' + (row.is_standard ? '标准端口' : '<b style="color:#ff7c44">非标准端口</b>');
                }
            },
            grid: { left: 4, right: 56, top: 4, bottom: 2, containLabel: true },
            xAxis: { type: 'value', axisLabel: { show: false }, splitLine: { show: false }, axisLine: { show: false } },
            yAxis: { type: 'category', inverse: true, data: [],
                     axisLabel: { color: '#cfe9ff', fontSize: 13, width: 56, overflow: 'truncate' },
                     axisLine: { lineStyle: { color: '#2b6f9b' } } },
            series: [{
                type: 'bar', barWidth: 8, barCategoryGap: '38%', data: [],
                label: { show: true, position: 'right', color: '#fff', fontSize: 12,
                         formatter: function (item) { return shortBps(item.value); } }
            }]
        });
    }

    /* ---------------- 事件类型分布（玫瑰图） ---------------- */
    var categoryItems = [];

    function initCategoryChart() {
        var dom = document.getElementById('chartCategories');
        if (!dom) { return; }
        charts.categories = echarts.init(dom);
        charts.categories.setOption({
            color: CATEGORY_COLOR,
            tooltip: {
                trigger: 'item', backgroundColor: 'rgba(6,30,55,0.92)', textStyle: { color: '#fff' },
                formatter: function (item) { return item.name + '<br/>数量：' + item.value + '（' + item.percent + '%）'; }
            },
            /* 窄面板里"竖排图例 + 引导线标签"必然互相压盖：
               改为底部横排图例承载名称与数量，饼图本身不再画标签 */
            legend: {
                orient: 'horizontal', bottom: 0, left: 'center', itemWidth: 9, itemHeight: 9,
                itemGap: 8, textStyle: { color: '#cfe9ff', fontSize: 12 },
                formatter: function (name) {
                    for (var i = 0; i < categoryItems.length; i += 1) {
                        if (categoryItems[i].name === name) { return name + ' ' + categoryItems[i].value; }
                    }
                    return name;
                }
            },
            series: [{
                type: 'pie', radius: ['38%', '62%'], center: ['50%', '42%'],
                avoidLabelOverlap: true, minShowLabelAngle: 12,
                label: { show: false }, labelLine: { show: false },
                emphasis: { label: { show: true, fontSize: 13, color: '#fff', formatter: '{b}\n{d}%' } },
                data: []
            }]
        });
    }

    /* ---------------- 攻击来源 TOP（横向条形） ---------------- */
    function initSourceChart() {
        var dom = document.getElementById('chartSources');
        if (!dom) { return; }
        charts.sources = echarts.init(dom);
        charts.sources.setOption({
            tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
                       backgroundColor: 'rgba(6,30,55,0.92)', textStyle: { color: '#fff' } },
            grid: { left: 4, right: 40, top: 4, bottom: 2, containLabel: true },
            xAxis: { type: 'value', axisLabel: { color: '#9fd8ff', fontSize: 12 },
                     splitLine: { lineStyle: { color: 'rgba(43,111,155,0.3)' } } },
            yAxis: { type: 'category', inverse: true, data: [],
                     axisLabel: { color: '#cfe9ff', fontSize: 13, width: 92, overflow: 'truncate' },
                     axisLine: { lineStyle: { color: '#2b6f9b' } } },
            series: [{
                type: 'bar', barWidth: 9,
                itemStyle: { color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
                    { offset: 0, color: '#fa3e5f' }, { offset: 1, color: '#febe12' }]) },
                label: { show: true, position: 'right', color: '#fff', fontSize: 12 },
                data: []
            }]
        });
    }

    function initCharts() {
        initTrendChart();
        initPortChart();
        initCategoryChart();
        initSourceChart();
    }

    /* ---------------- 渲染：实时指标 ---------------- */
    function renderMetrics(payload) {
        if (!payload) { return; }
        var bps = (payload.bps_in || 0) + (payload.bps_out || 0);
        var pps = (payload.pps_in || 0) + (payload.pps_out || 0);
        var capacity = 1000 * 1e6;
        var util = (payload.kpi && payload.kpi.bandwidth_util !== undefined)
            ? payload.kpi.bandwidth_util : Math.min(100, bps / capacity * 100);

        setText('kpiBps', formatBps(bps));
        setText('kpiUtil', Number(util || 0).toFixed(2) + ' %');
        setText('kpiPps', formatCount(pps) + ' pps');
        setText('kpiConns', formatCount(payload.conns || 0));
        setText('statPackets', formatCount(payload.packets_total || 0));
        setText('statBytes', formatBytes(payload.bytes_total || 0));
        setText('statSrc', formatCount(payload.unique_src || 0));
        setText('statPorts', formatCount(payload.unique_dst_ports || 0));

        var utilBar = document.getElementById('kpiUtilBar');
        if (utilBar) {
            utilBar.style.width = Math.min(100, util || 0) + '%';
            utilBar.style.background = util > 80 ? '#ff3b4e' : (util > 50 ? '#febe12' : '#00ffff');
        }

        if (charts.trend) {
            var ts = (payload.ts || Date.now() / 1000) * 1000;
            trendBuffer.bpsIn.push([ts, payload.bps_in || 0]);
            trendBuffer.bpsOut.push([ts, payload.bps_out || 0]);
            trendBuffer.pps.push([ts, pps]);
            ['bpsIn', 'bpsOut', 'pps'].forEach(function (key) {
                if (trendBuffer[key].length > MAX_POINTS) { trendBuffer[key].shift(); }
            });
            charts.trend.setOption({
                series: [{ data: trendBuffer.bpsIn }, { data: trendBuffer.bpsOut }, { data: trendBuffer.pps }]
            });
        }

        if (charts.ports && payload.ports && payload.ports.length) {
            var rows = payload.ports.slice(0, 6).reverse();
            charts.ports.setOption({
                yAxis: { data: rows.map(function (row) { return row.port + '/' + row.protocol; }) },
                series: [{
                    data: rows.map(function (row) {
                        return {
                            value: row.bps || 0, row: row,
                            itemStyle: { color: row.is_standard ? '#00bcd4' : '#ff3b4e' },
                            label: { color: row.is_standard ? '#cfe9ff' : '#ff8a8a' }
                        };
                    })
                }]
            });
        }
    }

    /* ---------------- 渲染：告警统计（类型分布 + 来源 TOP） ---------------- */
    function renderAlertStats(stats) {
        if (!stats) { return; }
        setText('statAlerts', formatCount(stats.total || 0));

        if (charts.categories) {
            var items = (stats.by_category || []).map(function (row) {
                return { name: row.category_text || row.category, value: row.count };
            });
            if (!items.length) {
                items = [{ name: '暂无告警', value: 1 }];
            }
            categoryItems = items;          // 供底部图例展示"名称 + 数量"
            charts.categories.setOption({ series: [{ data: items }] });
        }

        if (charts.sources) {
            var sources = (stats.top_sources || []).slice(0, 8).reverse();
            charts.sources.setOption({
                yAxis: { data: sources.map(function (row) { return row.ip; }) },
                series: [{ data: sources.map(function (row) { return row.count; }) }]
            });
        }
    }

    /* ---------------- 渲染：风险 IP 封禁表 ---------------- */
    function renderBlocks(payload) {
        var body = document.getElementById('blockBody');
        if (!body) { return; }
        var items = (payload && payload.items) || [];
        setText('statBlocked', formatCount(items.length));
        if (!items.length) {
            body.innerHTML = '<tr><td colspan="5" class="empty">暂无封禁记录（系统运行正常）</td></tr>';
            return;
        }
        body.innerHTML = items.slice(0, 12).map(function (item) {
            var color = SEVERITY_COLOR[item.severity] || '#febe12';
            return '<tr>'
                + '<td class="ip"><span class="dot" style="background:' + color + '"></span>'
                + escapeHtml(item.ip) + '</td>'
                + '<td><span class="tag" style="border-color:' + color + ';color:' + color + '">'
                + escapeHtml(item.category || 'manual') + '</span></td>'
                + '<td class="muted" title="' + escapeHtml(item.reason) + '">'
                + escapeHtml((item.reason || '').slice(0, 18)) + '</td>'
                + '<td class="countdown">' + timeText(item.remaining_sec) + '</td>'
                + '<td><button class="btn-mini" data-unblock="' + escapeHtml(item.ip) + '">解封</button></td>'
                + '</tr>';
        }).join('');
    }

    /* ---------------- 渲染：实时告警滚动播报 ---------------- */
    var alertCache = [];
    var rotateTimer = null;

    function renderAlertFeed(payload) {
        var items = (payload && payload.items) || [];
        alertCache = items.slice(0, 12);
        paintAlerts();
        if (!rotateTimer) {
            rotateTimer = setInterval(function () {
                if (alertCache.length > 1) {
                    alertCache.push(alertCache.shift());   // 循环滚动，形成"播报"效果
                    paintAlerts();
                }
            }, 4000);
        }
    }

    function paintAlerts() {
        var box = document.getElementById('alertScroll');
        if (!box) { return; }
        box.innerHTML = alertCache.map(function (item, index) {
            var color = SEVERITY_COLOR[item.severity] || '#febe12';
            var time = UI.fmt.time(item.ts).slice(11, 19);
            return '<li class="' + (index === 0 ? 'flash' : '') + '">'
                + '<span class="sev" style="background:' + color + '">' + escapeHtml(item.severity_text || '')
                + '</span>'
                + '<span class="cat">' + escapeHtml(item.category_text || item.category) + '</span>'
                + '<span class="ip">' + escapeHtml(item.source_ip || '-') + '</span>'
                + '<span class="time">' + escapeHtml(time) + '</span>'
                + '</li>';
        }).join('') || '<li class="empty">暂无安全告警</li>';
    }

    /* ---------------- 渲染：处置时间线 ---------------- */
    function renderDisposals(payload) {
        var box = document.getElementById('disposalList');
        if (!box) { return; }
        var items = (payload && payload.items) || [];
        if (!items.length) {
            box.innerHTML = '<li class="empty">暂无处置动作</li>';
            return;
        }
        // 动作文案统一走 UI.statusText（ui.js 的 STATUS_TEXT 是唯一来源），
        // 避免两边各维护一份映射、新增动作（比如封禁续期）时漏改
        box.innerHTML = items.slice(0, 8).map(function (item) {
            var dotColor = item.action === 'block' ? '#ff3b4e'
                : (item.action === 'extend' ? '#febe12' : '#44eab1');
            return '<li>'
                + '<span class="dot" style="background:' + dotColor + '"></span>'
                + '<span class="act">' + escapeHtml(UI.statusText(item.action)) + '</span>'
                + '<span class="target">' + escapeHtml(item.target || '-') + '</span>'
                + '<span class="time">' + escapeHtml(UI.fmt.time(item.ts).slice(5, 19)) + '</span>'
                + '</li>';
        }).join('');
    }

    /* ---------------- 渲染：资产与漏洞 ---------------- */
    function renderAssets(payload) {
        var box = document.getElementById('assetList');
        if (!box) { return; }
        var items = (payload && payload.items) || [];
        setText('statAssets', formatCount(items.length));
        box.innerHTML = items.slice(0, 10).map(function (item) {
            var color = SEVERITY_COLOR[item.risk_level] || '#44eab1';
            var ports = (item.open_ports || []).slice(0, 6).join(', ');
            return '<li>'
                + '<span class="dot" style="background:' + color + '"></span>'
                + '<span class="ip">' + escapeHtml(item.ip) + '</span>'
                + '<span class="ports" title="' + escapeHtml((item.open_ports || []).join(',')) + '">'
                + escapeHtml(ports) + '</span>'
                + '<span class="os" title="' + escapeHtml(item.os_guess) + '">'
                + escapeHtml((item.tags || []).join('/') || '未知') + '</span>'
                + '</li>';
        }).join('') || '<li class="empty">尚未发现资产（等待流量特征学习完成）</li>';
    }

    function renderVulns(payload) {
        var box = document.getElementById('vulnList');
        if (!box) { return; }
        var items = (payload && payload.items) || [];
        setText('statVulns', formatCount(items.length));
        box.innerHTML = items.slice(0, 10).map(function (item) {
            var color = SEVERITY_COLOR[item.severity] || '#febe12';
            return '<li title="' + escapeHtml(item.recommendation) + '">'
                + '<span class="sev" style="background:' + color + '">' + escapeHtml(item.cve) + '</span>'
                + '<span class="title">' + escapeHtml((item.title || '').slice(0, 26)) + '</span>'
                + '<span class="host">' + escapeHtml(item.asset_ip) + ':' + escapeHtml(item.port) + '</span>'
                + '</li>';
        }).join('') || '<li class="empty">暂无未修复漏洞</li>';
    }

    /* ---------------- 状态徽标与时钟 ---------------- */
    function renderStatus(status) {
        if (!status) { return; }
        var isMock = status.status === 'mock';
        var modeText = { ebpf: 'eBPF 采集', scapy: 'libpcap 采集', demo: '演示流量', unknown: '初始化中' };
        setText('modeBadge', isMock ? '演示数据（后端未连接）' : (modeText[status.capture_mode] || status.capture_mode));
        var modeNode = document.getElementById('modeBadge');
        if (modeNode) { modeNode.className = 'badge ' + (isMock ? 'badge-warn' : 'badge-ok'); }

        var fwText = (status.firewall_backend || 'none') + (status.dry_run ? ' · DRY-RUN' : ' · 已生效');
        setText('fwBadge', fwText);
        var fwNode = document.getElementById('fwBadge');
        if (fwNode) { fwNode.className = 'badge ' + (status.dry_run ? 'badge-warn' : 'badge-ok'); }

        setText('versionBadge', 'v' + (status.version || '-'));
    }

    function startClock() {
        function tick() {
            var now = new Date();
            function pad(value) { return (value < 10 ? '0' : '') + value; }
            var week = ['星期日', '星期一', '星期二', '星期三', '星期四', '星期五', '星期六'];
            setText('clock', now.getFullYear() + '-' + pad(now.getMonth() + 1) + '-' + pad(now.getDate())
                + ' ' + pad(now.getHours()) + ':' + pad(now.getMinutes()) + ':' + pad(now.getSeconds())
                + ' ' + week[now.getDay()]);
        }
        tick();
        setInterval(tick, 1000);
    }

    /* ---------------- 告警弹窗（检测 → 人工确认 → 隔离） ---------------- */
    var currentAlert = null;
    var ALERT_AUTO_CLOSE_MS = 5000;      // 弹窗展示时长：5 秒后自动关闭
    var alertAutoCloseTimer = null;
    // 印章海报背景水印：按严重度取英文等级词（仅装饰，缺失时回落 ALERT）
    var SEVERITY_WATERMARK = {
        critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO'
    };

    function showAlertModal(anomaly) {
        currentAlert = anomaly;
        var modal = document.getElementById('customModal');
        if (!modal) { return; }
        setText('alertCategory', anomaly.category_text || anomaly.category);
        setText('alertSeverity', anomaly.severity_text || anomaly.severity);
        setText('alertSource', anomaly.source_ip || '-');
        setText('alertTarget', (anomaly.dest_ip || '-') + ':' + (anomaly.dest_port || '-'));
        setText('alertTime', anomaly.ts_text || new Date().toLocaleString('zh-CN'));
        /* 告警详情：命中片段（cat /etc/passwd、select ... from、<script> 等）用红色标注 */
        var messageNode = document.getElementById('alertMessage');
        if (messageNode) { messageNode.innerHTML = highlight(anomaly.message || ''); }
        setText('alertDetector', anomaly.detector || '-');
        setText('alertWatermark',
            SEVERITY_WATERMARK[String(anomaly.severity || '').toLowerCase()] || 'ALERT');
        var autoTag = document.getElementById('alertAutoBlock');
        if (autoTag) { autoTag.style.display = anomaly.blocked ? 'inline-block' : 'none'; }
        modal.style.display = 'block';
        // 每次展示都重新计时；5 秒内出现新告警则顺延，避免弹窗被旧计时器提前关掉
        startAutoClose();
        if (soundEnabled) { playAlarm(); }
    }

    /** 启动 5 秒自动关闭计时（鼠标悬停 / 键盘聚焦时暂停，便于点击「查看详情」） */
    function startAutoClose() {
        stopAutoClose();
        alertAutoCloseTimer = setTimeout(function () {
            alertAutoCloseTimer = null;
            closeModals();
        }, ALERT_AUTO_CLOSE_MS);
    }

    function stopAutoClose() {
        if (alertAutoCloseTimer) {
            clearTimeout(alertAutoCloseTimer);
            alertAutoCloseTimer = null;
        }
    }

    function playAlarm() {
        try {
            var audio = new Audio('img/tsy.mp3');
            audio.volume = 0.6;
            audio.play();
        } catch (err) {
            console.warn('提示音播放失败（浏览器策略限制）', err);
        }
    }

    function closeModals() {
        stopAutoClose();                    // 手动/点击关闭时清掉自动关闭计时，避免误关后续弹窗
        ['customModal', 'isolationModal'].forEach(function (id) {
            var node = document.getElementById(id);
            if (node) { node.style.display = 'none'; }
        });
    }

    function showToast(message, isError) {
        var toast = document.getElementById('toast');
        if (!toast) { return; }
        toast.textContent = message;
        toast.className = 'toast show' + (isError ? ' error' : '');
        clearTimeout(showToast._timer);
        showToast._timer = setTimeout(function () { toast.className = 'toast'; }, 3200);
    }

    /** 轮询异步扫描任务，直到 done/error（后端已把长任务放后台，避免接口被超时取消）。 */
    function pollScanJob(jobId, button) {
        var attempts = 0;
        return new Promise(function (resolve) {
            var timer = setInterval(function () {
                attempts += 1;
                SecApi.get('/vulns/scan/' + jobId).then(function (job) {
                    if (button && job.percent !== undefined) {
                        button.textContent = '扫描中 ' + job.percent + '%';
                    }
                    if (job.status === 'done' || job.status === 'error') {
                        clearInterval(timer);
                        if (job.status === 'done') {
                            var summary = job.summary || {};
                            showToast('扫描完成：目标 ' + summary.targets + ' 个，服务 '
                                + summary.services_found + ' 个，漏洞 ' + summary.vulns_found + ' 个');
                        } else {
                            showToast('扫描失败：' + job.error, true);
                        }
                        SecApi.refreshAll();
                        resolve(job);
                    } else if (attempts > 150) {          // 最多等 5 分钟
                        clearInterval(timer);
                        showToast('扫描仍在后台执行，可稍后在漏洞页查看任务状态');
                        resolve(null);
                    }
                }).catch(function () {
                    if (attempts > 150) { clearInterval(timer); resolve(null); }
                });
            }, 2000);
        });
    }

    /* ---------------- 交互绑定 ---------------- */
    function bindEvents() {
        document.addEventListener('click', function (event) {
            var target = event.target;
            var unblockButton = target && target.closest ? target.closest('[data-unblock]') : null;
            if (unblockButton) {
                var ip = unblockButton.getAttribute('data-unblock');
                unblockButton.disabled = true;
                SecApi.unblock(ip).then(function (result) {
                    showToast(result.message || ('已解封 ' + ip), !result.success);
                    SecApi.refreshAll();
                }).catch(function (error) {
                    unblockButton.disabled = false;
                    showToast('解封失败：' + error.message, true);
                });
            }
        });

        var dismissButton = document.getElementById('dismissButton');
        if (dismissButton) {
            dismissButton.addEventListener('click', closeModals);
        }

        /* 悬停 / 聚焦弹窗时暂停自动关闭，移开后再续 5 秒，保证「查看详情」可点击 */
        var alertCard = document.querySelector('#customModal .alert-stamp');
        if (alertCard) {
            ['mouseenter', 'focusin'].forEach(function (name) {
                alertCard.addEventListener(name, stopAutoClose);
            });
            ['mouseleave', 'focusout'].forEach(function (name) {
                alertCard.addEventListener(name, function () {
                    var modal = document.getElementById('customModal');
                    if (modal && modal.style.display === 'block') { startAutoClose(); }
                });
            });
        }

        /* 查看详情：跳转威胁告警页并自动展开该告警对应的威胁事件抽屉。
           优先用后端返回的 threat_event_id 精确定位；缺失时退化为按源 IP 过滤列表。 */
        var detailButton = document.getElementById('detailButton');
        if (detailButton) {
            detailButton.addEventListener('click', function () {
                var alert = currentAlert || {};
                var target = 'threat.html';
                if (alert.threat_event_id) {
                    target += '?event=' + encodeURIComponent(alert.threat_event_id);
                } else if (alert.source_ip) {
                    target += '?src_ip=' + encodeURIComponent(alert.source_ip);
                }
                window.location.href = target;
            });
        }

        var isolateButton = document.getElementById('isolateButton');
        if (isolateButton) {
            isolateButton.addEventListener('click', function () {
                if (!currentAlert || !currentAlert.source_ip) {
                    closeModals();
                    return;
                }
                isolateButton.disabled = true;
                SecApi.block(currentAlert.source_ip, '大屏人工确认封禁：' + (currentAlert.category_text || ''))
                    .then(function (result) {
                        isolateButton.disabled = false;
                        closeModals();
                        showToast(result.message || '封禁指令已下发', !result.success);
                        SecApi.refreshAll();
                    }).catch(function (error) {
                        isolateButton.disabled = false;
                        showToast('封禁失败：' + error.message, true);
                    });
            });
        }

        Array.prototype.forEach.call(document.querySelectorAll('.modal .close'), function (button) {
            button.addEventListener('click', closeModals);
        });
        window.addEventListener('click', function (event) {
            if (event.target && event.target.classList && event.target.classList.contains('modal')) {
                closeModals();
            }
        });

        var soundButton = document.getElementById('btnSound');
        if (soundButton) {
            soundButton.addEventListener('click', function () {
                soundEnabled = !soundEnabled;
                soundButton.textContent = soundEnabled ? '告警音：开' : '告警音：关';
                soundButton.className = 'btn' + (soundEnabled ? ' active' : '');
            });
        }

        var scanButton = document.getElementById('btnScan');
        if (scanButton) {
            scanButton.addEventListener('click', function () {
                scanButton.disabled = true;
                scanButton.textContent = '扫描中…';
                SecApi.scan().then(function (result) {
                    // 后端默认异步执行：返回 job_id，这里轮询进度直到完成
                    if (result && result.job_id) {
                        showToast('扫描任务已提交（' + result.total + ' 个目标），正在后台执行…');
                        return pollScanJob(result.job_id, scanButton);
                    }
                    showToast('扫描完成：目标 ' + result.targets + ' 个，服务 ' + result.services_found
                        + ' 个，漏洞 ' + result.vulns_found + ' 个');
                    SecApi.refreshAll();
                    return null;
                }).catch(function (error) {
                    showToast('扫描失败：' + error.message, true);
                }).then(function () {
                    scanButton.disabled = false;
                    scanButton.textContent = '立即扫描';
                });
            });
        }

        var tabHeader = document.getElementById('tab_header');
        if (tabHeader) {
            var tabs = tabHeader.getElementsByTagName('li');
            var panels = document.getElementById('tab_content').getElementsByClassName('dom');
            Array.prototype.forEach.call(tabs, function (tab, index) {
                tab.addEventListener('click', function () {
                    Array.prototype.forEach.call(tabs, function (item, itemIndex) {
                        item.className = itemIndex === index ? 'selected' : '';
                        panels[itemIndex].style.display = itemIndex === index ? 'block' : 'none';
                    });
                    /* 标签页显示切换会改变容器尺寸，必须重算画布大小 */
                    resizeCharts();
                });
            });
        }

        bindChartAutoResize();
    }

    /* ---------------- 自适应字号 ----------------
     * rem 缩放策略（1rem = 屏宽 / 22），一套基准适配 1080P/2K/4K。
     * 必须在 echarts.init 之前调用：图表容器高度是 rem 单位，rem 基准变了容器才会变。 */
    function fitRem() {
        document.documentElement.style.fontSize = (window.innerWidth / 22) + 'px';
    }

    /* ---------------- 图表尺寸自适应 ----------------
     * 图表容器都用 rem 布局（1rem = 屏宽/22），rem 基准由 fitRem() 写入。
     * 若先 echarts.init() 再设置 rem 基准，ECharts 会把初始的错误像素尺寸固化进画布，
     * 现象就是"刷新后图形错位/挤在一起，缩放窗口或全屏后才恢复正常"。
     * 因此：① start() 里必须先 fitRem() 再 initCharts()；② 初始化后立即校正一次；
     *       ③ 用 ResizeObserver 直接监听容器尺寸变化（rem 变化、标签页切换都能覆盖）。 */
    function chartSizeOf(chart) {
        var dom = chart.getDom ? chart.getDom() : null;
        if (!dom) { return 'no-dom'; }
        return dom.clientWidth + 'x' + dom.clientHeight;
    }

    function resizeCharts() {
        Object.keys(charts).forEach(function (key) {
            var chart = charts[key];
            if (!chart || typeof chart.resize !== 'function') { return; }
            var signature = chartSizeOf(chart);
            /* 尺寸没变化就不重复 resize，避免 ResizeObserver 自触发死循环 */
            if (chart.__sizeSignature === signature) { return; }
            chart.__sizeSignature = signature;
            try {
                if (chart.isDisposed && chart.isDisposed()) { return; }
                chart.resize();
            } catch (error) {
                /* 容器已被移除时忽略 */
            }
        });
    }

    function bindChartAutoResize() {
        var pending = false;
        function schedule() {
            if (pending) { return; }
            pending = true;
            var run = function () { pending = false; resizeCharts(); };
            if (window.requestAnimationFrame) { window.requestAnimationFrame(run); }
            else { run(); }
        }

        if (window.ResizeObserver) {
            Object.keys(charts).forEach(function (key) {
                var chart = charts[key];
                var dom = chart && chart.getDom ? chart.getDom() : null;
                if (!dom) { return; }
                chart.__resizeObserver = new window.ResizeObserver(schedule);
                chart.__resizeObserver.observe(dom);
            });
        }
        window.addEventListener('resize', schedule);
        resizeCharts();
        schedule();
    }

    /* ---------------- 启动 ---------------- */
    function start() {
        /* rem 基准必须最先确定：图表容器高度依赖 rem，
           否则 echarts.init 会按错误的容器尺寸固化画布，刷新后图形就会错位。 */
        fitRem();
        window.addEventListener('resize', fitRem);

        initCharts();
        bindEvents();
        startClock();
        renderStatus({ capture_mode: 'unknown', dry_run: true, firewall_backend: '-', version: '-' });

        SecApi.on('status', renderStatus)
            .on('metrics', renderMetrics)
            .on('overview', function (payload) {
                setText('statAlerts', formatCount(payload.alerts_total || 0));
                setText('statBlocked', formatCount(payload.blocked_active || 0));
                setText('statAssets', formatCount(payload.assets_total || 0));
                setText('statVulns', formatCount(payload.vulns_open || 0));
                setText('statRisk', (payload.risk_score || 0).toFixed(1));
                renderStatus({
                    capture_mode: payload.capture_mode, dry_run: payload.dry_run,
                    firewall_backend: payload.firewall_backend, version: (SecApi.status || {}).version
                });
                var riskBar = document.getElementById('riskBar');
                if (riskBar) {
                    var score = Math.min(100, payload.risk_score || 0);
                    riskBar.style.width = score + '%';
                    riskBar.style.background = score > 70 ? '#ff3b4e' : (score > 40 ? '#febe12' : '#44eab1');
                }
            })
            .on('alertStats', renderAlertStats)
            .on('blocks', renderBlocks)
            .on('alerts', renderAlertFeed)
            .on('disposals', renderDisposals)
            .on('assets', renderAssets)
            .on('vulns', renderVulns)
            .on('alert', function (anomaly) {
                showAlertModal(anomaly);
                paintAlerts();
            })
            .on('connection', function (state) {
                if (state && state.metrics === false) {
                    setText('modeBadge', '实时连接中断，正在重连…');
                }
            });

        SecApi.start();
    }

    global.SecDashboard = {
        start: start,
        onAlert: showAlertModal,
        charts: charts,
        renderMetrics: renderMetrics
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})(window);






