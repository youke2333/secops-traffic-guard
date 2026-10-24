/**
 * page-traffic.js —— 模块 3.1 实时动态流量监控
 *
 * 数据来源：SSE /stream/metrics（实时帧） + REST /metrics/trend（首屏/切换窗口历史）
 *            + /metrics/sessions（会话明细，5s 轮询）
 * 处置能力：暂停画面、时间窗切换、导出会话 CSV、对可疑会话一键封禁源 IP
 */
(function (global) {
    'use strict';

    var trendChart = null;
    var portChart = null;
    var windowSec = 60;
    var paused = false;
    var sessions = [];
    var buffer = { bpsIn: [], bpsOut: [], pps: [] };
    var MAX_POINTS = 300;

    /** 坐标轴紧凑格式，避免长标签把绘图区压扁 */
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

    /* -------------------- 趋势图 -------------------- */
    function initTrend() {
        trendChart = echarts.init(document.getElementById('trendChart'));
        trendChart.setOption({
            tooltip: {
                trigger: 'axis', backgroundColor: 'rgba(6,30,55,0.92)', borderColor: '#00d8ff',
                textStyle: { color: '#fff' }
            },
            legend: { data: ['入站带宽', '出站带宽', '包速率'], textStyle: { color: '#9fd8ff', fontSize: 13 },
                      top: 2, itemWidth: 14, itemHeight: 9, itemGap: 14 },
            grid: { left: 10, right: 16, top: 36, bottom: 8, containLabel: true },
            xAxis: { type: 'time', axisLabel: { color: '#9fd8ff', fontSize: 13, hideOverlap: true },
                     axisLine: { lineStyle: { color: '#2b6f9b' } } },
            yAxis: [
                { type: 'value', name: '带宽', nameTextStyle: { color: '#9fd8ff', fontSize: 13 },
                  nameGap: 12,
                  axisLabel: { color: '#9fd8ff', fontSize: 13,
                               formatter: function (value) { return shortBps(value); } },
                  splitLine: { lineStyle: { color: 'rgba(43,111,155,0.3)' } } },
                { type: 'value', name: '包速率', nameTextStyle: { color: '#febe12', fontSize: 13 },
                  nameGap: 12,
                  axisLabel: { color: '#febe12', fontSize: 13,
                               formatter: function (value) { return shortCount(value); } },
                  splitLine: { show: false } }
            ],
            series: [
                { name: '入站带宽', type: 'line', smooth: true, showSymbol: false, yAxisIndex: 0,
                  lineStyle: { color: '#00ffff', width: 2 },
                  areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                      { offset: 0, color: 'rgba(0,255,255,0.42)' },
                      { offset: 1, color: 'rgba(0,255,255,0.02)' }]) }, data: [] },
                { name: '出站带宽', type: 'line', smooth: true, showSymbol: false, yAxisIndex: 0,
                  lineStyle: { color: '#7bdd43', width: 2 },
                  areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                      { offset: 0, color: 'rgba(123,221,67,0.32)' },
                      { offset: 1, color: 'rgba(123,221,67,0.02)' }]) }, data: [] },
                { name: '包速率', type: 'line', smooth: true, showSymbol: false, yAxisIndex: 1,
                  lineStyle: { color: '#febe12', type: 'dashed', width: 1.5 }, data: [] }
            ]
        });
    }

    function initPorts() {
        portChart = echarts.init(document.getElementById('portChart'));
        portChart.setOption({
            tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
                       backgroundColor: 'rgba(6,30,55,0.92)', textStyle: { color: '#fff' } },
            grid: { left: 6, right: 66, top: 8, bottom: 4, containLabel: true },
            xAxis: { type: 'value', axisLabel: { show: false }, splitLine: { show: false },
                     axisLine: { show: false } },
            yAxis: { type: 'category', inverse: true, data: [],
                     axisLabel: { color: '#cfe9ff', fontSize: 13, width: 62, overflow: 'truncate' },
                     axisLine: { lineStyle: { color: '#2b6f9b' } } },
            series: [{
                type: 'bar', barWidth: 9, barCategoryGap: '40%', data: [],
                label: { show: true, position: 'right', color: '#fff', fontSize: 12,
                         formatter: function (item) { return shortBps(item.value); } }
            }]
        });
    }

    /* -------------------- 端口 TOP 图 -------------------- */
    function renderPorts(ports) {
        if (!portChart || !ports || !ports.length) { return; }
        var rows = ports.slice(0, 8).reverse();
        portChart.setOption({
            yAxis: { data: rows.map(function (row) { return row.port + '/' + row.protocol; }) },
            series: [{
                data: rows.map(function (row) {
                    return { value: row.bps, itemStyle: { color: row.is_standard ? '#00bcd4' : '#ff3b4e' } };
                })
            }]
        });
    }

    /* -------------------- 实时帧处理 -------------------- */
    function onMetrics(frame) {
        if (!frame || !frame.ts) { return; }
        var pps = (frame.pps_in || 0) + (frame.pps_out || 0);
        /* 带宽利用率：优先取后端 kpi.bandwidth_util，缺失时按 总bps/链路带宽 估算
           （口径与后端 service.kpi() 及大屏 renderMetrics 保持一致） */
        var totalBps = (frame.bps_in || 0) + (frame.bps_out || 0);
        var capacityMbps = Number(frame.link_speed_mbps) || 1000;
        var util = (frame.kpi && frame.kpi.bandwidth_util !== undefined)
            ? frame.kpi.bandwidth_util
            : Math.min(100, totalBps / (capacityMbps * 1e6) * 100);

        UI.setText('kUtil', Number(util || 0).toFixed(2) + ' %');
        UI.setText('kIn', UI.fmt.bps(frame.bps_in));
        UI.setText('kOut', UI.fmt.bps(frame.bps_out));
        UI.setText('kPps', UI.fmt.pps(pps));
        UI.setText('kConns', UI.fmt.count(frame.conns));
        UI.setText('kSrc', UI.fmt.count(frame.unique_src));
        UI.setText('sourceHint', (frame.mode === 'demo' ? '仿真流量（演示）' : '真实网卡采集')
            + ' · ' + (frame.iface || '-'));

        renderPorts(frame.ports);
        if (paused) { return; }

        var ts = frame.ts * 1000;
        buffer.bpsIn.push([ts, frame.bps_in || 0]);
        buffer.bpsOut.push([ts, frame.bps_out || 0]);
        buffer.pps.push([ts, pps]);
        ['bpsIn', 'bpsOut', 'pps'].forEach(function (key) {
            while (buffer[key].length > MAX_POINTS) { buffer[key].shift(); }
        });
        trendChart.setOption({
            series: [{ data: buffer.bpsIn }, { data: buffer.bpsOut }, { data: buffer.pps }]
        }, { lazyUpdate: true });
    }

    /* -------------------- 历史趋势（切换时间窗） -------------------- */
    function loadTrend() {
        return SecApi.get('/metrics/trend?window_sec=' + windowSec).then(function (data) {
            buffer.bpsIn = (data.bps_in || []).map(function (item) { return [item[0] * 1000, item[1]]; });
            buffer.bpsOut = (data.bps_out || []).map(function (item) { return [item[0] * 1000, item[1]]; });
            buffer.pps = (data.pps_in || []).map(function (item, index) {
                var outPoint = (data.pps_out || [])[index] || [item[0], 0];
                return [item[0] * 1000, item[1] + outPoint[1]];
            });
            trendChart.setOption({
                series: [{ data: buffer.bpsIn }, { data: buffer.bpsOut }, { data: buffer.pps }]
            });
            UI.setText('refreshHint', paused ? '已暂停' : 'SSE 实时');
        });
    }

    /* -------------------- 会话明细（含一键封禁） -------------------- */
    function loadSessions() {
        return SecApi.sessions(20).then(function (data) {
            sessions = data.items || [];
            var body = document.getElementById('sessionBody');
            if (!sessions.length) {
                body.innerHTML = '<tr><td colspan="7" class="empty-row">当前没有活跃会话</td></tr>';
                return;
            }
            body.innerHTML = sessions.map(function (item) {
                var suspicious = !item.is_internal;
                return '<tr' + (suspicious ? ' class="row-alert"' : '') + '>'
                    + '<td class="mono">' + UI.esc(item.src_ip) + ':' + item.src_port + '</td>'
                    + '<td class="mono">' + UI.esc(item.dst_ip) + ':' + item.dst_port + '</td>'
                    + '<td>' + UI.esc(item.protocol) + '</td>'
                    + '<td class="num">' + UI.fmt.duration(item.duration_sec) + '</td>'
                    + '<td class="num">' + UI.fmt.bytes(item.bytes) + '</td>'
                    + '<td class="num">' + UI.fmt.bps(item.bps) + '</td>'
                    + '<td><button class="btn-mini" type="button" data-block-ip="'
                    + UI.esc(item.src_ip) + '">封禁源</button></td>'
                    + '</tr>';
            }).join('');
        });
    }

    /* -------------------- 交互绑定 -------------------- */
    function bind() {
        document.getElementById('windowGroup').addEventListener('click', function (event) {
            var button = event.target.closest ? event.target.closest('[data-window]') : null;
            if (!button) { return; }
            windowSec = Number(button.getAttribute('data-window'));
            Array.prototype.forEach.call(document.querySelectorAll('#windowGroup .btn'), function (item) {
                item.className = item === button ? 'btn active' : 'btn';
            });
            loadTrend();
            UI.toast('已切换时间窗口：最近 ' + (windowSec / 60) + ' 分钟');
        });

        document.getElementById('btnPause').addEventListener('click', function (event) {
            paused = !paused;
            event.target.textContent = paused ? '继续刷新' : '暂停画面';
            event.target.className = 'btn' + (paused ? ' active' : '');
            UI.setText('refreshHint', paused ? '已暂停' : 'SSE 实时');
            UI.toast(paused ? '画面已暂停（后台采集与检测不受影响）' : '已恢复实时刷新');
        });

        document.getElementById('btnStream').addEventListener('click', function () {
            UI.toast('实时帧来自 SSE /stream/metrics，每 '
                + ((SecApi.status && SecApi.status.interval_ms) || 500) + 'ms 一帧');
        });

        document.getElementById('btnExportSessions').addEventListener('click', function () {
            if (!sessions.length) {
                UI.toast('暂无可导出的会话', true);
                return;
            }
            var rows = [['源IP', '源端口', '目的IP', '目的端口', '协议', '时长(秒)', '数据包', '字节', 'bps', '是否内网']];
            sessions.forEach(function (item) {
                rows.push([item.src_ip, item.src_port, item.dst_ip, item.dst_port, item.protocol,
                    item.duration_sec, item.packets, item.bytes, item.bps, item.is_internal ? '是' : '否']);
            });
            UI.csv('sessions-' + Date.now() + '.csv', rows);
        });

        UI.delegate(document, '[data-block-ip]', 'click', function (event, target) {
            var ip = target.getAttribute('data-block-ip');
            UI.confirm('确认封禁 ' + ip + ' ？\n（默认 30 分钟后自动解封，可在「封禁与告警」页手动解封）', function () {
                SecApi.block(ip, '流量监控页人工封禁：可疑会话').then(function (result) {
                    UI.toast(result.message, !result.success);
                    loadSessions();
                }).catch(function (error) { UI.toast('封禁失败：' + error.message, true); });
            });
        });

        /* 图表尺寸自适应：窗口 resize / 容器尺寸变化（含 rem 基准变化）统一自动 resize */
        UI.autoResize([trendChart, portChart]);
    }

    /* -------------------- 启动 -------------------- */
    function start() {
        /* 必须先确定 rem 基准（1rem = 屏宽/22），否则图表容器会在 echarts.init 之后才变形，
           画布尺寸被固化，表现为"刷新后图形错位，缩放窗口才恢复" */
        UI.fitRem();
        initTrend();
        initPorts();
        bind();
        UI.boot('traffic');
        SecApi.on('metrics', onMetrics);
        SecApi.on('status', function () { loadTrend(); });
        loadTrend();
        loadSessions();
        setInterval(loadSessions, 5000);
    }

    global.SecTrafficPage = { start: start, onMetrics: onMetrics };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})(window);


