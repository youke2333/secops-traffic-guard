/**
 * page-asset.js —— 模块 3.5 资产管理
 *
 * 数据来源：/assets（台账）、/assets/summary（统计）、/assets/{ip}（详情：指纹+告警+漏洞）
 * 处置能力：风险/关键字筛选、导出 CSV、单资产重新指纹识别（重扫）、查看关联告警与漏洞
 */
(function (global) {
    'use strict';

    var assets = [];
    var riskChart = null;
    var portChart = null;
    var riskItems = [];

    /* -------------------- 图表 -------------------- */
    function initCharts() {
        riskChart = echarts.init(document.getElementById('riskChart'));
        riskChart.setOption({
            color: ['#ff3b4e', '#ff7c44', '#febe12', '#44eab1'],
            tooltip: {
                trigger: 'item', backgroundColor: 'rgba(6,30,55,0.92)', textStyle: { color: '#fff' },
                formatter: function (item) { return item.name + '<br/>资产数：' + item.value + '（' + item.percent + '%）'; }
            },
            /* 窄面板下"环形图 + 外部标签 + 图例"会三层压盖：标签移到图例承载 */
            legend: {
                orient: 'horizontal', bottom: 2, left: 'center', itemWidth: 10, itemHeight: 10,
                itemGap: 10, textStyle: { color: '#cfe9ff', fontSize: 13 },
                formatter: function (name) {
                    for (var i = 0; i < riskItems.length; i += 1) {
                        if (riskItems[i].name === name) { return name + ' ' + riskItems[i].value; }
                    }
                    return name;
                }
            },
            series: [{
                type: 'pie', radius: ['42%', '66%'], center: ['50%', '42%'],
                avoidLabelOverlap: true,
                label: { show: false }, labelLine: { show: false },
                emphasis: { label: { show: true, fontSize: 13, color: '#fff', formatter: '{b}\n{d}%' } },
                data: []
            }]
        });

        portChart = echarts.init(document.getElementById('portChart'));
        portChart.setOption({
            tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
                       backgroundColor: 'rgba(6,30,55,0.92)', textStyle: { color: '#fff' },
                       formatter: function (params) {
                           var item = params[0];
                           return '端口 ' + item.name + '<br/>暴露资产数：' + item.value;
                       } },
            grid: { left: 6, right: 44, top: 8, bottom: 4, containLabel: true },
            xAxis: { type: 'value', axisLabel: { show: false }, splitLine: { show: false },
                     axisLine: { show: false }, minInterval: 1 },
            yAxis: { type: 'category', inverse: true, data: [],
                     axisLabel: { color: '#cfe9ff', fontSize: 13, width: 60, overflow: 'truncate' },
                     axisLine: { lineStyle: { color: '#2b6f9b' } } },
            series: [{
                type: 'bar', barWidth: 10, barCategoryGap: '42%',
                itemStyle: { color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
                    { offset: 0, color: '#00d8ff' }, { offset: 1, color: '#44eab1' }]) },
                label: { show: true, position: 'right', color: '#fff', fontSize: 12 },
                data: []
            }]
        });
    }

    function loadSummary() {
        return SecApi.get('/assets/summary').then(function (data) {
            var dist = data.risk_distribution || {};
            UI.setText('kAssets', UI.fmt.count(data.total));
            UI.setText('kCritical', UI.fmt.count(dist.critical || 0));
            UI.setText('kHigh', UI.fmt.count(dist.high || 0));
            UI.setText('kMedium', UI.fmt.count(dist.medium || 0));
            UI.setText('kLow', UI.fmt.count(dist.low || 0));
            UI.setText('kPorts', UI.fmt.count((data.top_ports || []).reduce(function (sum, row) {
                return sum + row.count;
            }, 0)));

            riskItems = [
                { name: '紧急', value: dist.critical || 0 },
                { name: '高危', value: dist.high || 0 },
                { name: '中危', value: dist.medium || 0 },
                { name: '低危', value: dist.low || 0 }
            ];
            riskChart.setOption({
                legend: { data: riskItems.map(function (item) { return item.name; }) },
                series: [{ data: riskItems }]
            });

            var top = (data.top_ports || []).slice(0, 8).reverse();
            portChart.setOption({
                yAxis: { data: top.map(function (row) { return '端口 ' + row.port; }) },
                series: [{ data: top.map(function (row) { return row.count; }) }]
            });
        });
    }

    /* -------------------- 台账表 -------------------- */
    function filterAssets() {
        var risk = document.getElementById('riskFilter').value;
        var keyword = document.getElementById('assetSearch').value.trim().toLowerCase();
        return assets.filter(function (item) {
            if (risk && item.risk_level !== risk) { return false; }
            if (keyword) {
                var hay = [item.ip, item.hostname, (item.tags || []).join(',')].join(' ').toLowerCase();
                if (hay.indexOf(keyword) === -1) { return false; }
            }
            return true;
        });
    }

    function render() {
        var body = document.getElementById('assetBody');
        var rows = filterAssets();
        if (!rows.length) {
            body.innerHTML = '<tr><td colspan="10" class="empty-row">'
                + '暂无资产管理数据（等待流量特征学习完成，或点击“重新扫描”主动探测）</td></tr>';
            return;
        }
        body.innerHTML = rows.map(function (item) {
            var color = UI.sevColor(item.risk_level) || '#7fa9c8';
            var ports = (item.open_ports || []).slice(0, 6).join(', ');
            return '<tr>'
                + '<td class="mono">' + UI.esc(item.ip) + '</td>'
                + '<td>' + UI.esc(item.hostname || '-') + '</td>'
                + '<td>' + UI.esc((item.os_guess || '未知').slice(0, 18)) + '</td>'
                + '<td>' + UI.badge(UI.riskText(item.risk_level), color) + '</td>'
                + '<td class="mono" title="' + UI.esc((item.open_ports || []).join(',')) + '">'
                + UI.esc(ports) + ((item.open_ports || []).length > 6 ? ' …' : '') + '</td>'
                + '<td>' + UI.esc((item.tags || []).join('/') || '-') + '</td>'
                + '<td class="num ' + (item.alert_count > 0 ? 'warn' : '') + '">' + (item.alert_count || 0) + '</td>'
                + '<td class="num ' + (item.vuln_count > 0 ? 'danger' : '') + '">' + (item.vuln_count || 0) + '</td>'
                + '<td>' + UI.fmt.time(item.last_seen) + '</td>'
                + '<td><div class="actions">'
                + '<button class="btn-mini" type="button" data-asset-detail="' + UI.esc(item.ip) + '">详情</button>'
                + '<button class="btn-mini" type="button" data-asset-rescan="' + UI.esc(item.ip) + '">重扫</button>'
                + '</div></td>'
                + '</tr>';
        }).join('');
    }

    function loadAssets() {
        return SecApi.get('/assets?limit=500').then(function (data) {
            assets = data || [];
            render();
        });
    }

    /* -------------------- 详情抽屉（指纹 + 关联告警/漏洞） -------------------- */

    /* 发现途径：让运维一眼看出这条结论是怎么来的——
       指纹/CVE 是版本匹配，配置体检是主动探测，流量研判是我们自己抓到攻击证据。 */
    var SOURCE_TEXT = {
        scan: '指纹/CVE',
        web: 'Web 配置体检',
        traffic_rule: '攻击流量·规则研判',
        traffic_ai: '攻击流量·AI 复核'
    };

    function vulnItemHtml(item) {
        var meta = [];
        if (item.cve) { meta.push(item.cve); }
        if (SOURCE_TEXT[item.source]) { meta.push(SOURCE_TEXT[item.source]); }
        if (item.confidence === 'confirmed') { meta.push('已确认'); }
        else if (item.confidence === 'suspected') { meta.push('疑似'); }
        if (item.cvss) { meta.push('CVSS ' + item.cvss); }
        meta.push(UI.fmt.time(item.found_at).slice(5, 16));
        return '<li><span class="a">' + UI.esc(item.title || item.cve || '未命名漏洞') + '</span>'
            + UI.pill(UI.sevText(item.severity), UI.sevColor(item.severity))
            + '<span class="d">' + UI.esc(meta.join(' · ')) + '</span></li>';
    }

    /* 把漏洞挂到服务上：回答"这台机器的哪个服务存在什么问题"，而不是甩一串漏洞条目。
       没有漏洞的服务也列出来并标"未发现"，方便判断是全清了还是没扫到。 */
    function renderServiceVulns(groups, fallback) {
        if (!groups.length) {
            if (!fallback.length) {
                return '<div class="empty-row" style="padding:0.12rem 0">'
                    + '暂无服务与漏洞信息（可点击下方按钮主动探测或按攻击流量研判）</div>';
            }
            groups = [{ port: 0, service: '-', label: '未关联到具体服务', severity: '',
                confirmed: 0, suspected: 0, vulns: fallback }];
        }
        return groups.map(function (group) {
            var count = group.vulns.length;
            var tag = count
                ? '<span class="svc-count ' + UI.esc(group.severity || '') + '">' + count
                    + ' 个漏洞' + (group.confirmed ? '（已确认 ' + group.confirmed + '）' : '')
                    + '</span>'
                : '<span class="svc-count none">未发现漏洞</span>';
            var body = count
                ? '<ul class="timeline">' + group.vulns.map(vulnItemHtml).join('') + '</ul>'
                : '';
            return '<div class="svc-block">'
                + '<div class="svc-head"><span class="svc-name">'
                + UI.esc(group.label || (group.port + '/tcp · ' + (group.service || '-')))
                + '</span>' + tag + '</div>' + body + '</div>';
        }).join('');
    }
    function openDetail(ip) {
        SecApi.get('/assets/' + encodeURIComponent(ip)).then(function (asset) {
            var services = asset.services || [];
            var serviceRows = services.length ? services.map(function (service) {
                return '<tr>'
                    + '<td class="mono">' + (service.port || '-') + '</td>'
                    + '<td>' + UI.esc(service.name || '-') + '</td>'
                    + '<td>' + UI.esc(service.product || '-') + '</td>'
                    + '<td>' + UI.esc(service.version || '-') + '</td>'
                    + '<td title="' + UI.esc(service.banner || '') + '">'
                    + UI.esc((service.banner || '-').slice(0, 40)) + '</td>'
                    + '</tr>';
            }).join('') : '<tr><td colspan="5" class="empty-row">'
                + '暂无指纹信息（可点击“重新扫描”主动探测）</td></tr>';

            var alerts = asset.alerts || [];
            var alertRows = alerts.length ? alerts.map(function (item) {
                return '<li><span class="t">' + UI.fmt.time(item.ts).slice(5)
                    + '</span><span class="a">' + UI.esc(UI.catText(item.category)) + '</span>'
                    + '<span class="d">' + UI.esc(item.message) + '</span></li>';
            }).join('') : '<li>暂无关联告警</li>';

            var vulns = asset.vulnerabilities || [];
            var vulnGroups = renderServiceVulns(asset.service_vulns || [], vulns);

            UI.drawer.open('资产详情 ' + UI.esc(asset.ip),
                '<dl>'
                + '<dt>主机名</dt><dd>' + UI.esc(asset.hostname || '-') + '</dd>'
                + '<dt>OS 推断</dt><dd>' + UI.esc(asset.os_guess || '未知') + '</dd>'
                + '<dt>风险等级</dt><dd>' + UI.badge(UI.riskText(asset.risk_level),
                    UI.sevColor(asset.risk_level) || '#7fa9c8') + '</dd>'
                + '<dt>业务标签</dt><dd>' + UI.esc((asset.tags || []).join(' / ') || '-') + '</dd>'
                + '<dt>开放端口</dt><dd>' + UI.esc((asset.open_ports || []).join(', ') || '-') + '</dd>'
                + '<dt>累计流量</dt><dd>入 ' + UI.fmt.bytes(asset.bytes_in) + ' ／ 出 '
                + UI.fmt.bytes(asset.bytes_out) + '</dd>'
                + '<dt>关联告警</dt><dd>' + (asset.alert_count || 0) + ' 条</dd>'
                + '<dt>关联漏洞</dt><dd>' + (asset.vuln_count || 0) + ' 个</dd>'
                + '<dt>首次发现</dt><dd>' + UI.fmt.time(asset.first_seen) + '</dd>'
                + '<dt>最近活跃</dt><dd>' + UI.fmt.time(asset.last_seen) + '</dd>'
                + '</dl>'
                + '<h4>服务指纹</h4>'
                + '<div class="table-wrap"><table class="grid-table"><thead><tr>'
                + '<th>端口</th><th>服务</th><th>产品</th><th>版本</th><th>Banner</th>'
                + '</tr></thead><tbody>' + serviceRows + '</tbody></table></div>'
                + '<h4>服务与漏洞</h4>' + vulnGroups
                + '<h4>历史告警</h4><ul class="timeline">' + alertRows + '</ul>'
                + '<div class="toolbar" style="margin-top:0.16rem">'
                + '<button class="btn" type="button" data-asset-rescan="' + UI.esc(asset.ip)
                + '">重新扫描该资产</button>'
                + '<button class="btn" type="button" data-asset-infer="' + UI.esc(asset.ip)
                + '">按攻击流量研判漏洞</button>'
                + '</div>');
        }).catch(function (error) { UI.toast('读取资产详情失败：' + error.message, true); });
    }

    /* -------------------- 交互 -------------------- */
    function bind() {
        document.getElementById('riskFilter').addEventListener('change', render);
        document.getElementById('assetSearch').addEventListener('input', render);

        document.getElementById('btnExportAssets').addEventListener('click', function () {
            var rows = filterAssets();
            if (!rows.length) {
                UI.toast('暂无可导出的资产', true);
                return;
            }
            var csv = [['IP', '主机名', 'OS 推断', '风险等级', '开放端口', '业务标签',
                '告警数', '漏洞数', '首次发现', '最近活跃']];
            rows.forEach(function (item) {
                csv.push([item.ip, item.hostname, item.os_guess, UI.riskText(item.risk_level),
                    (item.open_ports || []).join(' '), (item.tags || []).join('/'),
                    item.alert_count, item.vuln_count, item.first_seen, item.last_seen]);
            });
            UI.csv('assets-' + Date.now() + '.csv', csv);
        });

        UI.delegate(document, '[data-asset-detail]', 'click', function (event, target) {
            openDetail(target.getAttribute('data-asset-detail'));
        });

        UI.delegate(document, '[data-asset-rescan]', 'click', function (event, target) {
            var ip = target.getAttribute('data-asset-rescan');
            target.disabled = true;
            SecApi.rescanAsset(ip, true).then(function (result) {
                UI.toast('重扫完成：开放端口 ' + (result.open_ports || []).length
                    + ' 个，命中漏洞 ' + (result.vulns_found || 0) + ' 个');
                loadAssets();
                loadSummary();
                if (document.getElementById('drawer').classList.contains('open')) {
                    openDetail(ip);
                }
            }).catch(function (error) {
                UI.toast('重扫失败：' + error.message, true);
            }).then(function () { target.disabled = false; });
        });

        UI.delegate(document, '[data-asset-infer]', 'click', function (event, target) {
            var ip = target.getAttribute('data-asset-infer');
            var label = target.textContent;
            target.disabled = true;
            target.textContent = '研判中…';
            SecApi.inferAssetVulns(ip, true).then(function (result) {
                var confirmed = result.confirmed || 0;
                var suspected = result.suspected || 0;
                if (!result.vulns_found) {
                    UI.toast('未从攻击流量中发现可判定的漏洞：该资产可能还没被打过，'
                        + '或采集等级未保留响应体', true);
                } else {
                    UI.toast('研判完成：确认 ' + confirmed + ' 个、疑似 ' + suspected + ' 个');
                }
                loadAssets();
                loadSummary();
                if (document.getElementById('drawer').classList.contains('open')) {
                    openDetail(ip);
                }
            }).catch(function (error) {
                UI.toast('研判失败：' + error.message, true);
                target.disabled = false;
                target.textContent = label;
            });
        });

        /* 图表尺寸自适应：窗口 resize / 容器尺寸变化（含 rem 基准变化）统一自动 resize */
        UI.autoResize([riskChart, portChart]);
    }

    function start() {
        /* 先定 rem 基准再初始化图表，避免画布尺寸被固化成错误值（刷新后错位） */
        UI.fitRem();
        initCharts();
        bind();
        UI.boot('asset');
        loadAssets();
        loadSummary();
        setInterval(function () { loadAssets(); loadSummary(); }, 15000);
    }

    global.SecAssetPage = { start: start };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})(window);


