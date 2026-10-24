/**
 * page-anomaly.js —— 模块 3.2 异常端口流量检测
 *
 * 数据来源：/metrics/ports/baseline（端口基线明细）、/alerts（异常事件）、/alerts/stats（统计）
 * 处置能力：双向筛选、导出 CSV、封禁源 IP、把误报来源加入白名单、确认/关闭告警
 */
(function (global) {
    'use strict';

    var typeChart = null;
    var portRows = [];
    var eventRows = [];
    var typeItems = [];
    var filter = 'all';
    var keyword = '';

    /* -------------------- 图表 -------------------- */
    function initChart() {
        typeChart = echarts.init(document.getElementById('typeChart'));
        typeChart.setOption({
            color: ['#fa3e5f', '#ff9f43', '#febe12', '#00ffff', '#7bdd43', '#9b7bff'],
            tooltip: {
                trigger: 'item', backgroundColor: 'rgba(6,30,55,0.92)', textStyle: { color: '#fff' },
                formatter: function (item) { return item.name + '<br/>数量：' + item.value + '（' + item.percent + '%）'; }
            },
            /* 竖排图例 + 引导线标签在窄面板中会互相压盖：
               改为底部横排图例（承载名称与数量） + 饼图内部不再画标签 */
            legend: {
                orient: 'horizontal', bottom: 2, left: 'center', itemWidth: 10, itemHeight: 10,
                itemGap: 10, textStyle: { color: '#cfe9ff', fontSize: 13 },
                formatter: function (name) {
                    for (var i = 0; i < typeItems.length; i += 1) {
                        if (typeItems[i].name === name) { return name + ' ' + typeItems[i].value; }
                    }
                    return name;
                }
            },
            series: [{
                type: 'pie', radius: ['40%', '64%'], center: ['50%', '44%'],
                avoidLabelOverlap: true, minShowLabelAngle: 12,
                label: { show: false }, labelLine: { show: false },
                emphasis: { label: { show: true, fontSize: 13, color: '#fff', formatter: '{b}\n{d}%' } },
                data: []
            }]
        });
    }

    /* -------------------- 端口基线明细 -------------------- */
    function renderPorts() {
        var body = document.getElementById('portBody');
        var rows = portRows.filter(function (row) {
            if (filter === 'anomaly' && !row.anomaly) { return false; }
            if (filter === 'nonstd' && row.is_standard) { return false; }
            if (keyword && String(row.port).indexOf(keyword) !== 0) { return false; }
            return true;
        });

        if (!rows.length) {
            body.innerHTML = '<tr><td colspan="11" class="empty-row">没有符合条件的端口</td></tr>';
            return;
        }
        body.innerHTML = rows.map(function (row) {
            var typeColor = row.is_standard ? '#44eab1' : '#ff7c44';
            var zClass = row.zscore >= 4 ? 'danger' : (row.zscore >= 2.5 ? 'warn' : '');
            return '<tr' + (row.anomaly ? ' class="row-alert"' : '') + '>'
                + '<td class="mono">' + row.port + '</td>'
                + '<td>' + UI.esc(row.protocol) + '</td>'
                + '<td>' + UI.pill(row.is_standard ? '标准端口' : '非标准端口', typeColor) + '</td>'
                + '<td class="num">' + UI.fmt.pps(row.pps) + '</td>'
                + '<td class="num">' + UI.fmt.bps(row.bps) + '</td>'
                + '<td class="num">' + UI.fmt.count(row.conns) + '</td>'
                + '<td class="num">' + UI.fmt.pps(row.baseline_mean_pps) + '</td>'
                + '<td class="num">' + (row.deviation_ratio ? row.deviation_ratio + '×' : '-') + '</td>'
                + '<td class="num ' + zClass + '">' + (row.zscore === undefined ? '-' : row.zscore) + '</td>'
                + '<td class="mono">' + UI.esc(row.top_source || '-') + '</td>'
                + '<td><div class="actions">'
                + (row.top_source
                    ? '<button class="btn-mini" type="button" data-block-ip="' + UI.esc(row.top_source)
                      + '" data-reason="端口 ' + row.port + ' 高频访问">封禁</button>'
                      + '<button class="btn-mini" type="button" data-whitelist-ip="' + UI.esc(row.top_source)
                      + '">加白名单</button>'
                    : '<span class="hint">-</span>')
                + '</div></td>'
                + '</tr>';
        }).join('');
    }

    function loadPorts() {
        return SecApi.portBaseline().then(function (data) {
            portRows = data.items || [];
            UI.setText('kAnomalyPorts', portRows.filter(function (row) { return row.anomaly; }).length);
            UI.setText('kNonStd', portRows.filter(function (row) { return !row.is_standard; }).length);
            UI.setText('kThreshold', 'Z ≥ ' + (data.threshold || '-'));
            UI.setText('kWindow', (data.window_sec || 10) + ' 秒滑窗');
            renderPorts();
        });
    }

    /* -------------------- 异常事件 -------------------- */
    function renderEvents() {
        var body = document.getElementById('eventBody');
        if (!eventRows.length) {
            body.innerHTML = '<tr><td colspan="10" class="empty-row">近 24 小时没有异常事件</td></tr>';
            return;
        }
        body.innerHTML = eventRows.slice(0, 60).map(function (item) {
            var color = UI.sevColor(item.severity);
            var status = item.status === 'blocked' ? UI.pill('已封禁', '#ff3c4e')
                : (item.status === 'closed' ? UI.pill('已确认', '#44eab1') : UI.pill('待处置', '#febe12'));
            /* 直达徽标：单条致命规则命中（绕过聚合投票），必须显著区别于聚合告警 */
            var direct = item.direct_alert
                ? UI.badge('直达', '#ff3c4e')
                : UI.badge('聚合', '#2b7ec1');
            return '<tr' + (item.severity === 'critical' || item.severity === 'high' ? ' class="row-alert"' : '') + '>'
                + '<td>' + UI.fmt.clockTime(item.ts) + '</td>'
                + '<td>' + UI.esc(item.category_text || UI.catText(item.category)) + '</td>'
                + '<td>' + UI.badge(item.severity_text || UI.sevText(item.severity), color) + '</td>'
                + '<td class="mono">' + UI.esc(item.source_ip || '-') + '</td>'
                + '<td class="num">' + (item.dest_port || '-') + '</td>'
                + '<td class="num">' + (item.score === undefined ? '-' : item.score) + '</td>'
                + '<td class="num">' + (item.risk_score === undefined ? '-' : item.risk_score) + '</td>'
                + '<td>' + direct + '</td>'
                + '<td>' + status + '</td>'
                + '<td><div class="actions">'
                + '<button class="btn-mini" type="button" data-alert-detail="' + item.id + '">详情</button>'
                + (item.source_ip
                    ? '<button class="btn-mini" type="button" data-alert-block="' + item.id + '">封禁</button>'
                    : '')
                + '<button class="btn-mini" type="button" data-alert-ack="' + item.id + '">确认</button>'
                + '</div></td>'
                + '</tr>';
        }).join('');
    }

    function loadEvents() {
        return SecApi.get('/alerts?limit=200').then(function (data) {
            eventRows = data || [];
            renderEvents();
        });
    }

    function loadStats() {
        return SecApi.get('/alerts/stats?hours=24').then(function (data) {
            UI.setText('kAlerts', UI.fmt.count(data.total));
            UI.setText('kBlocked', UI.fmt.count(data.blocked));
            /* Web 攻击类告警（类别以 web_ 开头，来自 Web 攻击知识库）单独计数 */
            var webAlerts = (data.by_category || []).filter(function (row) {
                return String(row.category || '').indexOf('web_') === 0;
            }).reduce(function (sum, row) { return sum + (row.count || 0); }, 0);
            UI.setText('kWebAlerts', UI.fmt.count(webAlerts));
            /* v2：直达告警数与"聚合抑制"信号数（抑制必须可见，禁止静默丢弃） */
            UI.setText('kDirectAlerts', UI.fmt.count(data.direct));
            UI.setText('kSuppressed', UI.fmt.count((data.signals || {}).suppressed));
            var items = (data.by_category || []).map(function (row) {
                return { name: row.category_text || row.category, value: row.count };
            }).sort(function (a, b) { return b.value - a.value; });
            if (!items.length) { items = [{ name: '暂无告警', value: 1 }]; }
            typeItems = items;              // 供底部图例展示"名称 + 数量"
            typeChart.setOption({
                legend: { data: items.map(function (item) { return item.name; }) },
                series: [{ data: items }]
            });
        });
    }

    /* -------------------- 阈值 / 信号 / 规则来源（v2） -------------------- */
    function loadScoring() {
        return SecApi.scoringConfig().then(function (data) {
            UI.setText('kScoreThreshold', '≥ ' + (data.threshold || 6));
            UI.setText('scoringHint', '评分机制：权重 = 严重度 × 置信度（critical 5.0 / high 3.0 / '
                + 'medium 1.5 / low 0.5；置信度系数 high 1.2 / medium 1.0 / low 0.8）。单条权重 ≥ '
                + (data.direct_alert_weight || 6) + '（critical + 高置信度）立即直达告警；'
                + '否则在 ' + (data.window_sec || 300) + 's 滑动窗口内累计，风险分 ≥ '
                + (data.threshold || 6) + ' 才告警（多类别 ×'
                + ((data.bonus || {}).multi_category_2 || 1.2) + ' / ×'
                + ((data.bonus || {}).multi_category_3 || 1.5) + '，含 critical ×'
                + ((data.bonus || {}).critical || 1.3) + '）。被抑制的信号同样落库，可在下方表格查看。');
        }).catch(function () { /* 演示模式或接口不可用时保留默认文案 */ });
    }

    function signalStatusCell(row) {
        if (!row.suppressed) { return UI.pill('已告警', '#44eab1'); }
        var text = row.suppressed_reason === 'cooldown' ? '冷却期抑制' : '未达阈值';
        return UI.pill(text, '#febe12');
    }

    function renderSignals(rows) {
        var body = document.getElementById('signalBody');
        if (!rows || !rows.length) {
            body.innerHTML = '<tr><td colspan="8" class="empty-row">窗口内暂无信号</td></tr>';
            return;
        }
        body.innerHTML = rows.slice(0, 60).map(function (row) {
            return '<tr>'
                + '<td>' + UI.fmt.time(row.ts) + '</td>'
                + '<td class="mono">' + UI.esc(row.source_ip || '-') + '</td>'
                + '<td class="mono">' + UI.esc(row.rule_id || '-') + '</td>'
                + '<td>' + UI.esc(UI.catText(row.category)) + '</td>'
                + '<td>' + UI.badge(UI.sevText(row.severity), UI.sevColor(row.severity)) + '</td>'
                + '<td class="num">' + (row.weight === undefined ? '-' : row.weight) + '</td>'
                + '<td>' + (row.direct_alert ? UI.badge('直达', '#ff3c4e')
                    : UI.pill('聚合', '#2b7ec1')) + '</td>'
                + '<td>' + signalStatusCell(row) + '</td>'
                + '</tr>';
        }).join('');
    }

    function loadSignals(suppressedOnly) {
        return SecApi.signals({ suppressed_only: !!suppressedOnly, limit: 80 })
            .then(function (rows) {
                renderSignals(rows || []);
                UI.setText('kSuppressed', UI.fmt.count((rows || []).filter(function (row) {
                    return row.suppressed; }).length));
            }).catch(function (error) { UI.toast('读取信号失败：' + error.message, true); });
    }

    function openThresholds() {
        Promise.all([SecApi.thresholds(), SecApi.thresholdsStatic()]).then(function (results) {
            var data = results[0] || {};
            var overview = results[1] || data.overview || {};
            var rows = (data.items || []).map(function (row) {
                return '<tr>'
                    + '<td>' + UI.esc(row.detection_type) + '</td>'
                    + '<td>' + UI.esc(row.asset_class) + '</td>'
                    + '<td>' + UI.esc(row.time_bucket) + '</td>'
                    + '<td class="num">' + row.static_value + '</td>'
                    + '<td class="num"><b>' + row.threshold_value + '</b></td>'
                    + '<td class="num">' + row.sample_count + '</td>'
                    + '<td class="num">' + Math.round((row.false_positive_rate || 0) * 100) + '%</td>'
                    + '<td>' + (row.manual_override ? UI.pill('人工覆盖', '#febe12')
                        : UI.pill('自动', '#44eab1')) + '</td>'
                    + '<td>' + UI.esc(row.last_updated || '-') + '</td>'
                    + '</tr>';
            }).join('') || '<tr><td colspan="9" class="empty-row">尚未产生维度化阈值</td></tr>';
            var staticRows = Object.keys(overview.static_base || {}).map(function (key) {
                return '<dt>' + UI.esc(key) + '</dt><dd>' + overview.static_base[key] + '</dd>';
            }).join('');
            UI.drawer.open('阈值管理（自适应基线）',
                '<div class="box">' + UI.esc(overview.note || '') + '</div>'
                + '<div class="hint">调整边界：' + UI.esc(JSON.stringify(overview.bounds || {}))
                + '</div>'
                + '<div class="table-wrap"><table class="grid-table"><thead><tr>'
                + '<th>检测类型</th><th>资产口径</th><th>时段</th><th>静态基准</th><th>生效阈值</th>'
                + '<th>样本数</th><th>误报率</th><th>来源</th><th>最近更新</th>'
                + '</tr></thead><tbody>' + rows + '</tbody></table></div>'
                + '<h4>静态基准（配置值）</h4><dl>' + (staticRows || '<dt>-</dt><dd>无</dd>') + '</dl>');
        }).catch(function (error) { UI.toast('读取阈值失败：' + error.message, true); });
    }

    function openRuleSources() {
        SecApi.ruleSources().then(function (data) {
            var rows = (data.sources || []).map(function (row) {
                return '<tr>'
                    + '<td>' + UI.pill(row.source, row.enabled ? '#44eab1' : '#8fa7bf') + '</td>'
                    + '<td>' + UI.esc(row.label) + '</td>'
                    + '<td class="num">' + row.rules + '</td>'
                    + '<td class="num">' + row.web_rules + '</td>'
                    + '<td class="num">' + row.direct_alert + '</td>'
                    + '</tr>';
            }).join('');
            var categories = (data.direct_alert_categories || []).join('、') || '-';
            UI.drawer.open('规则来源（内置知识库 + 开源规则库）',
                '<div class="hint">直达规则共 ' + (data.direct_alert_total || 0)
                + ' 条，覆盖攻击大类：' + UI.esc(categories) + '</div>'
                + '<div class="table-wrap"><table class="grid-table"><thead><tr>'
                + '<th>来源</th><th>说明</th><th>规则数</th><th>HTTP 侧</th><th>直达</th>'
                + '</tr></thead><tbody>' + rows + '</tbody></table></div>'
                + '<h4>Web 知识库</h4><dl>'
                + '<dt>规则总数</dt><dd>' + ((data.web_kb || {}).rules || '-') + '</dd>'
                + '<dt>含外部规则</dt><dd>' + ((data.web_kb || {}).external_rules || 0) + '</dd>'
                + '<dt>直达规则</dt><dd>' + ((data.web_kb || {}).direct_alert_rules || 0) + '</dd>'
                + '</dl>');
        }).catch(function (error) { UI.toast('读取规则来源失败：' + error.message, true); });
    }

    /* -------------------- 详情抽屉 -------------------- */
    /* AI 研判来源标签：降级必须可见（绿=模型可用，黄=本地规则，灰=模板，红=待人工） */
    function analysisSourceLabel(analysis) {
        var source = (analysis || {}).source || 'pending';
        var table = {
            deepseek_v4_flash: ['DeepSeek V4-Flash', '#44eab1'],
            local_rules: ['本地规则判定', '#febe12'],
            template: ['静态模板', '#8fa7bf'],
            pending: ['待人工研判', '#ff3c4e']
        };
        var item = table[source] || [source, '#8fa7bf'];
        return { source: source, text: item[0], color: item[1] };
    }

    function analysisHtml(item) {
        var analysis = item.llm_analysis;
        if (!analysis) {
            return '<h4>AI 研判</h4><div class="box">研判中或尚未研判（可点击下方「重新研判」）。'
                + '队列繁忙或 API 不可用时会降级到本地规则 / 模板，来源会明确标注。</div>';
        }
        var info = analysisSourceLabel(analysis);
        var verdictText = { confirm: '确认攻击', suspect: '疑似', dismiss: '误报', unknown: '无法判断' }[analysis.verdict]
            || analysis.verdict;
        var suggestionText = { block: '建议封禁', watch: '继续观察', ignore: '可忽略' }[analysis.suggestion]
            || analysis.suggestion;
        var refs = (analysis.evidence_refs || []).map(function (ref) {
            return '<li>' + UI.esc(ref) + '</li>';
        }).join('');
        return '<h4>AI 研判</h4>'
            + '<div class="toolbar" style="margin:0 0 0.1rem">'
            + UI.pill('来源：' + info.text, info.color)
            + UI.pill('结论：' + verdictText, analysis.verdict === 'confirm' ? '#ff3c4e' : '#febe12')
            + UI.pill('置信度：' + Math.round((analysis.confidence || 0) * 100) + '%', '#2b7ec1')
            + UI.pill(suggestionText, analysis.suggestion === 'block' ? '#ff3c4e' : '#44eab1')
            + '</div>'
            + (analysis.degraded
                ? '<div class="box">当前 AI API 不可用或未配置，已降级到'
                    + UI.esc(info.text) + '，结论置信度有限，请结合证据人工确认。</div>'
                : '')
            + '<div>' + UI.esc(analysis.reason || '') + '</div>'
            + (refs ? '<h4>研判依据</h4><ul>' + refs + '</ul>' : '');
    }

    function windowSignalsHtml(item) {
        var rows = item.signals || [];
        if (!rows.length) { return '<div class="hint">该告警为窗口内首个信号（窗口长度为 1）。</div>'; }
        return '<div class="table-wrap"><table class="grid-table"><thead><tr>'
            + '<th>时间</th><th>规则</th><th>类型</th><th>级别</th><th>权重</th><th>直达</th>'
            + '</tr></thead><tbody>'
            + rows.map(function (row) {
                return '<tr>'
                    + '<td>' + UI.fmt.time(row.ts) + '</td>'
                    + '<td class="mono">' + UI.esc(row.rule_id || '-') + '</td>'
                    + '<td>' + UI.esc(UI.catText(row.category)) + '</td>'
                    + '<td>' + UI.badge(UI.sevText(row.severity), UI.sevColor(row.severity)) + '</td>'
                    + '<td class="num">' + row.weight + '</td>'
                    + '<td>' + (row.direct_alert ? UI.badge('直达', '#ff3c4e')
                        : UI.pill('聚合', '#2b7ec1')) + '</td>'
                    + '</tr>';
            }).join('')
            + '</tbody></table></div>';
    }

    function openDetail(id) {
        SecApi.alertDetail(id).then(function (item) {
            var evidence = item.evidence || {};
            var evidenceHtml = Object.keys(evidence).map(function (key) {
                return '<dt>' + UI.esc(key) + '</dt><dd>' + UI.hl(evidence[key]) + '</dd>';
            }).join('');
            UI.drawer.open('告警详情 #' + item.id,
                '<dl>'
                + '<dt>事件类型</dt><dd>' + UI.esc(item.category_text) + '</dd>'
                + '<dt>风险级别</dt><dd>' + UI.pill(item.severity_text, UI.sevColor(item.severity)) + '</dd>'
                + '<dt>检测算法</dt><dd>' + UI.esc(item.detector || '-') + '</dd>'
                + '<dt>发生时间</dt><dd>' + UI.fmt.time(item.ts) + '</dd>'
                + '<dt>源 IP</dt><dd>' + UI.esc(item.source_ip || '-') + '</dd>'
                + '<dt>目标</dt><dd>' + UI.esc((item.dest_ip || '-') + ':' + (item.dest_port || '-')) + '</dd>'
                + '<dt>评分</dt><dd>' + UI.esc(item.score) + '</dd>'
                + '<dt>风险分（聚合）</dt><dd>' + UI.esc(item.risk_score === undefined ? '-'
                    : item.risk_score) + ' '
                    + (item.direct_alert ? UI.badge('直达（单条致命规则）', '#ff3c4e')
                        : UI.pill('聚合（多信号累计）', '#2b7ec1')) + '</dd>'
                + '<dt>命中规则</dt><dd class="mono">'
                    + UI.esc((item.contributing_rules || []).join(', ') || '-') + '</dd>'
                + '<dt>信号窗口</dt><dd class="mono">' + UI.esc(item.signal_window_id || '-')
                    + '（' + ((item.aggregation || {}).signal_count || 1) + ' 条信号）</dd>'
                + '<dt>当前状态</dt><dd>' + UI.esc(item.status) + (item.blocked ? '（已封禁）' : '') + '</dd>'
                + '</dl>'
                + '<h4>事件描述</h4><div>' + UI.hl(item.message) + '</div>'
                + analysisHtml(item)
                + '<h4>窗口 signals（聚合明细）</h4>' + windowSignalsHtml(item)
                + '<h4>检测证据</h4><dl>' + (evidenceHtml || '<dt>-</dt><dd>无</dd>') + '</dl>'
                + '<h4>处置建议</h4><div class="box">' + UI.esc(item.suggestion || '建议人工核对后处置。') + '</div>'
                + '<div class="toolbar" style="margin-top:0.16rem">'
                + (item.source_ip ? '<button class="btn btn-danger" type="button" data-block-ip="'
                    + UI.esc(item.source_ip) + '">确认封禁该源 IP</button>' : '')
                + '<button class="btn" type="button" data-reanalyze="' + item.id + '">重新研判</button>'
                + '<button class="btn" type="button" data-alert-ack="' + item.id + '">确认关闭</button>'
                + '</div>');
        }).catch(function (error) { UI.toast('读取详情失败：' + error.message, true); });
    }

    /* -------------------- 交互 -------------------- */
    /* -------------------- AI 流量研判 -------------------- */
    function openAiReview() {
        UI.drawer.open('AI 流量研判（近 10 分钟）', '<div class="hint">正在请求模型，最长 3 秒…</div>');
        SecApi.trafficReview(10).then(function (result) {
            var labels = { normal: '正常', suspicious: '可疑', malicious: '恶意', unknown: '待定' };
            var color = result.verdict === 'malicious' ? '#ff3c4e'
                : (result.verdict === 'suspicious' ? '#febe12' : '#44eab1');
            var digest = result.window || {};
            var win = digest.window || {};
            var html = '<div class="toolbar">'
                + UI.badge(labels[result.verdict] || result.verdict, color)
                + UI.badge('置信度 ' + Math.round((result.confidence || 0) * 100) + '%', '#7fa9c8')
                + UI.badge('来源 ' + (result.source || '-') + (result.degraded ? '（已降级）' : ''),
                    result.degraded ? '#febe12' : '#44eab1')
                + '</div>'
                + '<div class="box">' + UI.esc(result.summary || '') + '</div>'
                + '<h4>发现</h4><ul>' + (result.findings || []).map(function (item) {
                    return '<li>' + UI.esc(item) + '</li>';
                }).join('') + '</ul>'
                + '<h4>处置建议</h4><ol>' + (result.recommendations || []).map(function (item) {
                    return '<li>' + UI.esc(item) + '</li>';
                }).join('') + '</ol>'
                + '<h4>窗口摘要（仅聚合数据，不含原始载荷）</h4>'
                + '<div class="hint">bps_in=' + UI.esc(win.bps_in || 0)
                + ' ｜ pps_in=' + UI.esc(win.pps_in || 0)
                + ' ｜ conns=' + UI.esc(win.conns || 0)
                + ' ｜ 告警 ' + UI.esc((digest.alerts || {}).total || 0)
                + ' 条（直达 ' + UI.esc((digest.alerts || {}).direct_count || 0)
                + '）｜ 信号 ' + UI.esc(Object.keys(digest.signals || {}).length) + ' 类</div>'
                + '<div class="hint">AI 结论仅作研判建议，不会改变自动封禁判定。</div>';
            UI.drawer.open('AI 流量研判（近 10 分钟）', html);
        }).catch(function (error) {
            UI.drawer.open('AI 流量研判', '<div class="hint">研判失败：' + UI.esc(error.message) + '</div>');
        });
    }

    function bind() {
        document.getElementById('filterGroup').addEventListener('click', function (event) {
            var button = event.target.closest ? event.target.closest('[data-filter]') : null;
            if (!button) { return; }
            filter = button.getAttribute('data-filter');
            Array.prototype.forEach.call(document.querySelectorAll('#filterGroup .btn'), function (item) {
                item.className = item === button ? 'btn active' : 'btn';
            });
            renderPorts();
        });

        document.getElementById('portSearch').addEventListener('input', function (event) {
            keyword = event.target.value.trim();
            renderPorts();
        });

        document.getElementById('btnExportPorts').addEventListener('click', function () {
            if (!portRows.length) {
                UI.toast('暂无可导出的端口数据', true);
                return;
            }
            var rows = [['端口', '协议', '是否标准', '当前pps', '当前bps', '连接数',
                '基线均值pps', '偏离倍数', 'Z值', '主要来源', '是否异常']];
            portRows.forEach(function (row) {
                rows.push([row.port, row.protocol, row.is_standard ? '是' : '否', row.pps, row.bps,
                    row.conns, row.baseline_mean_pps, row.deviation_ratio || '', row.zscore,
                    row.top_source, row.anomaly ? '是' : '否']);
            });
            UI.csv('ports-baseline-' + Date.now() + '.csv', rows);
        });

        UI.delegate(document, '[data-block-ip]', 'click', function (event, target) {
            var ip = target.getAttribute('data-block-ip');
            var reason = target.getAttribute('data-reason') || '异常端口检测页人工封禁';
            UI.confirm('确认封禁 ' + ip + ' ？', function () {
                SecApi.block(ip, reason).then(function (result) {
                    UI.toast(result.message, !result.success);
                    UI.drawer.close();
                    loadEvents();
                    loadPorts();
                }).catch(function (error) { UI.toast('封禁失败：' + error.message, true); });
            });
        });

        UI.delegate(document, '[data-whitelist-ip]', 'click', function (event, target) {
            var ip = target.getAttribute('data-whitelist-ip');
            UI.confirm('把 ' + ip + ' 加入白名单？\n（加入后不再对其自动封禁，适用于确认是误报的来源）', function () {
                SecApi.whitelist(ip + '/32', '异常端口检测页加入').then(function (result) {
                    UI.toast(result.message, !result.success);
                }).catch(function (error) { UI.toast('添加失败：' + error.message, true); });
            });
        });

        UI.delegate(document, '[data-alert-detail]', 'click', function (event, target) {
            openDetail(Number(target.getAttribute('data-alert-detail')));
        });

        UI.delegate(document, '[data-alert-block]', 'click', function (event, target) {
            var id = Number(target.getAttribute('data-alert-block'));
            UI.confirm('确认封禁该告警的源 IP？', function () {
                SecApi.blockAlertSource(id, 1800).then(function (result) {
                    UI.toast(result.message, !result.success);
                    loadEvents();
                    loadStats();
                }).catch(function (error) { UI.toast('封禁失败：' + error.message, true); });
            });
        });

        UI.delegate(document, '[data-alert-ack]', 'click', function (event, target) {
            var id = Number(target.getAttribute('data-alert-ack'));
            SecApi.ackAlert(id).then(function (result) {
                UI.toast(result.message, !result.success);
                UI.drawer.close();
                loadEvents();
            }).catch(function (error) { UI.toast('确认失败：' + error.message, true); });
        });

        /* v2：阈值管理 / 信号列表 / 规则来源 / 重新研判 */
        document.getElementById('btnThresholds').addEventListener('click', openThresholds);
        document.getElementById('btnSignals').addEventListener('click', function () {
            loadSignals(false);
        });
        document.getElementById('btnSuppressed').addEventListener('click', function () {
            loadSignals(true);
        });
        document.getElementById('btnRuleSources').addEventListener('click', openRuleSources);
        document.getElementById('btnAiReview').addEventListener('click', openAiReview);
        document.getElementById('btnRecompute').addEventListener('click', function () {
            SecApi.recomputeThresholds().then(function (result) {
                UI.toast(result.message, !result.success);
                loadScoring();
                loadSignals(false);
            }).catch(function (error) { UI.toast('重算失败：' + error.message, true); });
        });

        UI.delegate(document, '[data-reanalyze]', 'click', function (event, target) {
            var id = Number(target.getAttribute('data-reanalyze'));
            SecApi.reanalyzeAlert(id).then(function (result) {
                UI.toast(result.message, !result.success);
                openDetail(id);
            }).catch(function (error) { UI.toast('研判失败：' + error.message, true); });
        });

        /* 图表尺寸自适应：窗口 resize / 容器尺寸变化（含 rem 基准变化）统一自动 resize */
        UI.autoResize(typeChart);
    }

    /* -------------------- 启动 -------------------- */
    function start() {
        /* 先定 rem 基准再初始化图表，避免画布尺寸被固化成错误值（刷新后错位） */
        UI.fitRem();
        initChart();
        bind();
        UI.boot('anomaly');
        loadPorts();
        loadEvents();
        loadStats();
        loadScoring();
        loadSignals(false);
        setInterval(loadPorts, 3000);
        setInterval(function () { loadEvents(); loadStats(); }, 8000);
        setInterval(function () { loadScoring(); loadSignals(false); }, 15000);
        SecApi.on('alert', function () { loadEvents(); loadStats(); loadPorts(); loadSignals(false); });
        /* 研判完成后刷新详情（SSE 事件回推，无需轮询） */
        SecApi.on('alert_enriched', function () {
            var open = document.querySelectorAll('[data-alert-detail]');
            if (open && open.length) { loadEvents(); }
        });
        /* 被抑制的信号也实时刷新（降级可见） */
        SecApi.on('signal', function () { loadSignals(false); loadStats(); });
    }

    global.SecAnomalyPage = { start: start };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})(window);


