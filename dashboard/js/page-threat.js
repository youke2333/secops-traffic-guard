/**
 * page-threat.js —— 威胁告警（v6 P1）
 *
 * 数据：/threats（筛选/分页）、/threats/{id}（请求快照）、/threats/facets、/threats/stats。
 * 处置：/threats/{id}/block（走统一五道闸门，DRY-RUN 时只记录）。
 */
(function (global) {
    'use strict';

    var state = { page: 1, page_size: 50, tag: [], total: 0 };
    var DIRECTION = { inbound: '外到内', internal: '内到内', outbound: '内到外', unknown: '未知' };

    function el(id) { return document.getElementById(id); }
    function val(id) { var node = el(id); return node ? node.value.trim() : ''; }

    function filters(includePage) {
        var params = {
            severity: val('fSeverity'), direction: val('fDirection'), status: val('fStatus'),
            tier: val('fTier'), category: val('fCategory'),
            src_ip: val('fSrcIp'), dst_ip: val('fDstIp'), q: val('fQuery'),
            tag: state.tag.slice()
        };
        var hours = val('fHours');
        if (hours) {
            params.start = String(Math.floor((Date.now() - Number(hours) * 3600 * 1000) / 1000));
        }
        if (includePage) {
            params.page = state.page;
            params.page_size = state.page_size;
        }
        return params;
    }

    function tagHtml(tags) {
        return (tags || []).map(function (tag) {
            var cls = tag === 'lab' ? 'tag-chip tier-lab' : (tag === 'core' ? 'tag-chip tier-core' : 'tag-chip');
            return '<span class="' + cls + '" data-tag="' + UI.esc(tag) + '">' + UI.esc(tag) + '</span>';
        }).join('');
    }

    function rowHtml(item) {
        var color = UI.sevColor(item.severity);
        var parts = [];
        if (item.rule_id) { parts.push('<span class="mono">' + UI.esc(item.rule_id) + '</span>'); }
        if (item.tier) { parts.push('<span class="hint">' + UI.esc(item.tier) + '</span>'); }
        return '<tr>'
            + '<td>' + UI.fmt.time(item.ts) + '</td>'
            + '<td class="mono">' + UI.esc(item.source_ip || '-') + '</td>'
            + '<td class="mono">' + UI.esc((item.dest_ip || '-') + (item.dest_port ? ':' + item.dest_port : '')) + '</td>'
            + '<td>' + UI.esc(UI.catText(item.category)) + '</td>'
            + '<td>' + UI.badge(UI.sevText(item.severity), color) + '</td>'
            + '<td>' + UI.esc(DIRECTION[item.direction] || item.direction || '未知') + '</td>'
            + '<td>' + (parts.join(' ') || '-') + '</td>'
            + '<td>' + (tagHtml(item.tags) || '-') + '</td>'
            + '<td>' + (item.alert_id ? '<span class="tag-chip">已告警</span>' : '<span class="hint">仅记录</span>')
            + (item.triage_verdict ? '<span class="hint"> / ' + UI.esc(item.triage_verdict) + '</span>' : '')
            + '</td>'
            + '<td><div class="actions">'
            + '<button class="btn-mini" type="button" data-threat-detail="' + item.id + '">详情</button>'
            + (item.source_ip ? '<button class="btn-mini" type="button" data-threat-block="' + item.id + '">封禁</button>' : '')
            + '</div></td></tr>';
    }

    function render(data) {
        state.total = data.total || 0;
        var items = data.items || [];
        UI.setText('kFiltered', UI.fmt.count(state.total));
        UI.setText('pageInfo', '第 ' + state.page + ' 页 / 共 ' + state.total + ' 条');
        el('btnPrev').disabled = state.page <= 1;
        el('btnNext').disabled = state.page * state.page_size >= state.total;
        var body = el('threatBody');
        if (!items.length) {
            body.innerHTML = '<tr><td colspan="10" class="empty-row">没有符合条件的威胁事件（'
                + (state.total ? '请调整筛选' : '系统尚未命中规则') + '）</td></tr>';
            return;
        }
        body.innerHTML = items.map(rowHtml).join('');
    }

    function load() {
        UI.setText('pageHint', '加载中…');
        return SecApi.threats(filters(true)).then(function (data) {
            render(data);
            UI.setText('pageHint', '点击“详情”查看请求快照、规则与研判证据');
        }).catch(function (error) {
            UI.setText('pageHint', '加载失败：' + error.message);
            el('threatBody').innerHTML = '<tr><td colspan="10" class="empty-row">加载失败：'
                + UI.esc(error.message) + '</td></tr>';
        });
    }

    function loadStats() {
        return SecApi.threatStats(24).then(function (data) {
            UI.setText('kThreats', UI.fmt.count(data.total));
            UI.setText('kAlerted', UI.fmt.count(data.alerted));
            var high = 0;
            (data.trend || []).forEach(function (row) {
                high += (row.critical || 0) + (row.high || 0);
            });
            UI.setText('kHigh', UI.fmt.count(high));
        }).catch(function () { /* 保留 0 */ });
    }

    function loadFacets() {
        return SecApi.threatFacets().then(function (data) {
            var select = el('fCategory');
            while (select.options.length > 1) { select.remove(1); }
            var categories = data.category || {};
            Object.keys(categories).sort().forEach(function (key) {
                var option = document.createElement('option');
                option.value = key;
                option.textContent = UI.catText(key) + '（' + categories[key] + '）';
                select.appendChild(option);
            });
        }).catch(function () { /* 忽略 */ });
    }

    function refresh() {
        loadStats();
        loadFacets();
        return load();
    }

    /** 读取 URL 预设：?event=<id> 自动展开该事件详情；?src_ip= 预填源 IP 过滤。 */
    function applyUrlFocus() {
        var params = new URLSearchParams(global.location.search);
        var srcIp = params.get('src_ip') || '';
        if (srcIp && el('fSrcIp')) {
            el('fSrcIp').value = srcIp;
            if (el('fHours')) { el('fHours').value = params.get('hours') || '24'; }
        }
        var eventId = String(params.get('event') || '').trim();
        return /^\d+$/.test(eventId) ? eventId : '';
    }

    function detailHtml(item) {
        var evidence = item.evidence || {};
        var alert = item.alert;
        var overview = '<div class="detail-grid">'
            + '<div><span class="label">时间</span><b>' + UI.esc(UI.fmt.time(item.ts)) + '</b></div>'
            + '<div><span class="label">源 / 目的</span><b>' + UI.esc(item.source_ip || '-')
            + ' → ' + UI.esc((item.dest_ip || '-') + (item.dest_port ? ':' + item.dest_port : '')) + '</b></div>'
            + '<div><span class="label">类别 / 级别</span><b>' + UI.esc(UI.catText(item.category))
            + ' / ' + UI.esc(UI.sevText(item.severity)) + '</b></div>'
            + '<div><span class="label">方向</span><b>' + UI.esc(DIRECTION[item.direction] || item.direction) + '</b></div>'
            + '<div><span class="label">规则 / 档位</span><b>' + UI.esc(item.rule_id || '-')
            + ' / ' + UI.esc(item.tier || '-') + '</b></div>'
            + '<div><span class="label">采集保真度</span><b>' + UI.esc(item.capture_level || 'L0')
            + '（' + UI.esc(item.capture_source || '-') + '）</b></div>'
            + '<div><span class="label">研判</span><b>' + UI.esc(item.triage_verdict || '未启用')
            + (item.triage_reason ? '：' + UI.esc(item.triage_reason) : '') + '</b></div>'
            + '<div><span class="label">关联告警</span><b>' + (alert
                ? '#' + alert.id + '（风险分 ' + UI.esc(alert.risk_score) + '）' : '无（被聚合抑制）') + '</b></div>'
            + '</div>'
            + '<p class="hint">' + UI.hl(item.message || '') + '</p>'
            + '<div>' + (tagHtml(item.tags) || '') + '</div>';
        var request = '<pre class="evidence-pre">' + UI.hl(item.request_head || '当前采集模式未包含请求头')
            + (item.request_body ? '\n\n' + UI.hl(item.request_body) : '\n\n[无请求体 / L0 日志模式]') + '</pre>';
        var response = '<pre class="evidence-pre">' + UI.hl(item.response_head || '当前采集模式未包含响应头')
            + (item.response_body ? '\n\n' + UI.hl(item.response_body) : '\n\n[仅状态码：'
            + UI.esc(item.status_code || '-') + ']') + '</pre>';
        var rules = (evidence.rules || []).map(function (rule) {
            return '<li><b>' + UI.esc(rule.id) + '</b> ' + UI.esc(rule.title || '')
                + '<span class="hint"> 目标=' + UI.esc(rule.target || '-')
                + ' 片段=' + UI.hl(rule.snippet || '-') + '</span></li>';
        }).join('') || '<li>无规则明细</li>';
        var evidenceHtml = '<ul class="timeline-list">' + rules + '</ul>'
            + '<p class="hint">评分聚合：' + UI.esc(JSON.stringify(evidence.aggregation || {})) + '</p>'
            + '<pre class="evidence-pre">' + UI.esc(JSON.stringify(evidence, null, 2).slice(0, 12000)) + '</pre>';
        return '<div class="tab-row" id="threatTabs">'
            + '<button class="btn active" type="button" data-tab="overview">概览</button>'
            + '<button class="btn" type="button" data-tab="request">请求包</button>'
            + '<button class="btn" type="button" data-tab="response">响应包</button>'
            + '<button class="btn" type="button" data-tab="evidence">匹配与证据</button></div>'
            + '<div class="atk-legend"><mark class="atk">红色标注</mark> 为命中的攻击特征'
            + '（命令执行 / SQL 注入 / XSS / 目录穿越 / 反序列化等）</div>'
            + '<div data-pane="overview">' + overview + '</div>'
            + '<div data-pane="request" class="hidden">' + request + '</div>'
            + '<div data-pane="response" class="hidden">' + response + '</div>'
            + '<div data-pane="evidence" class="hidden">' + evidenceHtml + '</div>';
    }

    function openDetail(id) {
        SecApi.threatDetail(id).then(function (item) {
            UI.drawer.open('威胁事件 #' + id, detailHtml(item));
            var row = document.getElementById('threatTabs');
            if (!row) { return; }
            row.addEventListener('click', function (event) {
                var button = event.target.closest('[data-tab]');
                if (!button) { return; }
                var name = button.getAttribute('data-tab');
                row.querySelectorAll('[data-tab]').forEach(function (node) {
                    node.classList.toggle('active', node === button);
                });
                document.querySelectorAll('[data-pane]').forEach(function (pane) {
                    pane.classList.toggle('hidden', pane.getAttribute('data-pane') !== name);
                });
            });
        }).catch(function (error) { UI.toast('详情加载失败：' + error.message, true); });
    }


    function bind() {
        el('btnSearch').addEventListener('click', function () { state.page = 1; load(); });
        el('btnRefresh').addEventListener('click', refresh);
        el('btnReset').addEventListener('click', function () {
            ['fSeverity', 'fDirection', 'fStatus', 'fTier', 'fCategory', 'fSrcIp', 'fDstIp', 'fQuery']
                .forEach(function (id) { el(id).value = ''; });
            el('fHours').value = '24';
            state.page = 1;
            state.tag = [];
            load();
        });
        el('fQuery').addEventListener('keydown', function (event) {
            if (event.key === 'Enter') { state.page = 1; load(); }
        });
        el('btnPrev').addEventListener('click', function () {
            if (state.page > 1) { state.page -= 1; load(); }
        });
        el('btnNext').addEventListener('click', function () {
            if (state.page * state.page_size < state.total) { state.page += 1; load(); }
        });
        el('btnExport').addEventListener('click', function () {
            global.location.href = SecApi.threatExportUrl(filters(false));
        });
        UI.delegate('#threatBody', '[data-threat-detail]', 'click', function (_event, node) {
            openDetail(node.getAttribute('data-threat-detail'));
        });
        UI.delegate('#threatBody', '[data-threat-block]', 'click', function (_event, node) {
            var id = node.getAttribute('data-threat-block');
            UI.confirm('确认封禁该事件源 IP（30 分钟）？DRY-RUN 模式下只记录命令。', function () {
                SecApi.blockThreat(id, 1800).then(function (result) {
                    UI.toast(result.message, !result.success);
                    refresh();
                }).catch(function (error) { UI.toast('封禁失败：' + error.message, true); });
            });
        });
        UI.delegate('#threatBody', '[data-tag]', 'click', function (_event, node) {
            var tag = node.getAttribute('data-tag');
            var position = state.tag.indexOf(tag);
            if (position >= 0) { state.tag.splice(position, 1); } else { state.tag.push(tag); }
            state.page = 1;
            el('tagHint').textContent = state.tag.length
                ? '已选标签：' + state.tag.join('、') + '（点击表格标签可取消）'
                : '标签筛选：点击表格中的标签即可筛选（再次点击取消）。';
            load();
        });
        var timer = setInterval(refresh, 15000);
        global.addEventListener('beforeunload', function () { clearInterval(timer); });
    }

    /** 等 SecApi 完成 live/mock 判定后再拉详情，避免与启动期的鉴权/降级竞态导致 404。 */
    function openDetailWhenReady(id, tries) {
        var left = typeof tries === 'number' ? tries : 12;
        if (SecApi.mode && SecApi.mode !== 'unknown') {
            openDetail(id);
            return;
        }
        if (left <= 0) { openDetail(id); return; }
        setTimeout(function () { openDetailWhenReady(id, left - 1); }, 150);
    }

    function start() {
        UI.boot('threat');
        bind();
        var focusId = applyUrlFocus();
        var loading = refresh();
        if (focusId) {
            // 从大屏告警弹窗「查看详情」跳转而来：直接打开对应威胁事件抽屉
            openDetailWhenReady(focusId);
            loading.then(function () {
                UI.setText('pageHint', '已定位到大屏告警对应的威胁事件 #' + focusId + '，详情已在右侧抽屉打开');
            });
        }
    }

    global.ThreatPage = { start: start, openDetail: openDetail };
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})(window);

