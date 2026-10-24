/**
 * page-block.js —— 封禁管理（v6 P1：封禁/白名单/处置流水/安全事件报告）
 *
 * 数据来源：/blocks（封禁表）、/whitelist（白名单）、/disposals（审计流水）、
 *            /notify/channels（通道状态）、/overview（KPI）、/reports（安全事件报告）
 * 处置能力：手动封禁、续期、解封、清理到期、白名单增删、告警通道自检、CSV 导出、生成报告
 */
(function (global) {
    'use strict';

    var blocks = [];
    var actions = [];

    /* -------------------- 封禁表 -------------------- */
    function loadBlocks() {
        var activeOnly = document.getElementById('chkActiveOnly').checked;
        return SecApi.get('/blocks?active_only=' + activeOnly + '&limit=200').then(function (data) {
            blocks = data.items || [];
            UI.setText('kActive', blocks.filter(function (item) { return item.active; }).length);
            UI.setText('kTotal', data.total || blocks.length);
            var body = document.getElementById('blockBody');
            if (!blocks.length) {
                body.innerHTML = '<tr><td colspan="10" class="empty-row">暂无封禁记录（系统运行正常）</td></tr>';
                return;
            }
            body.innerHTML = blocks.map(function (item) {
                var color = UI.sevColor(item.severity);
                var remaining = item.active
                    ? (item.remaining_sec === null || item.remaining_sec === undefined
                        ? '永久' : UI.fmt.duration(item.remaining_sec))
                    : '<span class="hint">已解除</span>';
                return '<tr>'
                    + '<td class="mono">' + UI.esc(item.ip) + '</td>'
                    + '<td>' + UI.pill(UI.catText(item.category), color) + '</td>'
                    + '<td>' + UI.badge(UI.sevText(item.severity), color) + '</td>'
                    + '<td title="' + UI.esc(item.reason) + '">' + UI.esc((item.reason || '').slice(0, 30)) + '</td>'
                    + '<td>' + UI.esc(item.source === 'auto' ? '自动' : '人工') + '</td>'
                    + '<td>' + UI.fmt.time(item.created_at) + '</td>'
                    + '<td class="num warn">' + remaining + '</td>'
                    + '<td class="num">' + (item.hits || 1) + '</td>'
                    + '<td><button class="btn-mini" type="button" data-report-ip="'
                    + UI.esc(item.ip) + '">生成报告</button></td>'
                    + '<td><div class="actions">'
                    + (item.active
                        ? '<button class="btn-mini" type="button" data-extend-ip="' + UI.esc(item.ip)
                          + '">续期30分</button>'
                          + '<button class="btn-mini" type="button" data-unblock-ip="' + UI.esc(item.ip)
                          + '">解封</button>'
                        : '<span class="hint">-</span>')
                    + '</div></td>'
                    + '</tr>';
            }).join('');
        });
    }

    /* -------------------- 白名单 -------------------- */
    function loadWhitelist() {
        return SecApi.get('/whitelist').then(function (data) {
            var items = data.items || [];
            UI.setText('kWhitelist', items.length);
            var body = document.getElementById('whitelistBody');
            body.innerHTML = items.length ? items.map(function (item) {
                return '<tr>'
                    + '<td class="mono">' + UI.esc(item.cidr) + '</td>'
                    + '<td>' + UI.esc(item.note || '-') + '</td>'
                    + '<td>' + UI.esc(item.source === 'config' ? '内置' : '页面维护') + '</td>'
                    + '<td>' + (item.source === 'config'
                        ? '<span class="hint">内置不可删</span>'
                        : '<button class="btn-mini" type="button" data-del-whitelist="'
                          + UI.esc(item.cidr) + '">移除</button>') + '</td>'
                    + '</tr>';
            }).join('') : '<tr><td colspan="4" class="empty-row">暂无白名单</td></tr>';
        });
    }

    /* -------------------- 处置时间线 -------------------- */
    function loadDisposals() {
        return SecApi.get('/disposals?limit=40').then(function (data) {
            actions = data.items || [];
            UI.setText('kActions', data.total || actions.length);
            var box = document.getElementById('disposalList');
            box.innerHTML = actions.length ? actions.map(function (item) {
                return '<li' + (item.success ? '' : ' class="fail"') + '>'
                    + '<span class="t">' + UI.fmt.time(item.ts).slice(5) + '</span>'
                    + '<span class="a">' + UI.esc(UI.statusText(item.action)) + '</span>'
                    + '<b>' + UI.esc(item.target || '-') + '</b>'
                    + '<span class="d">' + UI.esc(item.detail || '') + '</span>'
                    + '</li>';
            }).join('') : '<li>暂无处置动作</li>';
        });
    }

    /* -------------------- 告警通道 -------------------- */
    function loadChannels() {
        return SecApi.get('/notify/channels').then(function (data) {
            var channels = data.channels || [];
            UI.setText('kChannels', channels.length);
            UI.setHtml('channelList', channels.map(function (name) {
                var desc = name === 'log' ? '本地日志（审计兜底，始终启用）'
                    : (name.indexOf('webhook') === 0 ? '机器人 Webhook（钉钉/企业微信）' : '外部通道');
                return '<div style="padding:0.06rem 0">' + UI.pill(name, '#00d8ff')
                    + '<span class="hint" style="margin-left:0.1rem">' + UI.esc(desc) + '</span></div>';
            }).join('') || '<div class="hint">未配置任何通道</div>');

            var stats = data.stats || {};
            var history = data.history || [];
            document.getElementById('notifyHistory').innerHTML = history.length ? history.map(function (item) {
                var keys = Object.keys(item.channels || {});
                var okCount = keys.filter(function (key) { return item.channels[key].ok; }).length;
                return '<li>'
                    + '<span class="t">' + UI.fmt.time(item.ts || item.ts_text || '') + '</span>'
                    + '<span class="a">' + UI.esc(UI.catText(item.category)) + '</span>'
                    + '<b>' + UI.esc(item.source_ip || '-') + '</b>'
                    + '<span class="d">成功 ' + okCount + ' / ' + keys.length + ' 个通道 ｜ 累计成功 '
                    + (stats.sent || 0) + ' 次</span>'
                    + '</li>';
            }).join('') : '<li>暂无发送记录</li>';
        });
    }

    /* -------------------- KPI 与运行信息 -------------------- */
    function loadOverview() {
        return SecApi.get('/overview').then(function (data) {
            UI.setText('kActive', UI.fmt.count(data.blocked_active));
            UI.setText('kTotal', UI.fmt.count(data.blocked_total));
            UI.setText('kDryRun', data.dry_run ? 'DRY-RUN（仅记录）' : '已生效');
            UI.setText('fwHint', (data.firewall_backend || '-') + (data.dry_run ? ' / DRY-RUN' : ' / LIVE'));
        });
    }

    /* -------------------- 安全事件报告（v6 P1） -------------------- */
    function loadReports() {
        return SecApi.reports(50).then(function (data) {
            var items = data.items || [];
            var body = document.getElementById('reportBody');
            if (!body) { return; }
            if (!items.length) {
                body.innerHTML = '<tr><td colspan="5" class="empty-row">暂无报告；在封禁记录行点击“生成报告”</td></tr>';
                return;
            }
            body.innerHTML = items.map(function (item) {
                return '<tr>'
                    + '<td>' + UI.fmt.time(item.created_at) + '</td>'
                    + '<td class="mono">' + UI.esc(item.ip) + '</td>'
                    + '<td class="mono" title="' + UI.esc(item.sha256) + '">'
                    + UI.esc((item.sha256 || '').slice(0, 16)) + '…</td>'
                    + '<td>' + UI.esc(item.operator || '-') + '</td>'
                    + '<td><div class="actions">'
                    + '<a class="btn-mini" target="_blank" rel="noopener" href="' + UI.esc(item.view_url) + '">查看</a>'
                    + '<a class="btn-mini" href="' + UI.esc(item.download_url) + '">下载</a>'
                    + '</div></td></tr>';
            }).join('');
        }).catch(function () { /* 报告接口不可用时不影响封禁处置 */ });
    }

    function generateReport(ip) {
        SecApi.createReport(ip).then(function (result) {
            UI.toast('报告已生成（事件 ' + result.event_count + ' 条，告警 '
                + result.alert_count + ' 条）');
            loadReports();
            window.open(result.view_url, '_blank', 'noopener');
        }).catch(function (error) { UI.toast('生成报告失败：' + error.message, true); });
    }


    /* -------------------- 交互 -------------------- */
    function bind() {
        UI.delegate('#blockBody', '[data-report-ip]', 'click', function (_event, node) {
            generateReport(node.getAttribute('data-report-ip'));
        });
        document.getElementById('btnManualBlock').addEventListener('click', function () {
            var ip = document.getElementById('manualIp').value.trim();
            var reason = document.getElementById('manualReason').value.trim() || '页面人工封禁';
            var ttl = Number(document.getElementById('manualTtl').value);
            if (!ip) {
                UI.toast('请先填写要封禁的 IP 或 CIDR', true);
                return;
            }
            UI.confirm('确认封禁 ' + ip + '（' + UI.fmt.duration(ttl) + '）？', function () {
                SecApi.block(ip, reason, ttl).then(function (result) {
                    UI.toast(result.message, !result.success);
                    if (result.success) {
                        document.getElementById('manualIp').value = '';
                        document.getElementById('manualReason').value = '';
                    }
                    refresh();
                }).catch(function (error) { UI.toast('封禁失败：' + error.message, true); });
            });
        });

        document.getElementById('btnReap').addEventListener('click', function () {
            SecApi.reapBlocks().then(function (result) {
                UI.toast(result.message, !result.success);
                refresh();
            }).catch(function (error) { UI.toast('清理失败：' + error.message, true); });
        });

        document.getElementById('chkActiveOnly').addEventListener('change', loadBlocks);

        document.getElementById('btnExportBlocks').addEventListener('click', function () {
            if (!blocks.length) {
                UI.toast('暂无可导出的封禁记录', true);
                return;
            }
            var rows = [['IP', '类型', '级别', '原因', '来源', '操作人', '创建时间', '到期时间',
                '剩余秒', '命中次数', '是否生效', 'DRY-RUN']];
            blocks.forEach(function (item) {
                rows.push([item.ip, UI.catText(item.category), UI.sevText(item.severity), item.reason,
                    item.source, item.operator, item.created_at, item.expires_at || '',
                    item.remaining_sec === null || item.remaining_sec === undefined ? '' : item.remaining_sec,
                    item.hits, item.active ? '是' : '否', item.dry_run ? '是' : '否']);
            });
            UI.csv('blocks-' + Date.now() + '.csv', rows);
        });

        document.getElementById('btnAddWhitelist').addEventListener('click', function () {
            var cidr = document.getElementById('wlCidr').value.trim();
            var note = document.getElementById('wlNote').value.trim();
            if (!cidr) {
                UI.toast('请填写 IP 或 CIDR', true);
                return;
            }
            SecApi.whitelist(cidr, note).then(function (result) {
                UI.toast(result.message, !result.success);
                if (result.success) {
                    document.getElementById('wlCidr').value = '';
                    document.getElementById('wlNote').value = '';
                }
                loadWhitelist();
            }).catch(function (error) { UI.toast('添加失败：' + error.message, true); });
        });

        document.getElementById('btnNotifyTest').addEventListener('click', function (event) {
            event.target.disabled = true;
            SecApi.notifyTest().then(function (result) {
                UI.toast(result.message || '测试告警已发送', !result.success);
                loadChannels();
            }).catch(function (error) {
                UI.toast('通道自检失败：' + error.message, true);
            }).then(function () { event.target.disabled = false; });
        });

        UI.delegate(document, '[data-unblock-ip]', 'click', function (event, target) {
            var ip = target.getAttribute('data-unblock-ip');
            UI.confirm('确认解封 ' + ip + ' ？\n（将撤销防火墙规则并写入审计日志）', function () {
                SecApi.unblock(ip).then(function (result) {
                    UI.toast(result.message, !result.success);
                    refresh();
                }).catch(function (error) { UI.toast('解封失败：' + error.message, true); });
            });
        });

        UI.delegate(document, '[data-extend-ip]', 'click', function (event, target) {
            var ip = target.getAttribute('data-extend-ip');
            SecApi.extendBlock(ip, 1800).then(function (result) {
                UI.toast(result.message, !result.success);
                refresh();
            }).catch(function (error) { UI.toast('续期失败：' + error.message, true); });
        });

        UI.delegate(document, '[data-del-whitelist]', 'click', function (event, target) {
            var cidr = target.getAttribute('data-del-whitelist');
            UI.confirm('移除白名单 ' + cidr + ' ？\n（移除后该来源可能被再次自动封禁）', function () {
                SecApi.removeWhitelist(cidr).then(function (result) {
                    UI.toast(result.message, !result.success);
                    loadWhitelist();
                }).catch(function (error) { UI.toast('移除失败：' + error.message, true); });
            });
        });
    }

    function refresh() {
        loadBlocks();
        loadOverview();
        loadDisposals();
    }

    function start() {
        bind();
        UI.boot('block');
        refresh();
        loadWhitelist();
        loadChannels();
        loadReports();
        setInterval(refresh, 5000);
        setInterval(function () { loadWhitelist(); loadChannels(); }, 15000);
        SecApi.on('alert', function () { refresh(); });
    }

    global.SecBlockPage = { start: start };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})(window);


