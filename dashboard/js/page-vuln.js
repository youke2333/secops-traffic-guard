/**
 * page-vuln.js —— 模块 3.4 漏洞提醒与修复建议
 *
 * 数据来源：/vulns（漏洞清单）、/vulns/summary（统计）、/cve/kb（知识库）、/vulns/scan/*（扫描任务）
 * 处置能力：按级别/状态筛选、触发异步扫描并展示进度、状态流转（待修复→修复中→已修复/忽略）、
 *            查看修复建议与证据、导出 CSV
 */
(function (global) {
    'use strict';

    var items = [];
    var kvRules = [];
    var webKb = { stats: {}, categories: [], rules: [] };

    /* -------------------- 摘要 -------------------- */
    function loadSummary() {
        return SecApi.get('/vulns/summary').then(function (data) {
            var dist = data.distribution || {};
            UI.setText('kOpen', UI.fmt.count(data.open));
            UI.setText('kCritical', UI.fmt.count(dist.critical || 0));
            UI.setText('kHigh', UI.fmt.count(dist.high || 0));
            UI.setText('kRules', UI.fmt.count((data.kb || {}).rules));
            UI.setText('kbHint', '知识库 ' + ((data.kb || {}).version || '-')
                + ' ｜ 扫描引擎 ' + (data.nmap_available ? 'nmap -sV' : 'banner 抓取（未安装 nmap）'));
        });
    }

    function loadCounters() {
        return SecApi.get('/vulns').then(function (data) {
            var list = data || [];
            UI.setText('kFixing', list.filter(function (item) { return item.status === 'fixing'; }).length);
            UI.setText('kFixed', list.filter(function (item) { return item.status === 'fixed'; }).length);
        });
    }

    /* -------------------- Web 攻击知识库（/web/kb） -------------------- */
    function loadWebKb() {
        return SecApi.webKb().then(function (data) {
            webKb = { stats: data.stats || {}, categories: data.categories || [],
                      rules: data.rules || [] };
            UI.setText('kWebRules', UI.fmt.count(webKb.stats.rules));
            return webKb;
        }).catch(function () { return webKb; });
    }

    /* -------------------- 清单 -------------------- */
    function filterItems() {
        var severity = document.getElementById('sevFilter').value;
        var status = document.getElementById('statusFilter').value;
        var keyword = document.getElementById('vulnSearch').value.trim().toLowerCase();
        return items.filter(function (item) {
            if (severity && item.severity !== severity) { return false; }
            if (status && item.status !== status) { return false; }
            if (keyword) {
                var hay = [item.cve, item.title, item.asset_ip, String(item.port), item.service]
                    .join(' ').toLowerCase();
                if (hay.indexOf(keyword) === -1) { return false; }
            }
            return true;
        });
    }

    function render() {
        var body = document.getElementById('vulnBody');
        var rows = filterItems();
        if (!rows.length) {
            body.innerHTML = '<tr><td colspan="9" class="empty-row">没有符合条件的漏洞记录</td></tr>';
            return;
        }
        body.innerHTML = rows.map(function (item) {
            var color = UI.sevColor(item.severity);
            var statusPill = item.status === 'fixed' ? UI.pill('已修复', '#44eab1')
                : (item.status === 'fixing' ? UI.pill('修复中', '#febe12')
                : (item.status === 'ignored' ? UI.pill('已忽略', '#7fa9c8') : UI.pill('待修复', '#ff3c4e')));
            return '<tr' + (item.status === 'open' && item.severity === 'critical' ? ' class="row-alert"' : '') + '>'
                + '<td class="mono">' + UI.esc(item.cve) + sourceTag(item) + '</td>'
                + '<td title="' + UI.esc(item.title) + '">' + UI.esc((item.title || '').slice(0, 34)) + '</td>'
                + '<td class="mono">' + UI.esc(item.asset_ip) + ':' + item.port + '</td>'
                + '<td>' + UI.esc((item.service || '-').slice(0, 22)) + '</td>'
                + '<td class="num ' + (item.cvss >= 9 ? 'danger' : (item.cvss >= 7 ? 'warn' : '')) + '">'
                + (item.cvss || 0).toFixed(1) + '</td>'
                + '<td>' + UI.badge(UI.sevText(item.severity), color) + '</td>'
                + '<td>' + statusPill + '</td>'
                + '<td>' + UI.fmt.time(item.found_at) + '</td>'
                + '<td><div class="actions">'
                + '<button class="btn-mini" type="button" data-vuln-detail="' + item.id + '">建议</button>'
                + '<button class="btn-mini" type="button" data-vuln-ai="' + item.id + '">AI 建议</button>'
                + (item.status !== 'fixing' && item.status !== 'fixed'
                    ? '<button class="btn-mini" type="button" data-vuln-status="fixing" data-vuln-id="'
                      + item.id + '">修复中</button>' : '')
                + (item.status !== 'fixed'
                    ? '<button class="btn-mini" type="button" data-vuln-status="fixed" data-vuln-id="'
                      + item.id + '">已修复</button>' : '')
                + (item.status !== 'ignored'
                    ? '<button class="btn-mini" type="button" data-vuln-status="ignored" data-vuln-id="'
                      + item.id + '">忽略</button>' : '')
                + '</div></td>'
                + '</tr>';
        }).join('');
    }

    function loadVulns() {
        return SecApi.get('/vulns?limit=300').then(function (data) {
            items = data || [];
            render();
        });
    }

    /* -------------------- 扫描任务 -------------------- */
    function renderJobs(data) {
        var jobs = (data && data.items) || [];
        var body = document.getElementById('jobBody');
        if (!jobs.length) {
            body.innerHTML = '<tr><td colspan="8" class="empty-row">暂无扫描任务，点击「立即扫描」创建</td></tr>';
            return;
        }
        body.innerHTML = jobs.map(function (job) {
            var summary = job.summary || {};
            var statePill = job.status === 'done' ? UI.pill('已完成', '#44eab1')
                : (job.status === 'running' ? UI.pill('执行中', '#febe12')
                : (job.status === 'error' ? UI.pill('失败', '#ff3c4e') : UI.pill('排队中', '#7fa9c8')));
            var percent = job.percent === undefined
                ? Math.round((job.progress || 0) / Math.max(1, job.total || 1) * 100) : job.percent;
            return '<tr>'
                + '<td class="mono">' + UI.esc(job.id) + '</td>'
                + '<td>' + statePill + '</td>'
                + '<td class="num">' + percent + '%（' + (job.progress || 0) + '/' + (job.total || 0) + '）</td>'
                + '<td class="num">' + (job.total || 0) + '</td>'
                + '<td class="num">' + (summary.services_found === undefined ? '-' : summary.services_found) + '</td>'
                + '<td class="num">' + (summary.vulns_found === undefined ? '-' : summary.vulns_found) + '</td>'
                + '<td class="num">' + UI.fmt.duration(job.duration_sec || 0) + '</td>'
                + '<td>' + UI.fmt.time(job.started_at || '') + '</td>'
                + '</tr>';
        }).join('');
    }

    function loadJobs() {
        return SecApi.scanJobs(10).then(renderJobs).catch(function () { /* 忽略 */ });
    }

    /* -------------------- 知识库抽屉 -------------------- */
    function openKb() {
        var load = kvRules.length
            ? Promise.resolve({ rules: kvRules })
            : SecApi.cveKb().then(function (data) {
                kvRules = data.rules || [];
                return data;
            });
        load.then(function (data) {
            var stats = data.stats || {};
            UI.drawer.open('CVE 知识库（' + (stats.rules || kvRules.length) + ' 条规则）',
                '<div class="hint" style="margin-bottom:0.1rem">'
                + '知识库文件：backend/data/cve_rules.json，可直接扩展新规则，无需改代码。</div>'
                + '<div class="table-wrap"><table class="grid-table"><thead><tr>'
                + '<th>CVE</th><th>标题</th><th>级别</th><th>CVSS</th><th>修复版本</th>'
                + '</tr></thead><tbody>'
                + kvRules.map(function (rule) {
                    return '<tr>'
                        + '<td class="mono">' + UI.esc(rule.cve) + '</td>'
                        + '<td>' + UI.esc((rule.title || '').slice(0, 40)) + '</td>'
                        + '<td>' + UI.badge(UI.sevText(rule.severity), UI.sevColor(rule.severity)) + '</td>'
                        + '<td class="num">' + (rule.cvss || '-') + '</td>'
                        + '<td>' + UI.esc(rule.fixed_version || '-') + '</td>'
                        + '</tr>';
                }).join('')
                + '</tbody></table></div>');
        });
    }

    /* -------------------- Web 攻击知识库抽屉 -------------------- */
    function openWebKb() {
        var load = webKb.rules.length ? Promise.resolve(webKb) : loadWebKb();
        load.then(function (data) {
            var stats = data.stats || {};
            var byCategory = stats.by_category || {};
            var cards = (data.categories || []).map(function (category) {
                var count = byCategory[category.key] || category.rule_count || 0;
                return '<div class="box" style="margin:0.06rem 0">'
                    + '<b>' + UI.esc(category.name) + '</b> '
                    + UI.badge(UI.sevText(category.severity), UI.sevColor(category.severity))
                    + '<div class="hint">' + UI.esc(category.cwe) + ' ｜ ' + UI.esc(category.owasp)
                    + ' ｜ 规则 ' + count + ' 条</div>'
                    + '<div class="hint">' + UI.esc(category.description || '') + '</div>'
                    + '</div>';
            }).join('');
            UI.drawer.open('Web 攻击知识库（' + (stats.categories || 0) + ' 类 / '
                + (stats.rules || 0) + ' 条规则）',
                '<div class="hint" style="margin-bottom:0.1rem">'
                + '知识库文件：backend/data/web_attack_rules.json，覆盖 OWASP Top 10 与通用 Web 攻击类型，'
                + '可直接扩展 categories / rules，无需改代码。流量侧命中即生成 web_* 类型告警，'
                + '高危规则可直接联动封禁。</div>'
                + cards
                + '<h4>规则明细</h4>'
                + '<div class="table-wrap"><table class="grid-table"><thead><tr>'
                + '<th>规则</th><th>攻击类型</th><th>标题</th><th>级别</th><th>CWE</th>'
                + '<th>置信度</th><th>命中示例</th></tr></thead><tbody>'
                + (data.rules || []).map(function (rule) {
                    var example = (rule.examples || [])[0] || '-';
                    return '<tr>'
                        + '<td class="mono">' + UI.esc(rule.id) + '</td>'
                        + '<td>' + UI.esc(rule.category_name || rule.category) + '</td>'
                        + '<td title="' + UI.esc(rule.title) + '">'
                        + UI.esc((rule.title || '').slice(0, 26)) + '</td>'
                        + '<td>' + UI.badge(UI.sevText(rule.severity), UI.sevColor(rule.severity))
                        + '</td>'
                        + '<td class="mono">' + UI.esc(rule.cwe || '-') + '</td>'
                        + '<td>' + UI.esc(rule.confidence || '-') + '</td>'
                        + '<td class="mono" title="' + UI.esc(example) + '">'
                        + UI.esc(example.slice(0, 30)) + '</td>'
                        + '</tr>';
                }).join('')
                + '</tbody></table></div>');
        });
    }

    /* -------------------- AI 修复建议 -------------------- */
    function aiAdviceHtml(item) {
        var advice = item.ai_advice;
        if (!advice) {
            return '<div class="hint">尚未生成：点击「AI 建议」由大模型生成；'
                + 'API 不可用时自动降级为知识库模板（来源会标注）。</div>';
        }
        return '<div class="box">'
            + '<b>' + UI.esc(advice.summary || '') + '</b>'
            + '<div class="hint">来源：' + UI.esc(advice.source || '-')
            + (advice.degraded ? '（已降级）' : '') + ' ｜ 风险：' + UI.esc(advice.risk || '-')
            + ' ｜ 生成时间：' + UI.esc(advice.generated_at || '-') + '</div>'
            + '<ol>' + (advice.steps || []).map(function (step) {
                return '<li>' + UI.esc(step) + '</li>';
            }).join('') + '</ol>'
            + '<div class="hint">验证方法：' + UI.esc(advice.verification || '-') + '</div>'
            + '</div>';
    }

    function requestAiAdvice(id, force) {
        var item = items.filter(function (row) { return row.id === id; })[0];
        UI.toast(force ? '已向 AI 重新发送请求，等待生成…' : '正在生成 AI 修复建议（最长 3 秒）…');
        return SecApi.vulnAdvice(id, force).then(function (result) {
            if (item) {
                item.ai_advice = result;
                item.ai_source = result.source || '';
            }
            UI.toast('AI 建议已生成（来源：' + (result.source || '-')
                + (result.degraded ? '，已降级：未配置 API Key 或调用失败' : '')
                + '，' + (result.generated_at || '-') + '）');
            openDetail(id);
            render();
        }).catch(function (error) {
            UI.toast('生成失败：' + error.message, true);
        });
    }

    /* 发现途径标签：CVE 编号 vs 攻击流量研判，一眼可分 */
    var SOURCE_TAG = {
        web: { text: '体检', cls: 'web', tip: 'Web 应用配置与暴露面体检' },
        traffic_rule: { text: '流量', cls: 'traffic', tip: '由攻击请求/响应的规则研判得出' },
        traffic_ai: { text: 'AI', cls: 'ai', tip: '由攻击请求/响应经模型复核得出' }
    };

    function sourceTag(item) {
        var tag = SOURCE_TAG[item.source];
        if (!tag) { return ''; }
        var suffix = item.confidence === 'confirmed' ? '·确认'
            : (item.confidence === 'suspected' ? '·疑似' : '');
        return '<span class="src-tag ' + tag.cls + '" title="' + UI.esc(tag.tip) + '">'
            + tag.text + suffix + '</span>';
    }

    /* -------------------- 修复建议抽屉 -------------------- */
    function openDetail(id) {
        var item = items.filter(function (row) { return row.id === id; })[0];
        if (!item) { return; }
        var isTraffic = String(item.source || '').indexOf('traffic') === 0;
        UI.drawer.open('漏洞详情 ' + UI.esc(item.cve),
            '<dl>'
            + '<dt>漏洞标题</dt><dd>' + UI.esc(item.title) + '</dd>'
            + '<dt>严重级别</dt><dd>' + UI.pill(UI.sevText(item.severity), UI.sevColor(item.severity))
            + '（CVSS ' + (item.cvss || 0).toFixed(1) + '）</dd>'
            + '<dt>影响主机</dt><dd>' + UI.esc(item.asset_ip) + ':' + item.port + '</dd>'
            + '<dt>服务/版本</dt><dd>' + UI.esc(item.service || '-') + '</dd>'
            + '<dt>发现途径</dt><dd>' + UI.esc(sourceText(item)) + '</dd>'
            + '<dt>当前状态</dt><dd>' + UI.esc(UI.vulnStatusText(item.status)) + '</dd>'
            + '<dt>发现时间</dt><dd>' + UI.fmt.time(item.found_at) + '</dd>'
            + '</dl>'
            + '<h4>修复建议</h4><div class="box">' + UI.esc(item.recommendation || '升级到安全版本。') + '</div>'
            + '<h4>最低修复版本</h4><div>'
            + UI.esc(isTraffic ? '不适用：属应用逻辑缺陷，需改代码/加固配置，不是升级组件能解决的'
                : (item.fixed_version || '以厂商公告为准')) + '</div>'
            + '<h4>AI 修复建议</h4>' + aiAdviceHtml(item)
            + '<h4>检测证据</h4><div class="vuln-evidence">' + UI.esc(item.evidence || '-') + '</div>'
            + '<div class="toolbar" style="margin-top:0.16rem">'
            + '<button class="btn" type="button" data-vuln-ai="' + item.id + '">生成 / 重新生成 AI 建议</button>'
            + '<button class="btn" type="button" data-vuln-status="fixing" data-vuln-id="' + item.id
            + '">标记为修复中</button>'
            + '<button class="btn" type="button" data-vuln-status="fixed" data-vuln-id="' + item.id
            + '">标记为已修复</button>'
            + '<button class="btn" type="button" data-vuln-status="ignored" data-vuln-id="' + item.id
            + '">忽略该漏洞</button>'
            + '</div>');
    }

    function sourceText(item) {
        var tag = SOURCE_TAG[item.source];
        if (!tag) { return '主动扫描（端口/版本 + CVE 知识库）'; }
        var conf = item.confidence === 'confirmed' ? '，已确认'
            : (item.confidence === 'suspected' ? '，疑似' : '');
        return tag.tip + conf;
    }

    /* -------------------- 交互 -------------------- */
    function bind() {
        ['sevFilter', 'statusFilter'].forEach(function (id) {
            document.getElementById(id).addEventListener('change', render);
        });
        document.getElementById('vulnSearch').addEventListener('input', render);

        document.getElementById('btnScanAll').addEventListener('click', function (event) {
            var button = event.target;
            button.disabled = true;
            button.textContent = '扫描中…';
            SecApi.scan().then(function (result) {
                if (result && result.job_id) {
                    UI.toast('扫描任务已提交（' + result.total + ' 个目标），可在下方查看进度');
                    UI.pollScanJob(result.job_id, function (job) {
                        button.textContent = '扫描中 ' + job.percent + '%';
                    }).then(function () {
                        loadVulns();
                        loadSummary();
                        loadCounters();
                        loadJobs();
                        button.disabled = false;
                        button.textContent = '立即扫描';
                    });
                    return;
                }
                UI.toast('扫描完成：发现漏洞 ' + (result.vulns_found || 0) + ' 个');
                loadVulns();
                loadSummary();
                button.disabled = false;
                button.textContent = '立即扫描';
            }).catch(function (error) {
                UI.toast('扫描失败：' + error.message, true);
                button.disabled = false;
                button.textContent = '立即扫描';
            });
        });

        document.getElementById('btnKb').addEventListener('click', openKb);
        document.getElementById('btnWebKb').addEventListener('click', openWebKb);

        document.getElementById('btnWebScan').addEventListener('click', function (event) {
            var button = event.target;
            var input = document.getElementById('webappUrl');
            var url = (input.value || '').trim()
                || ('http://' + (location.hostname || '127.0.0.1') + ':8080/');
            input.value = url;
            button.disabled = true;
            button.textContent = '漏扫中…';
            SecApi.webappScan(url).then(function (result) {
                var info = result.fingerprint || {};
                UI.toast('Web 漏扫完成：' + (result.vulns_found || 0) + ' 条漏洞记录'
                    + '（检查 ' + (info.checks || result.vulns_found || 0) + ' 项 / '
                    + (info.pages_scanned || 0) + ' 个页面）', !result.vulns_found);
                var rows = (result.vulns || []).map(function (item) {
                    return '<tr><td class="mono">' + UI.esc(item.cve) + '</td>'
                        + '<td>' + UI.esc(item.title) + '</td>'
                        + '<td>' + UI.badge(UI.sevText(item.severity), UI.sevColor(item.severity))
                        + '</td><td class="mono">' + item.port + '</td></tr>';
                }).join('');
                UI.drawer.open('Web 应用漏扫结果：' + UI.esc(url),
                    '<div class="hint">站点标题：' + UI.esc(info.title || '-')
                    + ' ｜ Server：' + UI.esc(info.server || '-')
                    + ' ｜ X-Powered-By：' + UI.esc(info.powered_by || '-') + '</div>'
                    + '<div class="hint">登录态探测：' + (info.logged_in ? '成功（已带会话扫描）' : '未登录/未启用')
                    + ' ｜ 爬取页面：' + (info.pages_scanned || 0)
                    + ' ｜ 检查项：' + (info.checks || 0)
                    + ' ｜ 耗时：' + (info.duration_sec || 0) + 's</div>'
                    + '<div class="hint">' + UI.esc(info.note
                        || '所有结论均带 HTTP 证据（状态码 + 响应特征），只做只读探测。') + '</div>'
                    + (rows ? '<div class="table-wrap"><table class="grid-table"><thead><tr>'
                        + '<th>编号</th><th>标题</th><th>级别</th><th>端口</th></tr></thead><tbody>'
                        + rows + '</tbody></table></div>'
                        : '<div class="hint">未发现可确认的漏洞（通用检查项均未命中）。</div>'));
                loadVulns();
                loadSummary();
                loadCounters();
            }).catch(function (error) {
                UI.toast('漏扫失败：' + error.message, true);
            }).then(function () {
                button.disabled = false;
                button.textContent = 'Web 漏扫';
            });
        });

        document.getElementById('btnExportVulns').addEventListener('click', function () {
            var rows = filterItems();
            if (!rows.length) {
                UI.toast('暂无可导出的漏洞', true);
                return;
            }
            var csv = [['CVE', '标题', '主机', '端口', '服务', 'CVSS', '级别', '状态',
                '修复版本', '修复建议', '发现时间']];
            rows.forEach(function (item) {
                csv.push([item.cve, item.title, item.asset_ip, item.port, item.service, item.cvss,
                    UI.sevText(item.severity), UI.vulnStatusText(item.status), item.fixed_version,
                    item.recommendation, item.found_at]);
            });
            UI.csv('vulnerabilities-' + Date.now() + '.csv', csv);
        });

        UI.delegate(document, '[data-vuln-detail]', 'click', function (event, target) {
            openDetail(Number(target.getAttribute('data-vuln-detail')));
        });

        UI.delegate(document, '[data-vuln-ai]', 'click', function (event, target) {
            // 页面上所有「AI 建议 / 生成 / 重新生成」按钮都走强制重生成：
            // 用户点它就是想拿一份新的，命中旧结果等于没反应
            if (target.getAttribute('data-busy') === '1') { return; }
            var label = target.textContent;
            target.setAttribute('data-busy', '1');
            target.textContent = '请求中…';
            requestAiAdvice(Number(target.getAttribute('data-vuln-ai')), true).then(function () {
                // 抽屉与列表多半已重绘，旧节点可能已脱离文档，恢复失败也无影响
                target.removeAttribute('data-busy');
                target.textContent = label;
            });
        });

        UI.delegate(document, '[data-vuln-status]', 'click', function (event, target) {
            var id = Number(target.getAttribute('data-vuln-id'));
            var status = target.getAttribute('data-vuln-status');
            SecApi.updateVulnStatus(id, status).then(function (result) {
                UI.toast(result.message, !result.success);
                UI.drawer.close();
                loadVulns();
                loadSummary();
                loadCounters();
            }).catch(function (error) { UI.toast('更新失败：' + error.message, true); });
        });
    }

    function start() {
        bind();
        UI.boot('vuln');
        loadVulns();
        loadSummary();
        loadCounters();
        loadWebKb();
        loadJobs();
        setInterval(function () { loadVulns(); loadSummary(); loadCounters(); }, 15000);
        setInterval(loadJobs, 5000);
    }

    global.SecVulnPage = { start: start };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})(window);


