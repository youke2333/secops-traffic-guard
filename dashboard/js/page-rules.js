/**
 * page-rules.js —— 规则包 / 档位 / 匹配引擎（v6 P2）
 *
 * 只展示可观测状态与两个安全开关（档位、后端）；自定义规则上传属于 P5，
 * 服务端尚未开放写接口，页面不提供“看起来能用但实际失败”的按钮。
 */
(function (global) {
    'use strict';

    var packs = null;
    var engine = null;

    function el(id) { return document.getElementById(id); }

    function applyRole() {
        var role = (SecApi.user && SecApi.user.role) || 'viewer';
        var admin = role === 'admin';
        ['btnApplyTiers', 'btnApplyBackend', 'btnReload'].forEach(function (id) {
            var node = el(id);
            if (node) {
                node.disabled = !admin;
                node.title = admin ? '' : '需要 admin 角色';
            }
        });
        if (!admin) {
            el('tierHint').textContent = '当前账号为 ' + role + '，只能查看规则状态。';
        }
        var panel = el('userPanel');
        if (panel) { panel.classList.toggle('hidden', !admin); }
    }

    function packRow(item) {
        var tiers = item.by_tier || {};
        var tierText = Object.keys(tiers).map(function (key) {
            return key + ' ' + tiers[key];
        }).join(' / ') || '-';
        var selected = item.selected === undefined ? '-' : item.selected;
        var skipped = item.skipped_tier !== undefined
            ? (item.skipped_tier + ' 档位 / ' + (item.skipped_unknown || 0) + ' 类别')
            : '-';
        return '<tr>'
            + '<td><b>' + UI.esc(item.pack) + '</b><br><span class="hint">'
            + UI.esc(item.engine || '') + '</span></td>'
            + '<td class="num">' + UI.esc(item.count) + '</td>'
            + '<td>' + UI.esc(tierText) + '</td>'
            + '<td class="num">' + UI.esc(selected) + '</td>'
            + '<td>' + UI.esc(skipped) + (item.error ? '<br><span class="hint">' + UI.esc(item.error) + '</span>' : '') + '</td>'
            + '<td>' + (item.enabled ? '<span class="tag-chip tier-core">启用</span>' : '<span class="hint">未启用</span>') + '</td>'
            + '<td class="mono" title="' + UI.esc(item.checksum) + '">' + UI.esc(item.version || '-')
            + '<br><span class="hint">' + UI.esc((item.checksum || '').slice(0, 12)) + '</span></td>'
            + '</tr>';
    }

    function render() {
        var web = (packs && packs.web_kb) || {};
        var matcher = (engine && engine.matcher) || web.matcher || {};
        UI.setText('kRules', UI.fmt.count(web.rules || (engine && engine.rules) || 0));
        UI.setText('kBackend', engine ? engine.backend : '-');
        UI.setText('kCompile', ((engine && engine.compile_ms) || 0).toFixed(1) + ' ms');
        UI.setText('kFallback', UI.fmt.count((matcher.matcher_fallback_rules || 0)));
        UI.setText('kTiers', (packs && (packs.tiers_enabled || []).join(',')) || '-');
        UI.setText('kShadow', packs && packs.shadow_mode ? '开启（只记录）' : '关闭');

        var body = el('packBody');
        body.innerHTML = (packs && packs.packs || []).map(packRow).join('')
            || '<tr><td colspan="7" class="empty-row">规则包目录不可用</td></tr>';

        var hints = [];
        hints.push('matcher=' + ((matcher.matcher_backend) || 'python')
            + '，patterns=' + (matcher.matcher_patterns || 0)
            + '，scan=' + (matcher.scan_us_avg || 0) + ' µs/请求');
        if (web.duplicates) { hints.push('pattern 去重 ' + web.duplicates + ' 条'); }
        if (web.skipped_unknown) { hints.push('未知类别跳过 ' + web.skipped_unknown + ' 条（需修分类表）'); }
        if (matcher.error) { hints.push('RE2 错误：' + matcher.error); }
        el('engineHint').textContent = hints.join('；');

        var selected = (packs && packs.tiers_enabled) || [];
        document.querySelectorAll('.tierBox').forEach(function (box) {
            box.checked = selected.indexOf(box.value) >= 0;
        });
        el('chkShadow').checked = Boolean(packs && packs.shadow_mode);
        if (engine) {
            el('backendSelect').value = engine.configured_backend || 'auto';
            var fallback = (engine.fallback_rules || []).map(function (idx) {
                return '#' + idx;
            });
            el('fallbackBox').textContent = fallback.length
                ? '降级为逐条精匹配的规则索引：' + fallback.join(', ')
                : '无降级规则';
        }
    }

    function userRow(item) {
        var role = '<select class="input" data-user-role="' + item.id + '">'
            + ['viewer', 'analyst', 'admin'].map(function (value) {
                return '<option value="' + value + '"' + (item.role === value ? ' selected' : '') + '>'
                    + value + '</option>';
            }).join('') + '</select>';
        return '<tr>'
            + '<td class="num">' + item.id + '</td>'
            + '<td class="mono">' + UI.esc(item.username) + '</td>'
            + '<td>' + role + '</td>'
            + '<td>' + (item.active ? '<span class="tag-chip tier-core">启用</span>' : '<span class="hint">已停用</span>')
            + (item.must_change_password ? '<span class="hint"> 待改密</span>' : '') + '</td>'
            + '<td>' + UI.esc(item.last_login_at ? UI.fmt.time(item.last_login_at) : '-') + '</td>'
            + '<td><div class="actions">'
            + '<button class="btn-mini" type="button" data-user-save="' + item.id + '">保存角色</button>'
            + '<button class="btn-mini" type="button" data-user-reset="' + item.id + '">重置密码</button>'
            + (item.active
                ? (item.id === (SecApi.user && SecApi.user.id) ? ''
                    : '<button class="btn-mini" type="button" data-user-disable="' + item.id + '">停用</button>')
                : '<button class="btn-mini" type="button" data-user-enable="' + item.id + '">重新启用</button>')
            + '</div></td></tr>';
    }

    function loadUsers() {
        if (!SecApi.user || SecApi.user.role !== 'admin') { return; }
        return SecApi.users().then(function (data) {
            var body = el('userBody');
            if (!body) { return; }
            body.innerHTML = (data.items || []).map(userRow).join('')
                || '<tr><td colspan="6" class="empty-row">暂无用户</td></tr>';
        }).catch(function (error) {
            UI.toast('用户列表加载失败：' + error.message, true);
        });
    }

    function createUser() {
        var payload = {
            username: el('newUsername').value.trim(),
            display_name: el('newDisplayName').value.trim(),
            password: el('newPassword').value,
            role: el('newRole').value
        };
        if (!payload.username || !payload.password) {
            UI.toast('请填写用户名与初始密码', true);
            return;
        }
        SecApi.createUser(payload).then(function (result) {
            UI.toast(result.message);
            ['newUsername', 'newDisplayName', 'newPassword'].forEach(function (id) { el(id).value = ''; });
            loadUsers();
        }).catch(function (error) { UI.toast('创建失败：' + error.message, true); });
    }

    function bindUsers() {
        el('btnCreateUser').addEventListener('click', createUser);
        el('btnRefreshUsers').addEventListener('click', loadUsers);
        UI.delegate('#userBody', '[data-user-save]', 'click', function (_event, node) {
            var id = node.getAttribute('data-user-save');
            var select = document.querySelector('[data-user-role="' + id + '"]');
            SecApi.updateUser(id, { role: select.value }).then(function (result) {
                UI.toast(result.message);
                loadUsers();
            }).catch(function (error) { UI.toast('更新失败：' + error.message, true); });
        });
        UI.delegate('#userBody', '[data-user-reset]', 'click', function (_event, node) {
            var id = node.getAttribute('data-user-reset');
            UI.confirm('重置该用户密码？旧密码立即失效，所有会话被踢出。', function () {
                SecApi.resetUserPassword(id).then(function (result) {
                    var password = (result.detail || {}).temporary_password || '';
                    UI.toast('新临时密码：' + password + '（只显示一次）');
                    loadUsers();
                }).catch(function (error) { UI.toast('重置失败：' + error.message, true); });
            });
        });
        UI.delegate('#userBody', '[data-user-disable]', 'click', function (_event, node) {
            var id = node.getAttribute('data-user-disable');
            UI.confirm('停用该用户？记录会保留以便审计。', function () {
                SecApi.disableUser(id).then(function (result) {
                    UI.toast(result.message);
                    loadUsers();
                }).catch(function (error) { UI.toast('停用失败：' + error.message, true); });
            });
        });
        UI.delegate('#userBody', '[data-user-enable]', 'click', function (_event, node) {
            var id = node.getAttribute('data-user-enable');
            UI.confirm('重新启用该用户？对方需重新登录，原密码仍然有效。', function () {
                SecApi.updateUser(id, { active: true }).then(function (result) {
                    UI.toast(result.message);
                    loadUsers();
                }).catch(function (error) { UI.toast('启用失败：' + error.message, true); });
            });
        });
    }

    function load() {
        return Promise.all([SecApi.rulePacks(), SecApi.ruleEngine()]).then(function (result) {
            packs = result[0];
            engine = result[1];
            applyRole();
            render();
        }).catch(function (error) {
            UI.toast('规则状态加载失败：' + error.message, true);
            el('engineHint').textContent = '加载失败：' + error.message;
        });
    }

    function bind() {
        el('btnRefresh').addEventListener('click', load);
        el('btnReload').addEventListener('click', function () {
            UI.confirm('重载会重建规则索引；构建完成前检测继续使用旧快照。继续？', function () {
                SecApi.reloadRules().then(function (result) {
                    UI.toast(result.message);
                    load();
                }).catch(function (error) { UI.toast('重载失败：' + error.message, true); });
            });
        });
        el('btnApplyTiers').addEventListener('click', function () {
            var tiers = Array.prototype.slice.call(document.querySelectorAll('.tierBox:checked'))
                .map(function (box) { return box.value; });
            if (!tiers.length) {
                UI.toast('至少保留一个档位', true);
                return;
            }
            var shadow = el('chkShadow').checked;
            UI.confirm('确认应用档位 ' + tiers.join(',') + (shadow ? '，并开启影子模式' : '') + '？', function () {
                SecApi.updateRuleTiers(tiers, shadow).then(function (result) {
                    UI.toast(result.message);
                    load();
                }).catch(function (error) { UI.toast('档位更新失败：' + error.message, true); });
            });
        });
        el('btnApplyBackend').addEventListener('click', function () {
            var backend = el('backendSelect').value;
            UI.confirm('切换匹配后端为 ' + backend + '？切换会重建索引。', function () {
                SecApi.switchBackend(backend).then(function (result) {
                    UI.toast(result.message);
                    load();
                }).catch(function (error) { UI.toast('切换失败：' + error.message, true); });
            });
        });
    }

    function start() {
        UI.boot('rules');
        bind();
        bindUsers();
        // UI.boot 内部异步取身份；这里再等一次 ensureAuth，避免以 viewer 身份渲染 admin 区域
        SecApi.ensureAuth().then(function () {
            load();
            loadUsers();
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
    global.RulesPage = { load: load };
})(window);

