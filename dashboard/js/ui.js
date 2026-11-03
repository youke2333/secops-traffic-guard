/**
 * ui.js —— 子页面共享工具库
 *
 * 五个模块页面（流量监控 / 异常检测 / 封禁告警 / 漏洞提醒 / 资产管理）共用：
 *   * 统一顶部导航（模块切换）
 *   * 统一的数值格式化、等级配色、中文文案
 *   * 统一样式的抽屉（详情面板）、轻提示、确认框、CSV 导出
 * 目的：页面只写"业务渲染 + 处置动作"，避免五份复制粘贴的样板代码。
 */
(function (global) {
    'use strict';

    var MODULES = [
        { id: 'overview', name: '监控大屏', href: 'index.html', desc: '全景态势总览' },
        { id: 'traffic', name: '流量监控', href: 'traffic.html', desc: '带宽/包速率/会话' },
        { id: 'threat', name: '威胁告警', href: 'threat.html', desc: '可疑流量明细与证据' },
        { id: 'block', name: '封禁管理', href: 'block.html', desc: '封禁/白名单/报告' },
        { id: 'anomaly', name: '异常端口', href: 'anomaly.html', desc: '端口基线与信号' },
        { id: 'rules', name: '规则管理', href: 'rules.html', desc: '规则包/引擎/档位' },
        { id: 'vuln', name: '漏洞提醒', href: 'vuln.html', desc: 'CVE 与修复建议' },
        { id: 'asset', name: '资产管理', href: 'asset.html', desc: '台账与指纹' },
        { id: 'cloud', name: '云端协同', href: 'cloud.html', desc: '云端归档/证据存储/AI 简报' }
    ];

    /* 网络安全标准配色（与等保 / 态势感知通行色标对齐）：
       红=紧急、橙=高危、黄=中危、蓝=低危、绿=正常/安全。
       页面上所有"异常"标记（等级徽标、风险点、越限数值）统一取这套颜色。 */
    var SEVERITY_COLOR = {
        critical: '#e53935',   // 红
        high: '#fb8c00',       // 橙
        medium: '#fdd835',     // 黄
        low: '#4fc3f7',        // 蓝
        info: '#4fc3f7',       // 蓝色提示
        safe: '#43a047'        // 绿（正常）
    };
    var SEVERITY_TEXT = { critical: '紧急', high: '高危', medium: '中危', low: '低危' };
    var CATEGORY_TEXT = {
        port_scan: '端口扫描探测',
        brute_force: '认证端口暴力破解',
        nonstandard_port: '非标准端口高频访问',
        traffic_spike: '突发流量峰值',
        behavior_anomaly: '多维行为异常(ML)',
        manual: '人工封禁',
        /* Web 攻击检测（知识库 backend/data/web_attack_rules.json，17 大类） */
        web_sql_injection: 'Web-SQL 注入',
        web_sql_injection_blind: 'Web-SQL 盲注',
        web_xss_reflected: 'Web-反射型 XSS',
        web_xss_stored: 'Web-存储型 XSS',
        web_command_injection: 'Web-命令注入',
        web_file_inclusion: 'Web-文件包含',
        web_file_upload: 'Web-恶意文件上传',
        web_brute_force: 'Web-暴力破解',
        web_csrf: 'Web-CSRF',
        web_insecure_captcha: 'Web-不安全验证码',
        web_path_traversal: 'Web-目录穿越',
        web_ssrf: 'Web-SSRF',
        web_xxe: 'Web-XXE',
        web_webshell: 'Web-Webshell 访问',
        web_ssti: 'Web-模板注入',
        web_ldap_nosql_injection: 'Web-LDAP/NoSQL 注入',
        web_crlf_injection: 'Web-CRLF 注入',
        /* 规则包新增类别（v6） */
        web_scanner_fingerprint: '扫描器指纹',
        web_recon_scan: '资产侦察',
        web_deserialization: '反序列化攻击',
        web_protocol_anomaly: '协议异常',
        web_ddos_flood: 'DDoS 洪泛',
        web_dns_tunnel: 'DNS 隧道',
        web_crypto_mining: '挖矿行为',
        web_c2_beacon: 'C2 通信',
        web_api_abuse: '接口滥用'
    };
    var STATUS_TEXT = {
        block: '封禁', unblock: '解封', extend: '封禁续期', whitelist_add: '白名单新增',
        whitelist_remove: '白名单移除', scan: '漏洞扫描'
    };
    var VULN_STATUS_TEXT = { open: '待修复', fixing: '修复中', fixed: '已修复', ignored: '已忽略' };
    var RISK_TEXT = { critical: '紧急', high: '高危', medium: '中危', low: '低危', unknown: '未知' };

    function pad(value) {
        return (value < 10 ? '0' : '') + value;
    }

    /* -------------------- 攻击特征识别（用于详情/报告里的红色高亮） --------------------
     * 设计取舍：
     *   * 只收录「几乎不会出现在正常业务文本里」的特征（/etc/passwd、union select、
     *     <script、../..、${jndi: 等），避免把普通英文单词刷成红色；
     *   * 命令类要求带分隔符（; | && ` $()）或指向敏感路径，避免误伤 "id / ls" 等普通词；
     *   * 全部用非捕获组，正则整体编译一次（模块加载时），单条请求体匹配开销可忽略。
     * 匹配在「原始文本」上做，命中片段逐段转义 —— 与整串转义结果完全一致，
     * 因此不会破坏 HTML 结构，也不会漏转义。 */
    var ATK_RULES = [
        /* ---- 命令执行 / 敏感文件读取 ---- */
        '(?:cat|tac|head|tail|more|less|nl|strings)\\s+(?:-\\w+\\s+)*(?:\\/etc\\/|\\/proc\\/|[A-Za-z]:\\\\Windows)',
        '\\/etc\\/(?:passwd|shadow|group|sudoers|hosts|issue|motd)',
        '\\betc\\/(?:passwd|shadow|group|sudoers)',
        '\\/proc\\/self\\/(?:environ|cmdline|status|maps)',
        '(?:[;|]|&&|\\|\\|)\\s{0,3}(?:cat|ls|id|whoami|uname|pwd|hostname|ifconfig|ipconfig|netstat|wget|curl|nc|ncat|netcat|socat|bash|sh|zsh|cmd|powershell|python|perl|php|chmod|chown|rm|mv|cp|echo|touch|base64|telnet|ftp|scp|ssh|ping|sleep|nslookup|dig|reg|net|kill|ps)\\b(?![=\\w-])',
        '\\$\\s*\\([^)\\n]{0,80}\\)',
        '`[^`\\n]{1,80}`',
        '(?:nc|ncat|netcat)\\s+-\\w*e\\b',
        '\\/bin\\/(?:ba|z|da)?sh\\b',
        '\\/dev\\/tcp\\/',
        'mkfifo',
        'base64\\s+(?:-d|--decode)',
        'cmd\\.exe',
        'powershell(?:\\.exe)?\\s+-\\w',
        'net\\s+(?:user|localgroup|group)\\b',
        'whoami\\b',
        'uname\\s+-a',
        '(?:wget|curl)\\s+(?:-\\w+\\s+)*https?:\\/\\/',

        /* ---- SQL 注入 ---- */
        '\\b(?:union\\s+(?:all\\s+)?)?select\\b[\\s\\S]{0,80}?\\bfrom\\b',
        'union\\s+(?:all\\s+)?select',
        "['\"]\\s*(?:or|and)\\s+['\"]?\\d",
        '\\b(?:or|and)\\b\\s+\\d+\\s*=\\s*\\d+',
        '\\b(?:or|and)\\b\\s+\\d+\\s*>\\s*\\d+',
        '\\b(?:or|and)\\b\\s+(?:exists|ascii|char|substr|substring|length|sleep|benchmark|if|version|database|user)\\s*\\(',
        '\\b1\\s*=\\s*1\\b',
        'sleep\\s*\\(\\s*\\d+',
        'benchmark\\s*\\(',
        'pg_sleep\\s*\\(',
        'waitfor\\s+delay',
        'information_schema',
        'xp_cmdshell',
        'load_file\\s*\\(',
        'into\\s+(?:out|dump)file',
        'updatexml\\s*\\(',
        'extractvalue\\s*\\(',
        'group_concat\\s*\\(',
        '\\b(?:drop|truncate)\\s+table\\b',
        '\\bdelete\\s+from\\b',
        '\\binsert\\s+into\\b',

        /* ---- XSS / 脚本注入 ---- */
        '<\\/?script\\b',
        '<svg\\b',
        '<iframe\\b',
        '<img[^>]{0,80}on\\w+\\s*=',
        'javascript\\s*:',
        'on(?:error|load|click|mouseover|focus|submit)\\s*=',
        'document\\.cookie',
        'fromCharCode',
        'alert\\s*\\((?=\\s*[\\d\'"])',
        'eval\\s*\\(',

        /* ---- 目录穿越 / 文件包含 ---- */
        '(?:\\.\\.\\/){2,}',
        '(?:\\.\\.\\\\){2,}',
        '(?:%2e%2e)(?:%2f|\\/)',
        '\\.\\.%2f',
        'php://(?:input|filter)',
        'phar://',
        'expect://',

        /* ---- 其他常见攻击面 ---- */
        '\\$\\{jndi:',
        '\\$\\{(?:[^{}]{1,40})\\}',
        '\\{\\{[\\s\\S]{1,40}?\\}\\}',
        'phpinfo\\s*\\(',
        'shell_exec',
        'passthru\\s*\\(',
        'system\\s*\\(',
        'assert\\s*\\(',
        '(?:^|[?&;])(?:cmd|exec|shell)\\s*=',
        '%0d%0a',
        '%00',
        '<!ENTITY',
        '\\$(?:ne|gt|gte|lt|where|regex|nin)\\b'
    ];
    var ATK_RE = new RegExp(ATK_RULES.join('|'), 'gim');

    /* URL 解码 + 位置映射：WAF/代理日志里的载荷基本是 URL 编码的，
       直接匹配原文会漏标，这里解码后再匹配、再映射回原文区间。 */
    function pctDecode(text) {
        var out = '', map = [], total = text.length, index = 0;
        while (index < total) {
            var char = text.charAt(index);
            if (char === '%' && index + 2 < total) {
                var pair = text.substr(index + 1, 2);
                if (/^[0-9a-fA-F]{2}$/.test(pair)) {
                    out += String.fromCharCode(parseInt(pair, 16));
                    map.push(index);
                    index += 3;
                    continue;
                }
            }
            if (char === '+') {
                out += ' ';
                map.push(index);
                index += 1;
                continue;
            }
            out += char;
            map.push(index);
            index += 1;
        }
        map.push(total);
        return { text: out, map: map };
    }

    function matchSpans(text) {
        var spans = [];
        var match;
        ATK_RE.lastIndex = 0;
        while ((match = ATK_RE.exec(text)) !== null) {
            if (!match[0].length) { ATK_RE.lastIndex += 1; continue; }
            spans.push([match.index, match.index + match[0].length]);
        }
        return spans;
    }

    /** 所有需要高亮的区间（原文坐标），已排序并合并重叠部分。 */
    function attackSpans(text) {
        var spans = matchSpans(text);
        if (text.indexOf('%') >= 0 || text.indexOf('+') >= 0) {
            var decoded = pctDecode(text);
            if (decoded.text !== text) {
                matchSpans(decoded.text).forEach(function (span) {
                    var start = decoded.map[span[0]];
                    var end = decoded.map[span[1]];
                    if (end > start) { spans.push([start, end]); }
                });
            }
        }
        spans.sort(function (a, b) { return a[0] - b[0]; });
        var merged = [];
        spans.forEach(function (span) {
            var previous = merged[merged.length - 1];
            if (previous && span[0] <= previous[1]) {
                previous[1] = Math.max(previous[1], span[1]);
            } else {
                merged.push([span[0], span[1]]);
            }
        });
        return merged;
    }

    var UI = {
        MODULES: MODULES,
        SEVERITY_COLOR: SEVERITY_COLOR,
        SEVERITY_TEXT: SEVERITY_TEXT,
        SAFE_COLOR: SEVERITY_COLOR.safe,

        /* -------------------- 安全色研判 --------------------
         * 把"占用率 / 风险分"这类 0~100 的数值映射到标准色标，
         * 供硬件资源图、风险指数等"越限即异常"的场景统一着色。 */
        loadColor: function (percent, thresholds) {
            var value = Number(percent);
            if (!isFinite(value)) { return '#8fa9c4'; }
            var high = (thresholds && thresholds.high) || 85;
            var medium = (thresholds && thresholds.medium) || 70;
            var low = (thresholds && thresholds.low) || 50;
            if (value >= high) { return SEVERITY_COLOR.critical; }
            if (value >= medium) { return SEVERITY_COLOR.high; }
            if (value >= low) { return SEVERITY_COLOR.medium; }
            return SEVERITY_COLOR.safe;
        },
        loadLevel: function (percent, thresholds) {
            var color = UI.loadColor(percent, thresholds);
            /* 等级名与色板变量同名，避免"橙=medium"这类错位 */
            var map = {};
            map[SEVERITY_COLOR.critical] = 'critical';
            map[SEVERITY_COLOR.high] = 'high';
            map[SEVERITY_COLOR.medium] = 'medium';
            map[SEVERITY_COLOR.low] = 'low';
            map[SEVERITY_COLOR.safe] = 'safe';
            return map[color] || 'low';
        },
        /** 越限标签："异常"（红/橙）/ "正常"（绿），用于表格与 KPI 的异常标注 */
        abnTag: function (percent, thresholds) {
            var value = Number(percent);
            if (percent === null || percent === undefined || percent === '' || !isFinite(value)) {
                return '<span class="abn-tag unknown">--</span>';
            }
            var level = UI.loadLevel(value, thresholds);
            var text = level === 'safe' ? '正常' : '异常';
            return '<span class="abn-tag ' + level + '" style="--abn:'
                + UI.loadColor(value, thresholds) + '">' + text + '</span>';
        },

        /* -------------------- 格式化 -------------------- */
        fmt: {
            bps: function (value) {
                if (!value) { return '0 bps'; }
                if (value >= 1e9) { return (value / 1e9).toFixed(2) + ' Gbps'; }
                if (value >= 1e6) { return (value / 1e6).toFixed(2) + ' Mbps'; }
                if (value >= 1e3) { return (value / 1e3).toFixed(1) + ' Kbps'; }
                return Math.round(value) + ' bps';
            },
            pps: function (value) {
                var number = Number(value || 0);
                if (number >= 10000) { return (number / 10000).toFixed(2) + ' 万pps'; }
                return number.toFixed(number >= 100 ? 0 : 1) + ' pps';
            },
            bytes: function (value) {
                var size = Number(value || 0);
                var units = ['B', 'KB', 'MB', 'GB', 'TB'];
                var index = 0;
                while (size >= 1024 && index < units.length - 1) { size /= 1024; index += 1; }
                return size.toFixed(index === 0 ? 0 : 2) + ' ' + units[index];
            },
            count: function (value) {
                var number = Number(value || 0);
                if (number >= 100000000) { return (number / 100000000).toFixed(2) + ' 亿'; }
                if (number >= 10000) { return (number / 10000).toFixed(2) + ' 万'; }
                return String(Math.round(number));
            },
            duration: function (seconds) {
                var total = Math.max(0, Math.round(Number(seconds || 0)));
                if (total >= 3600) { return Math.floor(total / 3600) + 'h' + pad(Math.floor(total % 3600 / 60)) + 'm'; }
                if (total >= 60) { return Math.floor(total / 60) + 'm' + pad(total % 60) + 's'; }
                return total + 's';
            },
            time: function (value) {
                if (value === null || value === undefined || value === '') { return '-'; }
                // 1) 数字（或 10/13 位纯数字串）= Unix 秒 / 毫秒时间戳，换算成本地时间
                var raw = String(value).trim();
                if (typeof value === 'number' || /^\d{10}$|^\d{13}$/.test(raw)) {
                    var epoch = Number(value);
                    if (isFinite(epoch) && epoch > 0) {
                        return UI.fmt.dateTime(new Date(epoch > 1e12 ? epoch : epoch * 1000));
                    }
                }
                // 2) 带时区标记的 ISO 串（后端若输出 UTC 会带 Z / +08:00）：换算成本地时间再展示，
                //    避免"大屏时钟是对的、事件时间却早 8 小时"
                if (/[zZ]$/.test(raw) || /[+-]\d{2}:?\d{2}$/.test(raw)) {
                    var parsed = new Date(raw);
                    if (!isNaN(parsed.getTime())) { return UI.fmt.dateTime(parsed); }
                }
                // 3) 无时区的 naive 串：库里存的就是本地时间，原样展示
                var text = raw.replace('T', ' ');
                return text.length >= 19 ? text.slice(0, 19) : text;
            },
            dateTime: function (date) {
                return date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' + pad(date.getDate())
                    + ' ' + pad(date.getHours()) + ':' + pad(date.getMinutes()) + ':' + pad(date.getSeconds());
            },
            clockTime: function (value) {
                var text = UI.fmt.time(value);
                return text.length >= 19 ? text.slice(11, 19) : text;
            }
        },

        /* -------------------- 文案与配色 -------------------- */
        sevColor: function (severity) { return SEVERITY_COLOR[severity] || '#febe12'; },
        sevText: function (severity) { return SEVERITY_TEXT[severity] || severity || '未知'; },
        catText: function (category) { return CATEGORY_TEXT[category] || category || '-'; },
        statusText: function (action) { return STATUS_TEXT[action] || action; },
        vulnStatusText: function (status) { return VULN_STATUS_TEXT[status] || status; },
        riskText: function (level) { return RISK_TEXT[level] || level; },

        esc: function (text) {
            return String(text === undefined || text === null ? '' : text)
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        },
        pill: function (text, color) {
            return '<span class="pill" style="border-color:' + color + ';color:' + color + '">'
                + UI.esc(text) + '</span>';
        },
        badge: function (text, color) {
            return '<span class="solid-pill" style="background:' + (color || '#00d8ff') + '">'
                + UI.esc(text) + '</span>';
        },
        setText: function (id, text) {
            var node = document.getElementById(id);
            if (node) { node.textContent = text; }
        },
        setHtml: function (id, html) {
            var node = document.getElementById(id);
            if (node) { node.innerHTML = html; }
        },

        /* ---- 攻击特征高亮 ----
         * 把文本按攻击特征切段：命中片段包成 <mark class="atk">，其余照常转义。
         * 返回的是可直接 innerHTML 的安全 HTML；未命中时等价于 UI.esc(text)。
         * URL 编码载荷（%27%20union%20select）会先解码再匹配，再映射回原文区间，
         * 因此高亮覆盖的是日志里的原始文本，渲染内容一字不改。 */
        hl: function (text) {
            var raw = String(text === undefined || text === null ? '' : text);
            if (!raw) { return ''; }
            var spans = attackSpans(raw);
            if (!spans.length) { return UI.esc(raw); }   /* 没命中：走原路径，零额外开销 */
            var out = '';
            var last = 0;
            for (var i = 0; i < spans.length; i += 1) {
                var start = spans[i][0];
                var end = spans[i][1];
                if (start > last) { out += UI.esc(raw.slice(last, start)); }
                out += '<mark class="atk">' + UI.esc(raw.slice(start, end)) + '</mark>';
                last = end;
            }
            return out + UI.esc(raw.slice(last));
        },

        /* ---- 是否存在攻击特征（用于详情页给出「已标注 N 处特征」提示） ---- */
        hasAttack: function (text) {
            var raw = String(text === undefined || text === null ? '' : text);
            return Boolean(raw) && attackSpans(raw).length > 0;
        },

        /* -------------------- 功能页签：每页只展示一个功能 --------------------
         * 用法：页面只要在段落容器上加 data-tab="功能名"，多段同名即归入同一页签
         *      （例如"筛选"与"事件列表"同属"事件检索"）。页面无需引入任何框架代码。
         * 行为：自动生成页签条、记住上次停留的功能、切换后重算图表尺寸。 */
        tabs: {
            KEY: 'secops.tab:',
            current: '',
            titleOf: function (node) {
                var head = node.querySelector('h2');
                if (!head) { return ''; }
                /* 去掉"模块 3.1"之类编号前缀，只留功能名 */
                return head.textContent.replace(/^模块\s*[\d.]+\s*/, '').trim();
            },
            init: function () {
                var host = document.querySelector('.page-body');
                if (!host || host.getAttribute('data-tabs') === 'off') { return; }
                if (document.getElementById('funcTabs')) { return; }

                var units = [];
                Array.prototype.forEach.call(host.children, function (node) {
                    if (node.nodeType !== 1) { return; }
                    if (node.classList.contains('tab-bar')) { return; }
                    /* 一个功能单元 = 一个 panel，或包含 panel 的栅格容器（grid-2 / rule-grid 等） */
                    if (!node.classList.contains('panel') && !node.querySelector('.panel')) { return; }
                    if (node.classList.contains('hidden')) { return; }   /* 无权限的面板不占页签 */
                    units.push(node);
                });
                if (units.length < 2) { return; }                        /* 单功能页面不需要页签 */

                var labels = [];
                units.forEach(function (node, index) {
                    var label = node.getAttribute('data-tab') || UI.tabs.titleOf(node)
                        || ('功能 ' + (index + 1));
                    node.setAttribute('data-tab-pane', label);
                    if (labels.indexOf(label) < 0) { labels.push(label); }
                });
                if (labels.length < 2) { return; }

                var bar = document.createElement('div');
                bar.className = 'tab-bar func-tabs';
                bar.id = 'funcTabs';
                bar.setAttribute('role', 'tablist');
                bar.innerHTML = labels.map(function (label) {
                    return '<button class="tab-btn" type="button" role="tab"'
                        + ' data-tab-target="' + UI.esc(label) + '">' + UI.esc(label) + '</button>';
                }).join('');
                host.insertBefore(bar, units[0]);
                bar.addEventListener('click', function (event) {
                    var button = event.target.closest ? event.target.closest('[data-tab-target]') : null;
                    if (button) { UI.tabs.activate(button.getAttribute('data-tab-target')); }
                });

                var saved = '';
                try {
                    saved = global.sessionStorage.getItem(UI.tabs.KEY + global.location.pathname) || '';
                } catch (error) { saved = ''; }
                UI.tabs.activate(labels.indexOf(saved) >= 0 ? saved : labels[0]);
                /* 鉴权结果晚于页面初始化时，非管理员面板会被追加 hidden —— 稍后再校一次 */
                setTimeout(UI.tabs.refresh, 700);
            },
            activate: function (label) {
                if (!label) { return; }
                UI.tabs.current = label;
                Array.prototype.forEach.call(document.querySelectorAll('[data-tab-pane]'), function (node) {
                    node.classList.toggle('tab-pane-hidden',
                        node.getAttribute('data-tab-pane') !== label);
                });
                Array.prototype.forEach.call(
                    document.querySelectorAll('#funcTabs [data-tab-target]'), function (button) {
                        var on = button.getAttribute('data-tab-target') === label;
                        button.classList.toggle('active', on);
                        button.setAttribute('aria-selected', on ? 'true' : 'false');
                    });
                try {
                    global.sessionStorage.setItem(UI.tabs.KEY + global.location.pathname, label);
                } catch (error) { /* 隐私模式忽略 */ }
                /* 隐藏容器里的 ECharts 尺寸为 0，切回来后必须重算（多补两帧防抖动） */
                UI.resizeCharts();
                setTimeout(UI.resizeCharts, 80);
                setTimeout(UI.resizeCharts, 260);
            },
            refresh: function () {
                var bar = document.getElementById('funcTabs');
                if (!bar) { return; }
                var visible = {};
                Array.prototype.forEach.call(document.querySelectorAll('[data-tab-pane]'), function (node) {
                    var label = node.getAttribute('data-tab-pane');
                    if (!node.classList.contains('hidden')) { visible[label] = true; }
                });
                Array.prototype.forEach.call(bar.querySelectorAll('[data-tab-target]'), function (button) {
                    button.classList.toggle('hidden', !visible[button.getAttribute('data-tab-target')]);
                });
                if (!visible[UI.tabs.current]) {
                    var first = Object.keys(visible)[0];
                    if (first) { UI.tabs.activate(first); }
                }
            }
        },

        /* -------------------- 图表尺寸重算（页签切换后调用） -------------------- */
        resizeCharts: function () {
            if (!global.echarts || !global.echarts.getInstanceByDom) { return; }
            Array.prototype.forEach.call(
                document.querySelectorAll('.chart, .chart-box, [id^="chart"], [id^="res"]'), function (node) {
                    var instance = global.echarts.getInstanceByDom(node);
                    if (instance && !(instance.isDisposed && instance.isDisposed())) {
                        try { instance.resize(); } catch (error) { /* 已销毁的实例忽略 */ }
                    }
                });
        },

        /* -------------------- 顶部导航 -------------------- */
        nav: function (active) {
            var box = document.getElementById('nav');
            if (!box) { return; }
            box.innerHTML = MODULES.map(function (item) {
                var cls = item.id === active ? 'nav-item active' : 'nav-item';
                return '<a class="' + cls + '" href="' + item.href + '" title="'
                    + UI.esc(item.desc || '') + '">' + UI.esc(item.name) + '</a>';
            }).join('');
        },

        /* -------------------- 轻提示 -------------------- */
        toast: function (message, isError) {
            var node = document.getElementById('toast');
            if (!node) {
                node = document.createElement('div');
                node.id = 'toast';
                node.className = 'toast';
                document.body.appendChild(node);
            }
            node.textContent = message;
            node.className = 'toast show' + (isError ? ' error' : '');
            clearTimeout(UI.toast._timer);
            UI.toast._timer = setTimeout(function () { node.className = 'toast'; }, 3600);
        },

        /* -------------------- 详情浮窗（右侧抽屉） -------------------- */
        drawer: {
            open: function (title, html) {
                UI.drawer.ensure();
                UI.setText('drawerTitle', title);
                UI.setHtml('drawerBody', html);
                document.getElementById('drawer').classList.add('open');
                document.getElementById('drawerMask').classList.add('open');
            },
            close: function () {
                var drawer = document.getElementById('drawer');
                var mask = document.getElementById('drawerMask');
                if (drawer) { drawer.classList.remove('open'); }
                if (mask) { mask.classList.remove('open'); }
            },
            isOpen: function () {
                var drawer = document.getElementById('drawer');
                return Boolean(drawer && drawer.classList.contains('open'));
            },
            ensure: function () {
                if (document.getElementById('drawer')) { return; }
                var mask = document.createElement('div');
                mask.id = 'drawerMask';
                mask.className = 'drawer-mask';
                mask.addEventListener('click', UI.drawer.close);
                var drawer = document.createElement('aside');
                drawer.id = 'drawer';
                /* 注意：初始不加 open 类，配合 CSS 的 visibility:hidden 保证默认不显示 */
                drawer.className = 'drawer';
                drawer.innerHTML = '<header><h3 id="drawerTitle">详情</h3>'
                    + '<span class="drawer-close" id="drawerClose">×</span></header>'
                    + '<div class="drawer-body" id="drawerBody"></div>';
                document.body.appendChild(mask);
                document.body.appendChild(drawer);
                drawer.querySelector('#drawerClose').addEventListener('click', UI.drawer.close);
                /* 兜底复位：确保详情浮窗在页面加载后一定是收起状态，
                   只有点击「详情」按钮调用 UI.drawer.open() 时才滑入显示 */
                UI.drawer.close();
                document.addEventListener('keydown', function (event) {
                    if (event.key === 'Escape' || event.key === 'Esc') { UI.drawer.close(); }
                });
            }
        },

        /* -------------------- 确认框 -------------------- */
        confirm: function (message, onOk) {
            if (global.confirm(message)) { onOk(); }
        },

        /* -------------------- CSV 导出（带 BOM，Excel 打开不乱码） -------------------- */
        csv: function (filename, rows) {
            var content = rows.map(function (row) {
                return row.map(function (cell) {
                    var text = String(cell === undefined || cell === null ? '' : cell);
                    return '"' + text.replace(/"/g, '""') + '"';
                }).join(',');
            }).join('\r\n');
            var blob = new Blob(['\ufeff' + content], { type: 'text/csv;charset=utf-8;' });
            var link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(link.href);
            UI.toast('已导出 ' + filename);
        },

        /* -------------------- 事件委托 -------------------- */
        delegate: function (root, selector, eventName, handler) {
            var node = typeof root === 'string' ? document.querySelector(root) : root;
            if (!node) { return; }
            node.addEventListener(eventName || 'click', function (event) {
                var target = event.target && event.target.closest ? event.target.closest(selector) : null;
                if (target && node.contains(target)) { handler(event, target); }
            });
        },

        /* -------------------- 时钟与 rem 适配 -------------------- */
        clock: function (selector) {
            function tick() {
                var now = new Date();
                var week = ['星期日', '星期一', '星期二', '星期三', '星期四', '星期五', '星期六'];
                UI.setText((selector || '#pageClock').replace('#', ''),
                    now.getFullYear() + '-' + pad(now.getMonth() + 1) + '-' + pad(now.getDate()) + ' '
                    + pad(now.getHours()) + ':' + pad(now.getMinutes()) + ':' + pad(now.getSeconds())
                    + ' ' + week[now.getDay()]);
            }
            tick();
            setInterval(tick, 1000);
        },
        fitRem: function () {
            function apply() {
                document.documentElement.style.fontSize = (global.innerWidth / 22) + 'px';
            }
            apply();
            global.addEventListener('resize', apply);
        },

        /* -------------------- 图表尺寸自适应（统一修复"刷新后图形错位"） --------------------
         * 背景：图表容器都用 rem 布局（1rem = 屏宽 / 22），而 rem 基准是本文件在页面启动时写入的。
         * 如果先 echarts.init() 再设置 rem 基准，ECharts 会把初始的（错误）像素尺寸固化进画布——
         * 现象就是"刷新后图形挤在一起/错位，缩放一下窗口或全屏又恢复正常"（因为 resize 事件会补一次 resize）。
         * 统一解法：
         *   1) 各页面 start() 必须先 UI.fitRem() 再 echarts.init()（顺序错了任何兜底都晚一拍）；
         *   2) 初始化后立即校正一次，并在下一帧再校正一次，兜住背景图/字体/滚动条带来的尾部抖动；
         *   3) 用 ResizeObserver 直接监听容器真实尺寸变化（rem 变化、标签页显示切换、滚动条出现都能覆盖）。
         * 用法：initCharts() 之后调用 UI.autoResize([chartA, chartB])，页面不再自己绑定 window.resize。 */
        autoResize: function (chartOrList) {
            var charts = (Array.isArray(chartOrList) ? chartOrList : [chartOrList])
                .filter(function (chart) { return Boolean(chart) && typeof chart.resize === 'function'; });
            if (!charts.length) { return charts; }

            function sizeOf(chart) {
                var dom = chart.getDom ? chart.getDom() : null;
                if (!dom) { return 'no-dom'; }
                return dom.clientWidth + 'x' + dom.clientHeight;
            }

            function resizeAll() {
                charts.forEach(function (chart) {
                    var signature = sizeOf(chart);
                    /* 尺寸没变化就不重复 resize，避免 ResizeObserver 自触发死循环 */
                    if (chart.__sizeSignature === signature) { return; }
                    chart.__sizeSignature = signature;
                    try {
                        if (chart.isDisposed && chart.isDisposed()) { return; }
                        chart.resize();
                    } catch (error) {
                        /* 容器已被移除（切换页面/销毁实例）时忽略 */
                    }
                });
            }

            var pending = false;
            function schedule() {
                if (pending) { return; }
                pending = true;
                var run = function () { pending = false; resizeAll(); };
                if (global.requestAnimationFrame) { global.requestAnimationFrame(run); }
                else { run(); }
            }

            charts.forEach(function (chart) {
                var dom = chart.getDom ? chart.getDom() : null;
                if (!dom || !global.ResizeObserver) { return; }
                chart.__resizeObserver = new global.ResizeObserver(schedule);
                chart.__resizeObserver.observe(dom);
            });
            global.addEventListener('resize', schedule);

            resizeAll();
            schedule();
            return charts;
        },

        /* -------------------- 顶部运行状态徽标 -------------------- */
        renderStatus: function (status, ids) {
            if (!status) { return; }
            var target = ids || { mode: 'modeBadge', firewall: 'fwBadge', version: 'versionBadge' };
            var isMock = status.status === 'mock';
            var modeText = { ebpf: 'eBPF 采集', scapy: 'libpcap 采集', demo: '演示流量' };
            UI.setText(target.mode, isMock ? '演示数据'
                : (modeText[status.capture_mode] || status.capture_mode || '-'));
            var modeNode = document.getElementById(target.mode);
            if (modeNode) { modeNode.className = 'badge ' + (isMock ? 'badge-warn' : 'badge-ok'); }
            if (target.firewall) {
                UI.setText(target.firewall, (status.firewall_backend || '-')
                    + (status.dry_run ? ' · DRY-RUN' : ' · 已生效'));
                var fwNode = document.getElementById(target.firewall);
                if (fwNode) { fwNode.className = 'badge ' + (status.dry_run ? 'badge-warn' : 'badge-ok'); }
            }
            if (target.version) { UI.setText(target.version, 'v' + (status.version || '-')); }
        },

        /* -------------------- 页面通用启动 -------------------- */
        boot: function (activeModule) {
            UI.nav(activeModule);
            UI.clock('#pageClock');
            UI.fitRem();
            UI.tabs.init();
            UI.drawer.ensure();
            SecApi.on('status', function (status) { UI.renderStatus(status); });
            SecApi.start();
            // 登录用户菜单（鉴权关闭时不显示；失败静默，不影响页面）
            setTimeout(function () {
                SecApi.authMe().then(function (data) {
                    if (!data || !data.auth_enabled || !data.user) { return; }
                    var box = document.querySelector('.sub-status');
                    if (!box) { return; }
                    var chip = document.createElement('span');
                    chip.className = 'nav-user';
                    chip.innerHTML = '<b>' + UI.esc(data.user.display_name || data.user.username) + '</b>'
                        + ' <span class="hint">' + UI.esc(data.role || '') + '</span>'
                        + ' <button class="btn-mini" id="btnLogout" type="button">退出</button>';
                    box.insertBefore(chip, box.firstChild);
                    var button = chip.querySelector('#btnLogout');
                    if (button) {
                        button.addEventListener('click', function () {
                            SecApi.logout().finally(function () {
                                window.location.replace('/login.html');
                            });
                        });
                    }
                }).catch(function () { /* 未登录由 api.js 统一跳转 */ });
            }, 150);
        },

        /* -------------------- 异步扫描任务轮询（漏洞页/资产页共用） -------------------- */
        pollScanJob: function (jobId, onProgress) {
            var attempts = 0;
            return new Promise(function (resolve) {
                var timer = setInterval(function () {
                    attempts += 1;
                    SecApi.get('/vulns/scan/' + jobId).then(function (job) {
                        if (onProgress) { onProgress(job); }
                        if (job.status === 'done' || job.status === 'error') {
                            clearInterval(timer);
                            if (job.status === 'done') {
                                var summary = job.summary || {};
                                UI.toast('扫描完成：目标 ' + summary.targets + ' 个，服务 '
                                    + summary.services_found + ' 个，漏洞 ' + summary.vulns_found + ' 个');
                            } else {
                                UI.toast('扫描失败：' + job.error, true);
                            }
                            resolve(job);
                        } else if (attempts > 150) {
                            clearInterval(timer);
                            UI.toast('任务仍在后台执行，稍后可刷新查看');
                            resolve(null);
                        }
                    }).catch(function () {
                        if (attempts > 150) { clearInterval(timer); resolve(null); }
                    });
                }, 2000);
            });
        }
    };

    global.UI = UI;
})(window);

