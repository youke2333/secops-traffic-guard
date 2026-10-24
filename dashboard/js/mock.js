/**
 * mock.js —— 本地仿真数据源（后端未启动时的大屏演示模式）
 *
 * 输出结构与真实后端完全一致（metrics / alert / blocks / assets / vulns ...），
 * 因此 dashboard.js 无需区分数据来源；页面右上角会显示「演示数据」标识。
 */
(function (global) {
    'use strict';

    var SERVERS = ['192.168.1.10', '192.168.1.15', '192.168.1.18', '192.168.1.20', '192.168.1.30'];
    var CLIENTS = ['10.20.0.11', '10.20.0.12', '10.20.0.13', '10.20.0.14', '10.20.0.15'];
    var ATTACKERS = ['203.0.113.66', '198.51.100.23', '45.33.32.156', '185.199.108.153', '91.121.87.5'];
    var CATEGORY_TEXT = {
        port_scan: '端口扫描探测',
        brute_force: '认证端口暴力破解',
        nonstandard_port: '非标准端口高频访问',
        traffic_spike: '突发流量峰值',
        web_sql_injection: 'Web-SQL 注入',
        web_xss_reflected: 'Web-反射型 XSS',
        web_command_injection: 'Web-命令注入',
        web_file_inclusion: 'Web-文件包含',
        web_file_upload: 'Web-恶意文件上传',
        web_brute_force: 'Web-暴力破解',
        web_csrf: 'Web-CSRF',
        web_webshell: 'Web-Webshell 访问'
    };
    var SEVERITY_TEXT = { critical: '紧急', high: '高危', medium: '中危', low: '低危' };

    /* 演示模式下的「Web 攻击知识库」样例（真实知识库见 backend/data/web_attack_rules.json，
       17 大类 / 63 条规则；这里摘录全部大类，保证无后端时页面结构完整） */
    var WEB_CATEGORIES = [
        { key: 'sql_injection', name: 'SQL 注入', cwe: 'CWE-89', owasp: 'A03:2021 Injection', severity: 'critical', rule_count: 6, description: '参数拼接 SQL 语句，绕过查询条件或读取数据库。' },
        { key: 'sql_injection_blind', name: 'SQL 盲注', cwe: 'CWE-89', owasp: 'A03:2021 Injection', severity: 'critical', rule_count: 5, description: '用布尔/时间差异逐字符推断数据库内容。' },
        { key: 'xss_reflected', name: '反射型 XSS', cwe: 'CWE-79', owasp: 'A03:2021 Injection', severity: 'high', rule_count: 5, description: '脚本随参数回显到页面并在受害者浏览器执行。' },
        { key: 'xss_stored', name: '存储型 XSS', cwe: 'CWE-79', owasp: 'A03:2021 Injection', severity: 'high', rule_count: 4, description: '恶意脚本被持久化保存，查看页面者都会中招。' },
        { key: 'command_injection', name: '命令注入', cwe: 'CWE-78', owasp: 'A03:2021 Injection', severity: 'critical', rule_count: 4, description: '参数被拼进系统命令，可直接获取 Shell。' },
        { key: 'file_inclusion', name: '文件包含', cwe: 'CWE-98', owasp: 'A03:2021 Injection', severity: 'critical', rule_count: 3, description: 'LFI/RFI：读取本地敏感文件或加载远程脚本。' },
        { key: 'file_upload', name: '恶意文件上传', cwe: 'CWE-434', owasp: 'A04:2021 Insecure Design', severity: 'critical', rule_count: 3, description: '上传 Webshell 获取服务器控制权。' },
        { key: 'brute_force', name: '暴力破解', cwe: 'CWE-307', owasp: 'A07:2021 认证失效', severity: 'high', rule_count: 4, description: '高频尝试口令/验证码以接管账号。' },
        { key: 'csrf', name: '跨站请求伪造', cwe: 'CWE-352', owasp: 'A01:2021 访问控制失效', severity: 'high', rule_count: 4, description: '敏感操作缺少 Token/来源校验。' },
        { key: 'insecure_captcha', name: '不安全的验证码', cwe: 'CWE-804', owasp: 'A07:2021 认证失效', severity: 'medium', rule_count: 3, description: '验证码可空/固定/复用或流程可跳步。' },
        { key: 'path_traversal', name: '目录穿越', cwe: 'CWE-22', owasp: 'A01:2021 访问控制失效', severity: 'high', rule_count: 4, description: '用 ../ 跳出 Web 根目录读取任意文件。' },
        { key: 'ssrf', name: '服务端请求伪造', cwe: 'CWE-918', owasp: 'A10:2021 SSRF', severity: 'high', rule_count: 4, description: '服务端代访内网或云元数据地址。' },
        { key: 'xxe', name: 'XML 外部实体注入', cwe: 'CWE-611', owasp: 'A05:2021 配置错误', severity: 'high', rule_count: 3, description: 'XML 解析开启外部实体导致文件读取/SSRF。' },
        { key: 'webshell', name: 'Webshell 访问', cwe: 'CWE-506', owasp: 'A03:2021 Injection', severity: 'critical', rule_count: 3, description: '请求木马脚本或在参数里执行命令。' },
        { key: 'ssti', name: '服务端模板注入', cwe: 'CWE-1336', owasp: 'A03:2021 Injection', severity: 'critical', rule_count: 3, description: '模板引擎把用户输入当模板渲染，可执行代码。' },
        { key: 'ldap_nosql_injection', name: 'LDAP/NoSQL 注入', cwe: 'CWE-90', owasp: 'A03:2021 Injection', severity: 'high', rule_count: 3, description: '构造永真查询绕过认证或拖库。' },
        { key: 'crlf_injection', name: 'CRLF 注入', cwe: 'CWE-93', owasp: 'A03:2021 Injection', severity: 'medium', rule_count: 2, description: '注入 %0d%0a 篡改响应头。' }
    ];

    /* 规则摘录（演示用）：结构、字段与后端 /web/kb 完全一致 */
    var WEB_ATTACK_RULES = [
        { id: 'WEB-SQLI-001', category: 'sql_injection', category_name: 'SQL 注入', title: 'SQL 注入：联合查询（UNION SELECT）', severity: 'critical', cvss: 9.8, confidence: 'high', cwe: 'CWE-89', owasp: 'A03:2021 Injection', examples: ["?id=1' union select user,password from users-- -"] },
        { id: 'WEB-SQLI-002', category: 'sql_injection', category_name: 'SQL 注入', title: 'SQL 注入：永真条件绕过（OR 1=1）', severity: 'critical', cvss: 9.8, confidence: 'high', cwe: 'CWE-89', owasp: 'A03:2021 Injection', examples: ["?id=1' OR '1'='1"] },
        { id: 'WEB-SQLB-001', category: 'sql_injection_blind', category_name: 'SQL 盲注', title: 'SQL 盲注：时间型（SLEEP/WAITFOR）', severity: 'critical', cvss: 9.8, confidence: 'high', cwe: 'CWE-89', owasp: 'A03:2021 Injection', examples: ["?id=1' AND SLEEP(5)-- -"] },
        { id: 'WEB-XSSR-001', category: 'xss_reflected', category_name: '反射型 XSS', title: '反射型 XSS：script 标签注入', severity: 'high', cvss: 8.3, confidence: 'high', cwe: 'CWE-79', owasp: 'A03:2021 Injection', examples: ['?name=<script>alert(document.cookie)</script>'] },
        { id: 'WEB-XSSS-001', category: 'xss_stored', category_name: '存储型 XSS', title: '存储型 XSS：留言字段写入脚本', severity: 'high', cvss: 8.8, confidence: 'high', cwe: 'CWE-79', owasp: 'A03:2021 Injection', examples: ["mtxMessage=<script>alert('stored')</script>"] },
        { id: 'WEB-CMDI-001', category: 'command_injection', category_name: '命令注入', title: '命令注入：命令分隔符 + 系统命令', severity: 'critical', cvss: 9.8, confidence: 'high', cwe: 'CWE-78', owasp: 'A03:2021 Injection', examples: ['ip=127.0.0.1; cat /etc/passwd'] },
        { id: 'WEB-LFI-001', category: 'file_inclusion', category_name: '文件包含', title: '文件包含：参数指向本地敏感文件', severity: 'critical', cvss: 9.4, confidence: 'high', cwe: 'CWE-98', owasp: 'A03:2021 Injection', examples: ['?page=../../../../etc/passwd'] },
        { id: 'WEB-UPLD-001', category: 'file_upload', category_name: '恶意文件上传', title: '文件上传：危险脚本扩展名', severity: 'critical', cvss: 9.8, confidence: 'high', cwe: 'CWE-434', owasp: 'A04:2021 Insecure Design', examples: ['filename="shell.php"'] },
        { id: 'WEB-BF-001', category: 'brute_force', category_name: '暴力破解', title: '暴力破解：登录接口高频尝试', severity: 'high', cvss: 7.5, confidence: 'high', cwe: 'CWE-307', owasp: 'A07:2021 认证失效', examples: ['60 秒内 12 次 POST /login.php'] },
        { id: 'WEB-CSRF-001', category: 'csrf', category_name: '跨站请求伪造', title: 'CSRF：敏感操作缺少防伪 Token', severity: 'high', cvss: 7.6, confidence: 'medium', cwe: 'CWE-352', owasp: 'A01:2021 访问控制失效', examples: ['POST /csrf/ password_new=a&password_conf=a'] },
        { id: 'WEB-CAPTCHA-001', category: 'insecure_captcha', category_name: '不安全的验证码', title: '不安全验证码：空值/固定值提交', severity: 'medium', cvss: 6.5, confidence: 'high', cwe: 'CWE-804', owasp: 'A07:2021 认证失效', examples: ['captcha=&step=2'] },
        { id: 'WEB-TRV-001', category: 'path_traversal', category_name: '目录穿越', title: '目录穿越：上跳目录序列（../）', severity: 'high', cvss: 8.6, confidence: 'high', cwe: 'CWE-22', owasp: 'A01:2021 访问控制失效', examples: ['?file=../../../../etc/shadow'] },
        { id: 'WEB-SSRF-002', category: 'ssrf', category_name: '服务端请求伪造', title: 'SSRF：云元数据接口与内网敏感端口', severity: 'critical', cvss: 9.1, confidence: 'high', cwe: 'CWE-918', owasp: 'A10:2021 SSRF', examples: ['?url=http://169.254.169.254/latest/meta-data/'] },
        { id: 'WEB-XXE-001', category: 'xxe', category_name: 'XML 外部实体注入', title: 'XXE：DOCTYPE/ENTITY 声明注入', severity: 'high', cvss: 8.6, confidence: 'high', cwe: 'CWE-611', owasp: 'A05:2021 配置错误', examples: ['<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'] },
        { id: 'WEB-WS-001', category: 'webshell', category_name: 'Webshell 访问', title: 'Webshell：常见木马文件名/路径访问', severity: 'critical', cvss: 9.8, confidence: 'high', cwe: 'CWE-506', owasp: 'A03:2021 Injection', examples: ['GET /upload/shell.php?cmd=id'] },
        { id: 'WEB-SSTI-001', category: 'ssti', category_name: '服务端模板注入', title: 'SSTI：Jinja2/Twig 模板对象访问链', severity: 'critical', cvss: 9.6, confidence: 'high', cwe: 'CWE-1336', owasp: 'A03:2021 Injection', examples: ['?name={{7*7}}'] },
        { id: 'WEB-LDAP-001', category: 'ldap_nosql_injection', category_name: 'LDAP/NoSQL 注入', title: 'LDAP 注入：永真过滤器构造', severity: 'high', cvss: 8.2, confidence: 'high', cwe: 'CWE-90', owasp: 'A03:2021 Injection', examples: ['?user=*)(uid=*))(|(uid=*'] },
        { id: 'WEB-CRLF-001', category: 'crlf_injection', category_name: 'CRLF 注入', title: 'CRLF 注入：响应头拆分', severity: 'medium', cvss: 6.1, confidence: 'high', cwe: 'CWE-93', owasp: 'A03:2021 Injection', examples: ['?next=%0d%0aSet-Cookie:admin=1'] }
    ];

    function rnd(min, max) {
        return min + Math.random() * (max - min);
    }
    function pick(list) {
        return list[Math.floor(Math.random() * list.length)];
    }
    function nowText(ts) {
        var date = new Date((ts || Date.now() / 1000) * 1000);
        function pad(value) { return (value < 10 ? '0' : '') + value; }
        return date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' + pad(date.getDate()) + ' '
            + pad(date.getHours()) + ':' + pad(date.getMinutes()) + ':' + pad(date.getSeconds());
    }

    var Mock = {
        api: null,
        started: false,
        load: 0.18,              // 当前负载占比（相对 1000Mbps）
        trend: [],
        packetsTotal: 1_268_400,
        bytesTotal: 8_732_000_000,
        blocks: [],
        alerts: [],
        disposals: [],
        assets: [],
        vulns: [],
        whitelist: [],
        scanJobs: [],
        cveRules: [],
        _scanSeq: 0,
        scenario: null,
        nextScenarioAt: Date.now() / 1000 + 8,

        /* -------------------- 启动 -------------------- */
        start: function (api) {
            if (this.started) { return; }
            this.started = true;
            this.api = api;
            this._seedStatic();
            this._seedTrend();
            this._seedAlerts();
            this._emitLists();
            this._timer = setInterval(this._tick.bind(this), 500);
            this._listTimer = setInterval(this._emitLists.bind(this), 5000);
            console.info('[SecMock] 演示数据模式已启动');
        },

        /* -------------------- 初始静态数据 -------------------- */
        _seedStatic: function () {
            var self = this;
            this.assets = SERVERS.map(function (ip, index) {
                var ports = [[22, 80, 443], [22, 3306], [80, 8080, 6379], [22, 3389], [443, 9200]][index] || [22, 80];
                var tags = [];
                ports.forEach(function (port) {
                    if (port === 443 || port === 80 || port === 8080) { tags.push('Web'); }
                    if (port === 3306 || port === 9200) { tags.push('数据库'); }
                    if (port === 22 || port === 3389) { tags.push('远程管理'); }
                    if (port === 6379) { tags.push('缓存'); }
                });
                return {
                    id: index + 1, ip: ip, hostname: 'srv-' + ip.split('.').pop(), mac: '',
                    os_guess: index % 2 ? 'Linux（SSH banner 推断）' : 'Linux/RHEL 系（banner 推断）',
                    open_ports: ports, services: [], tags: tags,
                    risk_level: ['low', 'medium', 'high', 'low', 'critical'][index % 5],
                    bytes_in: Math.floor(rnd(2e8, 4e9)), bytes_out: Math.floor(rnd(1e8, 2e9)),
                    alert_count: Math.floor(rnd(0, 9)), vuln_count: Math.floor(rnd(0, 3)),
                    first_seen: nowText(Date.now() / 1000 - 86400 * 7), last_seen: nowText()
                };
            });
            this.vulns = [
                { cve: 'CVE-2024-6387', title: 'OpenSSH 服务端信号竞态导致未授权远程代码执行（regreSSHion）',
                  severity: 'critical', cvss: 8.1, fixed_version: '9.8p1', port: 22,
                  recommendation: '升级 OpenSSH 至 9.8p1 及以上；无法立即升级时把 LoginGraceTime 设为 0。' },
                { cve: 'CVE-2021-23017', title: 'nginx resolver 模块 1 字节堆覆写导致远程代码执行',
                  severity: 'high', cvss: 7.7, fixed_version: '1.20.1', port: 80,
                  recommendation: '升级 nginx 至 1.20.1 或 1.21.0 以上，检查 resolver 配置。' },
                { cve: 'MISCONF-REDIS-UNAUTH', title: 'Redis 未授权访问（未开启保护模式/无密码）',
                  severity: 'critical', cvss: 9.8, fixed_version: '配置修复', port: 6379,
                  recommendation: '绑定内网地址、设置 requirepass、开启 protected-mode 并限制来源网段。' },
                { cve: 'CVE-2022-21215', title: 'MySQL 服务端拒绝服务及信息泄漏（多版本累积修复）',
                  severity: 'high', cvss: 7.1, fixed_version: '5.7.37 / 8.0.28', port: 3306,
                  recommendation: '升级 MySQL 补丁版本，限制 3306 仅内网可达。' },
                { cve: 'CVE-2019-0708', title: 'RDP 远程代码执行（BlueKeep）',
                  severity: 'critical', cvss: 9.8, fixed_version: '系统安全补丁', port: 3389,
                  recommendation: '安装 BlueKeep 补丁、开启 NLA，并通过 VPN/堡垒机收敛暴露面。' }
            ].map(function (item, index) {
                item.id = index + 1;
                item.asset_ip = SERVERS[index % SERVERS.length];
                item.service = item.cve.indexOf('MISCONF') === 0 ? '配置类风险' : '服务指纹匹配';
                item.evidence = '演示数据：端口 ' + item.port + ' 指纹命中知识库';
                item.status = 'open';
                item.found_at = nowText(Date.now() / 1000 - 3600 * (index + 1));
                return item;
            });
            this.disposals = [];
            this.whitelist = [
                { id: 1, cidr: '127.0.0.1/32', note: '系统内置', operator: 'system', created_at: nowText(), source: 'config' },
                { id: 2, cidr: '10.20.0.0/24', note: '办公网段（演示）', operator: 'admin', created_at: nowText(), source: 'db' }
            ];
            this.cveRules = [
                { cve: 'CVE-2024-6387', title: 'OpenSSH 服务端信号竞态导致未授权远程代码执行（regreSSHion）', severity: 'critical', cvss: 8.1, fixed_version: '9.8p1' },
                { cve: 'CVE-2023-38408', title: 'OpenSSH ssh-agent PKCS#11 转发导致远程代码执行', severity: 'critical', cvss: 9.8, fixed_version: '9.3p2' },
                { cve: 'CVE-2021-41773', title: 'Apache httpd 路径穿越导致文件读取/远程代码执行', severity: 'critical', cvss: 9.8, fixed_version: '2.4.51' },
                { cve: 'CVE-2021-23017', title: 'nginx resolver 模块 1 字节堆覆写导致远程代码执行', severity: 'high', cvss: 7.7, fixed_version: '1.20.1 / 1.21.0' },
                { cve: 'CVE-2022-0543', title: 'Redis Lua 沙箱逃逸导致远程代码执行（Debian/Ubuntu 打包版本）', severity: 'critical', cvss: 10.0, fixed_version: '6.2.7 / 7.0.0' },
                { cve: 'MISCONF-REDIS-UNAUTH', title: 'Redis 未授权访问（未开启保护模式/无密码）', severity: 'critical', cvss: 9.8, fixed_version: '配置修复（无需升级）' },
                { cve: 'CVE-2021-44228', title: 'Apache Log4j2 JNDI 注入（Log4Shell）', severity: 'critical', cvss: 10.0, fixed_version: '2.17.1' },
                { cve: 'CVE-2022-21215', title: 'MySQL 服务端拒绝服务及信息泄漏（多版本累积修复）', severity: 'high', cvss: 7.1, fixed_version: '5.7.37 / 8.0.28' },
                { cve: 'CVE-2017-0144', title: 'SMBv1 远程代码执行（MS17-010 永恒之蓝）', severity: 'critical', cvss: 9.8, fixed_version: 'MS17-010 安全更新' },
                { cve: 'CVE-2019-0708', title: 'RDP 远程代码执行（BlueKeep）', severity: 'critical', cvss: 9.8, fixed_version: '对应系统安全补丁' }
            ];
        },

        /* 首屏示例告警：让演示模式一打开就能看到「评分 / 直达 / AI 研判」三类字段 */
        _seedAlerts: function () {
            var seeds = [
                ['web_command_injection', '203.0.113.66', '192.168.1.30', 80],
                ['port_scan', '198.51.100.23', '192.168.1.15', 0],
                ['web_webshell', '45.33.32.156', '192.168.1.20', 80]
            ];
            for (var i = 0; i < seeds.length; i += 1) {
                this._raiseAlert(seeds[i][0], seeds[i][1], seeds[i][2], seeds[i][3]);
            }
        },

        _seedTrend: function () {
            var now = Date.now() / 1000;
            this.trend = [];
            for (var i = 180; i >= 0; i -= 1) {
                var base = 120 * 1024 * 1024 + Math.sin(i / 9) * 40 * 1024 * 1024;
                this.trend.push({
                    ts: now - i * 0.5,
                    bps_in: Math.max(0, base + rnd(-12, 12) * 1024 * 1024),
                    bps_out: Math.max(0, base * 0.45 + rnd(-8, 8) * 1024 * 1024),
                    pps_in: Math.max(0, 9000 + rnd(-1500, 1500)),
                    pps_out: Math.max(0, 4200 + rnd(-900, 900)),
                    conns: Math.floor(rnd(60, 160))
                });
            }
        },

        /* -------------------- 每 500ms 生成一帧指标 -------------------- */
        _tick: function () {
            var now = Date.now() / 1000;
            this._maybeScenario(now);

            var target = 0.16 + Math.sin(now / 12) * 0.06;
            if (this.scenario && this.scenario.kind === 'traffic_spike') {
                target = 0.78;
            } else if (this.scenario) {
                target = 0.34;
            }
            this.load += (target - this.load) * 0.25;

            var capacity = 1000 * 1e6;
            var bpsIn = this.load * capacity * 0.62 + rnd(-1.5, 1.5) * 1e6;
            var bpsOut = this.load * capacity * 0.30 + rnd(-1, 1) * 1e6;
            var ppsIn = 4200 + this.load * 26000 + rnd(-400, 400);
            var ppsOut = 2100 + this.load * 12000 + rnd(-300, 300);

            this.packetsTotal += Math.floor(ppsIn * 0.5);
            this.bytesTotal += Math.floor((bpsIn + bpsOut) * 0.5 / 8);

            var point = {
                ts: now, bps_in: Math.max(0, bpsIn), bps_out: Math.max(0, bpsOut),
                pps_in: Math.max(0, ppsIn), pps_out: Math.max(0, ppsOut),
                conns: Math.floor(80 + this.load * 260 + rnd(-8, 8))
            };
            this.trend.push(point);
            if (this.trend.length > 400) { this.trend.shift(); }

            var ports = this._ports(point);
            this.lastMetrics = {
                ts: now, interval_ms: 500, iface: 'demo0', mode: 'demo',
                bps_in: point.bps_in, bps_out: point.bps_out,
                pps_in: point.pps_in, pps_out: point.pps_out,
                conns: point.conns, unique_src: Math.floor(rnd(12, 42)),
                unique_dst_ports: ports.length,
                packets_total: this.packetsTotal, bytes_total: this.bytesTotal,
                kpi: {}, ports: ports
            };
            this.api.emit('metrics', this.lastMetrics);

            this.blocks = this.blocks.filter(function (item) {
                return !item.expires_at || item.expires_at > now;
            });
            this.blocks.forEach(function (item) {
                item.remaining_sec = Math.max(0, Math.floor((item.expires_at || now) - now));
            });
        },

        _ports: function (point) {
            var rows = [
                { port: 443, protocol: 'TCP', is_standard: true, top_source: pick(CLIENTS) },
                { port: 80, protocol: 'TCP', is_standard: true, top_source: pick(CLIENTS) },
                { port: 3306, protocol: 'TCP', is_standard: true, top_source: pick(SERVERS) },
                { port: 53, protocol: 'UDP', is_standard: true, top_source: pick(CLIENTS) },
                { port: 6379, protocol: 'TCP', is_standard: true, top_source: pick(SERVERS) },
                { port: 22, protocol: 'TCP', is_standard: true, top_source: pick(CLIENTS) }
            ];
            var totalBps = point.bps_in + point.bps_out;
            var totalPps = point.pps_in + point.pps_out;
            var weights = [0.42, 0.22, 0.12, 0.08, 0.09, 0.07];

            if (this.scenario && this.scenario.port) {
                rows.unshift({ port: this.scenario.port, protocol: 'TCP', is_standard: false,
                               top_source: this.scenario.src });
            }
            return rows.map(function (row, index) {
                var ratio = weights[index] || (this.scenario ? 0.35 : 0.05);
                return {
                    port: row.port, protocol: row.protocol,
                    pps: Math.round((row.is_standard ? totalPps * ratio : totalPps * ratio * 1.6) * 10) / 10,
                    bps: Math.round((row.is_standard ? totalBps * ratio : totalBps * ratio * 1.4) * 10) / 10,
                    conns: Math.floor(rnd(4, 40) * (row.is_standard ? 1 : 2)),
                    is_standard: row.is_standard, top_source: row.top_source,
                    anomaly: !row.is_standard
                };
            }.bind(this));
        },

        /* -------------------- 攻击剧本与告警 -------------------- */
        _maybeScenario: function (now) {
            if (this.scenario) {
                if (now >= this.scenario.until) {
                    this.scenario = null;
                    this.nextScenarioAt = now + rnd(25, 40);
                }
                return;
            }
            if (now < this.nextScenarioAt) { return; }

            var kinds = ['port_scan', 'brute_force', 'nonstandard_port', 'traffic_spike',
                         'web_sql_injection', 'web_xss_reflected', 'web_command_injection', 'web_file_inclusion',
                         'web_file_upload', 'web_brute_force', 'web_csrf', 'web_webshell'];
            var kind = pick(kinds);
            var src = pick(ATTACKERS);
            var dst = pick(SERVERS);
            var config = {
                port_scan: { port: 0, ttl: 18 },
                brute_force: { port: pick([22, 3389, 3306]), ttl: 22 },
                nonstandard_port: { port: pick([4444, 6666, 31337, 12345]), ttl: 20 },
                traffic_spike: { port: pick([9090, 5555]), ttl: 14 },
                web_sql_injection: { port: 80, ttl: 20 },
                web_xss_reflected: { port: 80, ttl: 18 },
                web_command_injection: { port: 80, ttl: 20 },
                web_file_inclusion: { port: 80, ttl: 18 },
                web_file_upload: { port: 80, ttl: 18 },
                web_brute_force: { port: 80, ttl: 24 },
                web_csrf: { port: 80, ttl: 18 },
                web_webshell: { port: 80, ttl: 22 }
            }[kind];
            this.scenario = { kind: kind, src: src, dst: dst, port: config.port, until: now + config.ttl };
            this._raiseAlert(kind, src, dst, config.port);
        },

        _raiseAlert: function (kind, src, dst, port) {
            var severity = { port_scan: 'high', brute_force: 'high', nonstandard_port: 'medium',
                             traffic_spike: 'critical',
                             web_sql_injection: 'critical', web_xss_reflected: 'high',
                             web_command_injection: 'critical', web_file_inclusion: 'critical',
                             web_file_upload: 'critical', web_brute_force: 'high',
                             web_csrf: 'high', web_webshell: 'critical' }[kind];
            var message = {
                port_scan: '源 ' + src + ' 在 10s 内探测 240 个目的端口（熵 7.21），判定为端口扫描',
                brute_force: '源 ' + src + ' 对端口 ' + port + ' 发起 156 次访问，疑似暴力破解/凭证填充',
                nonstandard_port: '非标准端口 ' + port + '/TCP 出现高频访问 862 pps（46 连接，主要来源 ' + src + '）',
                traffic_spike: '整机流量 782.35Mbps 超出基线 182.10Mbps（Z=7.42），疑似突发攻击或数据外泄',
                web_sql_injection: '源 ' + src + ' → ' + dst + ':80 GET /vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271 命中「SQL 注入」（WEB-SQLI-002）；命中片段：\' or \'1\'=\'1',
                web_xss_reflected: '源 ' + src + ' → ' + dst + ':80 GET /search?q=<script>alert(1)</script> 命中「反射型 XSS」（WEB-XSSR-001）；命中片段：<script>alert(1)</script>',
                web_command_injection: '源 ' + src + ' → ' + dst + ':80 POST /vulnerabilities/exec/ 命中「命令注入」（WEB-CMDI-001）；命中片段：;cat /etc/passwd',
                web_file_inclusion: '源 ' + src + ' → ' + dst + ':80 GET /vulnerabilities/fi/?page=../../../../etc/passwd 命中「文件包含」（WEB-LFI-001）',
                web_file_upload: '源 ' + src + ' → ' + dst + ':80 POST /vulnerabilities/upload/ 命中「恶意文件上传」（WEB-UPLD-001）；上传文件名 shell.php',
                web_brute_force: '源 ' + src + ' 对 ' + dst + ':80 /vulnerabilities/brute/ 在 60s 内提交 12 次登录（阈值 10），命中「暴力破解」（WEB-BF-001）',
                web_csrf: '源 ' + src + ' → ' + dst + ':80 POST /vulnerabilities/csrf/ 缺少 CSRF Token/来源校验，命中「跨站请求伪造」（WEB-CSRF-001/002）',
                web_webshell: '源 ' + src + ' → ' + dst + ':80 GET /upload/shell.php?cmd=whoami 命中「Webshell 访问」（WEB-WS-001/002）'
            }[kind];

            var anomaly = {
                id: this.alerts.length + 1,
                category: kind, category_text: CATEGORY_TEXT[kind], severity: severity,
                severity_text: SEVERITY_TEXT[severity], score: Math.round(rnd(0.55, 0.98) * 1000) / 1000,
                source_ip: src, dest_ip: dst, dest_port: port, protocol: 'TCP',
                message: message, detector: kind === 'behavior_anomaly' ? 'isolation-forest' : 'ewma-zscore',
                evidence: { demo: true, window_sec: 10, port: port,
                            unique_dst_ports: kind === 'port_scan' ? 240 : 1,
                            port_entropy: kind === 'port_scan' ? 7.21 : 0.0,
                            threshold: 3.5 },
                status: 'open', blocked: false, region: src.indexOf('192.168') === 0 ? '内网' : '互联网',
                ts: Date.now() / 1000, ts_text: nowText(),
                /* 演示模式同样提供威胁事件 ID，保证弹窗「查看详情」可直达事件抽屉 */
                threat_event_id: this.alerts.length + 1
            };
            anomaly.suggestion = {
                port_scan: '确认该源 IP 是否为授权巡检系统；若不是建议立即封禁并排查横向探测。',
                brute_force: '立即封禁并检查被攻击服务登录日志，必要时关闭密码登录。',
                nonstandard_port: '确认端口对应进程是否为已知服务，非已知建议封禁并排查后门。',
                traffic_spike: '确认是否为业务高峰/备份窗口；非预期时检查 DDoS 或数据外泄。',
                web_sql_injection: '封禁来源 IP 并核查数据库是否被拖库（binlog / 慢查询）；把该接口改为参数化查询。',
                web_xss_reflected: '修复回显参数的输出编码并加 CSP；对来源 IP 限速，排查批量扫描行为。',
                web_command_injection: '立即隔离主机取证（进程 / 计划任务 / 反弹 Shell），封禁来源 IP 并修复命令拼接。',
                web_file_inclusion: '检查 Web 根是否出现异常文件，关闭 allow_url_include；路径参数改白名单映射。',
                web_file_upload: '检查上传目录是否已有脚本落地，禁止该目录执行脚本；封禁来源并轮换凭据。',
                web_brute_force: '封禁来源 IP；对登录接口启用验证码、失败锁定与双因素认证。',
                web_csrf: '确认接口是否缺少 CSRF Token；补齐 Token + SameSite Cookie；核查恶意诱导页面。',
                web_webshell: '高度疑似主机已被控制：立即封禁、隔离主机、删除后门文件并轮换凭据。'
            }[kind] || '建议人工核对流量与主机日志后再处置。';

            var self = this;
            if (severity === 'high' || severity === 'critical') {
                anomaly.blocked = true;
                var block = {
                    id: this.blocks.length + 1, ip: src, reason: '[自动] ' + CATEGORY_TEXT[kind] + '：' + message,
                    category: kind, severity: severity, backend: 'iptables', source: 'auto',
                    operator: 'system', created_at: nowText(),
                    expires_at: Date.now() / 1000 + 1800, active: true, hits: 1, dry_run: true,
                    remaining_sec: 1800
                };
                this.blocks.unshift(block);
                this.disposals.unshift({
                    id: this.disposals.length + 1, ts: nowText(), action: 'block', target: src,
                    detail: '[' + kind + '/' + severity + '] ' + message + ' | 后端=iptables（DRY-RUN）',
                    operator: 'system', success: true
                });
            }
            this.alerts.unshift({
                id: anomaly.id, ts: nowText(), source_ip: src, dest_ip: dst, dest_port: port,
                category: kind, category_text: CATEGORY_TEXT[kind], severity: severity,
                severity_text: SEVERITY_TEXT[severity], message: message, blocked: anomaly.blocked,
                status: 'open', evidence: anomaly.evidence, detector: anomaly.detector,
                region: anomaly.region, suggestion: anomaly.suggestion,
                /* v2：评分 / 直达 / 窗口 / AI 研判（演示模式同样提供，保证前端字段齐全） */
                score: anomaly.score,
                risk_score: Math.round((severity === 'critical' ? 6.0 : severity === 'high' ? 3.6 : 1.5)
                    * (0.9 + rnd(0, 0.2)) * 100) / 100,
                direct_alert: severity === 'critical',
                contributing_rules: this._rulesFor(kind),
                signal_window_id: 'demo-' + anomaly.id,
                signal_count: severity === 'critical' ? 1 : Math.floor(rnd(3, 7)),
                llm_analysis: this._analysis(kind, severity === 'critical')
            });
            this.alerts = this.alerts.slice(0, 40);
            this.disposals = this.disposals.slice(0, 30);

            this.api.emit('alert', anomaly);
            this._emitLists();
            console.info('[SecMock] 演示告警:', kind, src);
            if (global.SecDashboard && global.SecDashboard.onAlert) {
                global.SecDashboard.onAlert(anomaly);
            }
        },

        /* -------------------- 聚合列表数据 -------------------- */
        _overview: function () {
            var now = Date.now() / 1000;
            this._bootAt = this._bootAt || now;
            var metrics = this.lastMetrics || { bps_in: 0, bps_out: 0, pps_in: 0, pps_out: 0, conns: 0 };
            var bps = metrics.bps_in + metrics.bps_out;
            var pps = metrics.pps_in + metrics.pps_out;
            return {
                bps: bps, pps: pps, conns: metrics.conns || 0,
                bandwidth_util: Math.round(bps / (1000 * 1e6) * 10000) / 100,
                packets_total: this.packetsTotal, bytes_total: this.bytesTotal,
                unique_src: metrics.unique_src || 0, unique_dst_ports: metrics.unique_dst_ports || 0,
                alerts_total: this.alerts.length,
                alerts_open: this.alerts.filter(function (item) { return item.status !== 'closed'; }).length,
                blocked_total: this.blocks.length, blocked_active: this.blocks.length,
                assets_total: this.assets.length,
                vulns_open: this.vulns.filter(function (item) { return item.status === 'open'; }).length,
                risk_score: Math.min(100, this.blocks.length * 6 + this.vulns.length * 4),
                firewall_backend: 'iptables', dry_run: true, capture_mode: 'demo',
                channels: ['log', 'webhook:dingtalk'], uptime_sec: Math.floor(now - this._bootAt),
                server_time: new Date().toLocaleString('zh-CN')
            };
        },

        _emitLists: function () {
            var self = this;
            var now = Date.now() / 1000;
            var metrics = this.lastMetrics || { bps_in: 0, bps_out: 0, pps_in: 0, pps_out: 0, conns: 0 };
            var overview = this._overview();

            var categoryCount = {};
            this.alerts.forEach(function (item) {
                categoryCount[item.category_text] = (categoryCount[item.category_text] || 0) + 1;
            });
            var severityCount = {};
            this.alerts.forEach(function (item) {
                severityCount[item.severity] = (severityCount[item.severity] || 0) + 1;
            });
            var sourceCount = {};
            this.alerts.forEach(function (item) {
                sourceCount[item.source_ip] = (sourceCount[item.source_ip] || 0) + 1;
            });

            this.api.emit('overview', overview);
            this.api.emit('blocks', { total: this.blocks.length, items: this.blocks });
            this.api.emit('alerts', { total: this.alerts.length, items: this.alerts.slice(0, 15) });
            this.api.emit('alertStats', {
                window_hours: 24, total: this.alerts.length,
                blocked: this.alerts.filter(function (item) { return item.blocked; }).length,
                by_category: Object.keys(categoryCount).map(function (key) {
                    return { category_text: key, count: categoryCount[key] };
                }),
                by_severity: Object.keys(severityCount).map(function (key) {
                    return { severity: key, severity_text: SEVERITY_TEXT[key], count: severityCount[key] };
                }),
                top_sources: Object.keys(sourceCount).map(function (key) {
                    return { ip: key, count: sourceCount[key] };
                }).sort(function (a, b) { return b.count - a.count; }).slice(0, 10)
            });
            this.api.emit('assets', { items: this.assets });
            this.api.emit('assetSummary', {
                total: this.assets.length,
                risk_distribution: this.assets.reduce(function (acc, item) {
                    acc[item.risk_level] = (acc[item.risk_level] || 0) + 1;
                    return acc;
                }, { critical: 0, high: 0, medium: 0, low: 0 }),
                top_ports: [443, 80, 22, 3306, 6379].map(function (port) {
                    return { port: port, count: 5 };
                })
            });
            this.api.emit('vulns', { items: this.vulns });
            this.api.emit('vulnSummary', {
                total: this.vulns.length, open: this.vulns.length,
                distribution: {
                    critical: this.vulns.filter(function (i) { return i.severity === 'critical'; }).length,
                    high: this.vulns.filter(function (i) { return i.severity === 'high'; }).length,
                    medium: 0, low: 0
                },
                kb: { rules: 18, version: '2024.11' }, nmap_available: false
            });
            this.api.emit('disposals', { total: this.disposals.length, items: this.disposals });
            this.api.emit('metrics', this.lastMetrics || metrics);
        },

        /* ================================================================
         * 演示模式下的"伪后端"：把 REST 请求映射到内存状态
         * 目的：五个模块页面在无后端时也能完整演示（含封禁/解封/扫描/状态流转等处置动作）
         * ================================================================ */
        /* 把漏洞按端口归拢到服务上（形状与后端 GET /assets/{ip} 的 service_vulns 一致） */
        _groupByService: function (asset, vulns) {
            var names = {22: 'ssh', 80: 'http', 443: 'https', 3306: 'mysql',
                3389: 'rdp', 6379: 'redis', 8080: 'http', 9200: 'elasticsearch'};
            var groups = {};
            (asset.open_ports || []).forEach(function (port) {
                groups[port] = { port: port, service: names[port] || '未知服务', banner: '',
                    vulns: [], confirmed: 0, suspected: 0, severity: '' };
            });
            (vulns || []).forEach(function (item) {
                var port = Number(item.port || 0);
                var group = groups[port] || (groups[port] = {
                    port: port, service: item.service || '未知服务', banner: '',
                    vulns: [], confirmed: 0, suspected: 0, severity: ''
                });
                group.vulns.push(item);
                if (item.confidence === 'confirmed') { group.confirmed += 1; }
                else { group.suspected += 1; }
            });
            var list = Object.keys(groups).map(function (key) {
                var group = groups[key];
                group.vulns.sort(function (a, b) { return (b.cvss || 0) - (a.cvss || 0); });
                if (group.vulns.length) { group.severity = group.vulns[0].severity || ''; }
                group.label = group.port + '/tcp · ' + group.service;
                return group;
            });
            list.sort(function (a, b) {
                if (!!a.vulns.length !== !!b.vulns.length) { return a.vulns.length ? -1 : 1; }
                return a.port - b.port;
            });
            return list;
        },

        canHandle: function () {
            return true;      // 演示模式接管全部 /api/v1 请求
        },

        handle: function (method, path, body) {
            var self = this;
            return new Promise(function (resolve, reject) {
                var parts = String(path).split('?');
                var url = parts[0];
                var query = {};
                (parts[1] || '').split('&').forEach(function (pair) {
                    if (!pair) { return; }
                    var kv = pair.split('=');
                    query[decodeURIComponent(kv[0])] = decodeURIComponent(kv[1] || '');
                });
                try {
                    var result = self._route(String(method || 'GET').toUpperCase(), url, query, body || {});
                    if (result === undefined) {
                        reject(new Error('演示模式暂不支持该接口：' + method + ' ' + path));
                    } else {
                        resolve(result);
                    }
                } catch (err) {
                    reject(err);
                }
            });
        },

        _route: function (method, url, query, body) {
            var now = Date.now() / 1000;
            var match;

            /* ---------- 硬件资源（大屏「硬件资源」功能页，演示模式伪数据） ---------- */
            if (url === '/system/resources') {
                var tick = Math.floor(now / 2);
                var wave = function (base, amp, phase) {
                    return Math.max(2, Math.min(99,
                        base + Math.sin(tick / 9 + phase) * amp + Math.random() * 3));
                };
                var cpuPercent = wave(46, 22, 0);
                var memPercent = wave(63, 8, 1.4);
                var diskPercent = 79.3;
                var latest = this.lastMetrics || {};
                return {
                    ts: new Date().toISOString().replace('T', ' ').slice(0, 19),
                    platform: 'Linux', host: 'secops-demo', uptime_sec: 86400 * 3 + 3600 * 7,
                    cpu: { percent: Number(cpuPercent.toFixed(1)), cores: 8,
                           load: { '1m': 1.24, '5m': 0.98, '15m': 0.86 } },
                    memory: { total: 16 * 1024 ** 3, used: Math.round(16 * 1024 ** 3 * memPercent / 100),
                              percent: Number(memPercent.toFixed(1)) },
                    disk: { path: '/', total: 500 * 1024 ** 3,
                            used: Math.round(500 * 1024 ** 3 * diskPercent / 100),
                            free: 500 * 1024 ** 3 - Math.round(500 * 1024 ** 3 * diskPercent / 100),
                            percent: diskPercent },
                    network: { rx_bps: latest.bps_in || 0, tx_bps: latest.bps_out || 0,
                               util: latest.bandwidth_util || 0, capacity_mbps: 1000,
                               iface: latest.iface || 'eth0' },
                    peak_percent: Number(Math.max(cpuPercent, memPercent, diskPercent).toFixed(1)),
                    source: 'demo'
                };
            }

            /* ---------- v6：登录 / 威胁 / 报告 / 规则包（离线演示） ---------- */
            if (url === '/auth/me') {
                return { user: null, csrf_token: '', auth_enabled: false };
            }
            if (url === '/users') {
                if (method === 'POST') {
                    return { success: true, message: '演示模式：用户已创建', code: 'created' };
                }
                return { total: 1, items: [{ id: 1, username: 'admin', role: 'admin', active: true,
                    must_change_password: false, last_login_at: new Date().toISOString() }] };
            }
            if (/^\/users\/\d+/.test(url) && method !== 'GET') {
                return { success: true, message: '演示模式：用户操作已记录',
                         detail: { temporary_password: 'DemoPass123456' } };
            }
            if (url === '/threats') {
                var rows = (this.alerts || []).slice(0, 30).map(function (item, index) {
                    return {
                        id: item.id || index + 1, ts: item.ts || new Date().toISOString(),
                        alert_id: item.id || null, source_ip: item.source_ip || '203.0.113.10',
                        source_port: 50000, dest_ip: item.dest_ip || '192.168.1.10',
                        dest_port: item.dest_port || 8080, protocol: 'TCP',
                        direction: 'inbound', category: item.category || 'web_sql_injection',
                        severity: item.severity || 'high', confidence: 'high',
                        rule_id: item.rule_id || 'WEB-SQLI-001', rule_pack: 'intrusion',
                        tier: 'core', triage_verdict: '', triage_rule_id: '', triage_reason: '',
                        score_delta: 0, status_code: 200, method: 'GET', host: 'app.local',
                        path: '/vulnerabilities/sqli/', query: 'id=1%27+OR+1%3D1',
                        request_bytes: 320, response_bytes: 0, capture_source: 'demo',
                        capture_level: 'L1', iface: '', message: item.message || '演示威胁事件',
                        tags: ['SQL 注入', 'core', '高危直达']
                    };
                });
                return { total: rows.length, page: Number(query.page || 1), page_size: 50, items: rows };
            }
            if (url === '/threats/facets') {
                return { severity: { high: 3, medium: 2 }, direction: { inbound: 4, unknown: 1 },
                         category: { web_sql_injection: 2, web_command_injection: 1,
                                     web_file_upload: 1, web_xss_reflected: 1 },
                         rule_pack: { intrusion: 3, builtin: 2 }, tier: { core: 4 },
                         verdict: {}, tags: { 'SQL 注入': 2, core: 4, '高危直达': 1 } };
            }
            if (url === '/threats/stats') {
                // 与本地时钟一致：演示模式的趋势桶标签也用本地小时
                var nowDate = new Date();
                var pad2 = function (n) { return (n < 10 ? '0' : '') + n; };
                var hour = nowDate.getFullYear() + '-' + pad2(nowDate.getMonth() + 1) + '-'
                    + pad2(nowDate.getDate()) + ' ' + pad2(nowDate.getHours()) + ':00';
                return { hours: 24, total: 5, alerted: 3,
                         trend: [{ bucket: hour, total: 5, alerts: 3, critical: 1, high: 2 }] };
            }
            if (url === '/reports') {
                return { total: 0, items: [] };
            }
            if (url === '/rules/packs') {
                return {
                    rulesets_enabled: true, tiers_enabled: ['core'], shadow_mode: false, total: 1371,
                    packs: [
                        { pack: 'intrusion', count: 742, selected: 89, enabled: true,
                          version: '2026.10', checksum: 'demo-checksum', engine: 'http_text,flow',
                          by_tier: { core: 89, extended: 630, lab: 23 } },
                        { pack: 'triage', count: 300, enabled: false, version: '2026.10',
                          checksum: 'demo', engine: 'context' },
                        { pack: 'malware', count: 329, enabled: false, version: '2026.10',
                          checksum: 'demo', engine: 'file_scan' }
                    ],
                    web_kb: { rules: 163, categories: 21, duplicates: 7,
                              matcher: { matcher_backend: 'python', matcher_patterns: 300 } }
                };
            }
            if (url === '/rules/engine') {
                return { backend: 'python', configured_backend: 'auto', rules: 163, plans: 163,
                         compile_ms: 42.0, fallback_rules: [],
                         matcher: { matcher_backend: 'python', matcher_patterns: 300,
                                    matcher_fallback_rules: 0, scan_us_avg: 0 } };
            }
            if (url === '/rules/reload' && method === 'POST') {
                return { success: true, message: '演示模式：规则已热加载', code: 'reloaded' };
            }
            if (url === '/rules/packs/intrusion' && method === 'PATCH') {
                return { success: true, message: '演示模式：档位已更新', code: 'tiers_updated' };
            }
            if (url === '/rules/engine/backend' && method === 'POST') {
                return { success: true, message: '演示模式：后端已切换', code: 'backend_switched' };
            }
            if ((match = url.match(/^\/threats\/(\d+)$/)) && method === 'GET') {
                var id = Number(match[1]);
                return {
                    id: id, ts: new Date().toISOString(), alert_id: id,
                    source_ip: '203.0.113.10', dest_ip: '192.168.1.10', dest_port: 8080,
                    direction: 'inbound', category: 'web_sql_injection', severity: 'high',
                    confidence: 'high', rule_id: 'WEB-SQLI-001', rule_pack: 'intrusion',
                    tier: 'core', status_code: 200, method: 'GET', host: 'app.local',
                    path: '/vulnerabilities/sqli/', query: 'id=1%27+OR+1%3D1',
                    request_head: 'GET /product/query?id=1%27+OR+1%3D1 HTTP/1.1\nHost: app.local',
                    request_body: '', response_head: '', response_body: '',
                    capture_source: 'demo', capture_level: 'L1',
                    message: '演示威胁事件', tags: ['SQL 注入', 'core', '高危直达'],
                    evidence: { rules: [{ id: 'WEB-SQLI-001', title: '联合查询注入',
                                          target: 'query', snippet: "' OR 1=1" }],
                                aggregation: { risk_score: 7.4 } },
                    alert: { id: id, risk_score: 7.4, status: 'open', blocked: false,
                             message: '演示告警' }
                };
            }
            if ((match = url.match(/^\/threats\/(\d+)\/block$/)) && method === 'POST') {
                return { success: true, message: '演示模式：封禁已记录（DRY-RUN）', code: 'ok' };
            }
            if ((match = url.match(/^\/blocks\/([^/]+)\/report$/)) && method === 'POST') {
                return { success: true, report_id: 1, ip: decodeURIComponent(match[1]),
                         sha256: 'demo', view_url: '#', download_url: '#',
                         event_count: 0, alert_count: 0 };
            }

            /* ---------- 基础状态 ---------- */
            if (url === '/health') {
                return { status: 'mock', version: '1.0.0-demo', capture_mode: 'demo',
                         firewall_backend: 'iptables', dry_run: true,
                         channels: ['log', 'webhook:dingtalk'], db: 'memory' };
            }
            if (url === '/status') {
                return { running: true, capture_mode: 'demo', iface: 'demo0',
                         ticks: Math.floor(now) % 100000, conn_table: 42,
                         alerts_emitted: this.alerts.length, blocks_triggered: this.blocks.length,
                         engine: { iforest_available: true, iforest_ready: true } };
            }
            if (url === '/overview') { return this._overview(); }
            if (url === '/notify/channels') {
                return {
                    channels: ['log', 'webhook:dingtalk'],
                    stats: { sent: this.alerts.length, failed: 0 },
                    history: this.alerts.slice(0, 5).map(function (item) {
                        return { ts: item.ts, category: item.category, severity: item.severity,
                                 source_ip: item.source_ip, message: item.message,
                                 channels: { log: { ok: true }, 'webhook:dingtalk': { ok: true } } };
                    })
                };
            }
            if (url === '/notify/test' && method === 'POST') {
                return { success: true, message: '通道自检完成（演示模式）', code: 'ok',
                         detail: { channels: ['log'], results: { log: { ok: true, message: 'logged' } } } };
            }
            if (url === '/disposals') {
                return { total: this.disposals.length,
                         items: this.disposals.slice(0, Number(query.limit || 30)) };
            }

            /* ---------- 指标 ---------- */
            if (url === '/metrics/trend') {
                var windowSec = Number(query.window_sec || 120);
                var since = now - windowSec;
                var points = this.trend.filter(function (item) { return item.ts >= since; });
                return {
                    window_sec: windowSec, interval_ms: 500,
                    bps_in: points.map(function (item) { return [item.ts, item.bps_in]; }),
                    bps_out: points.map(function (item) { return [item.ts, item.bps_out]; }),
                    pps_in: points.map(function (item) { return [item.ts, item.pps_in]; }),
                    pps_out: points.map(function (item) { return [item.ts, item.pps_out]; }),
                    conns: points.map(function (item) { return [item.ts, item.conns]; })
                };
            }
            if (url === '/metrics/ports') {
                var portList = (this.lastMetrics && this.lastMetrics.ports) || [];
                return { total: portList.length, items: portList.slice(0, Number(query.top || 12)) };
            }
            if (url === '/metrics/ports/baseline') {
                var ports = (this.lastMetrics && this.lastMetrics.ports) || [];
                var baseline = ports.map(function (item) {
                    var mean = Math.max(1, item.pps * (item.is_standard ? 0.85 : 0.12));
                    return {
                        port: item.port, protocol: item.protocol, pps: item.pps, bps: item.bps,
                        conns: item.conns, is_standard: item.is_standard, top_source: item.top_source,
                        baseline_mean_pps: Math.round(mean * 100) / 100,
                        baseline_std: Math.round(mean * 0.15 * 100) / 100,
                        zscore: Math.round((item.pps - mean) / Math.max(1, mean * 0.15) * 100) / 100,
                        deviation_ratio: Math.round(item.pps / mean * 100) / 100,
                        baseline_samples: 120, baseline_ready: true, anomaly: !item.is_standard
                    };
                }).sort(function (a, b) { return (b.anomaly - a.anomaly) || (b.bps - a.bps); });
                return {
                    total: baseline.length, items: baseline,
                    standard_ports: [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 1433, 3306,
                                     3389, 5432, 6379, 8080, 8443, 9200, 27017],
                    threshold: 4.0, window_sec: 10, updated_at: nowText()
                };
            }
            if (url === '/metrics/sessions') {
                var sessions = this._sessions(Number(query.top || 20));
                return { total: sessions.length, items: sessions, conn_table: 42, updated_at: nowText() };
            }
            if (url === '/metrics/portfolio') {
                return {
                    kpi: {}, trend: this._route('GET', '/metrics/trend', { window_sec: '120' }, {}),
                    ports: (this.lastMetrics && this.lastMetrics.ports) || [],
                    latest: this.lastMetrics || {}, engine: {}, overview: this._overview()
                };
            }

            /* ---------- 告警 ---------- */
            if (url === '/alerts' && method === 'GET') {
                var list = this.alerts;
                if (query.severity) {
                    list = list.filter(function (item) { return item.severity === query.severity; });
                }
                if (query.status) {
                    list = list.filter(function (item) { return item.status === query.status; });
                }
                if (query.direct_only === 'true') {
                    list = list.filter(function (item) { return item.direct_alert; });
                }
                if (query.min_score) {
                    list = list.filter(function (item) {
                        return Number(item.risk_score || 0) >= Number(query.min_score);
                    });
                }
                return list.slice(0, Number(query.limit || 50));
            }
            if (url === '/alerts/feed') {
                return { total: this.alerts.length,
                         items: this.alerts.slice(0, Number(query.limit || 15)) };
            }
            if (url === '/alerts/stats') {
                var categoryCount = {};
                var severityCount = {};
                var sourceCount = {};
                this.alerts.forEach(function (item) {
                    categoryCount[item.category_text] = (categoryCount[item.category_text] || 0) + 1;
                    severityCount[item.severity] = (severityCount[item.severity] || 0) + 1;
                    sourceCount[item.source_ip] = (sourceCount[item.source_ip] || 0) + 1;
                });
                return {
                    window_hours: Number(query.hours || 24), total: this.alerts.length,
                    blocked: this.alerts.filter(function (item) { return item.blocked; }).length,
                    direct: this.alerts.filter(function (item) { return item.direct_alert; }).length,
                    avg_risk_score: Math.round(this.alerts.reduce(function (sum, item) {
                        return sum + Number(item.risk_score || 0);
                    }, 0) / Math.max(1, this.alerts.length) * 100) / 100,
                    signals: { total: this.alerts.length + this._demotedSignals().length,
                               suppressed: this._demotedSignals().length },
                    by_category: Object.keys(categoryCount).map(function (key) {
                        return { category_text: key, count: categoryCount[key] };
                    }),
                    by_severity: Object.keys(severityCount).map(function (key) {
                        return { severity: key, severity_text: SEVERITY_TEXT[key], count: severityCount[key] };
                    }),
                    top_sources: Object.keys(sourceCount).map(function (key) {
                        return { ip: key, count: sourceCount[key] };
                    }).sort(function (a, b) { return b.count - a.count; }).slice(0, 10)
                };
            }
            if ((match = url.match(/^\/alerts\/(\d+)$/)) && method === 'GET') {
                var alertId = Number(match[1]);
                var found = this.alerts.filter(function (item) { return item.id === alertId; })[0];
                return found ? Object.assign({}, found, { suggestion: found.suggestion || '建议人工核对后处置。' }) : undefined;
            }
            if ((match = url.match(/^\/alerts\/(\d+)\/(ack|block)$/))) {
                var targetId = Number(match[1]);
                var action = match[2];
                var target = this.alerts.filter(function (item) { return item.id === targetId; })[0];
                if (!target) { throw new Error('告警不存在'); }
                if (action === 'ack') {
                    target.status = 'closed';
                    return { success: true, message: '告警 ' + targetId + ' 已确认关闭', code: 'ok', detail: {} };
                }
                return this._block(target.source_ip, '告警 ' + targetId + ' 一键封禁', target.category,
                    target.severity, Number(query.ttl_sec || 1800));
            }

            /* ---------- 封禁 ---------- */
            if (url === '/blocks' && method === 'GET') {
                var blocks = this.blocks;
                if (query.active_only === 'true') {
                    blocks = blocks.filter(function (item) { return item.active; });
                }
                return { total: blocks.length, items: blocks.slice(0, Number(query.limit || 50)) };
            }
            if (url === '/blocks' && method === 'POST') {
                return this._block(body.ip, body.reason || '人工封禁', body.category || 'manual',
                    body.severity || 'high', Number(body.ttl_sec || 1800));
            }
            if (url === '/blocks/reap' && method === 'POST') {
                var before = this.blocks.length;
                this.blocks = this.blocks.filter(function (item) { return item.remaining_sec > 0; });
                return { success: true, message: '已释放 ' + (before - this.blocks.length) + ' 条到期封禁规则',
                         code: 'ok', detail: {} };
            }
            if ((match = url.match(/^\/blocks\/([^/]+)\/extend$/)) && method === 'POST') {
                var extendIp = match[1];
                var extendTarget = this.blocks.filter(function (item) { return item.ip === extendIp; })[0];
                if (!extendTarget) { throw new Error(extendIp + ' 当前未被封禁，无法续期'); }
                extendTarget.remaining_sec = Number(query.ttl_sec || 1800);
                extendTarget.expires_at = now + extendTarget.remaining_sec;
                this.disposals.unshift({
                    id: this.disposals.length + 1, ts: nowText(), action: 'block', target: extendIp,
                    detail: '封禁续期 ' + extendTarget.remaining_sec + 's', operator: 'dashboard', success: true
                });
                this._emitLists();
                return { success: true, message: extendIp + ' 封禁时长已延长', code: 'extended',
                         detail: { ttl_sec: extendTarget.remaining_sec } };
            }
            if ((match = url.match(/^\/blocks\/([^/]+)$/)) && method === 'DELETE') {
                var removeIp = match[1];
                var removed = 0;
                this.blocks = this.blocks.filter(function (item) {
                    if (item.ip === removeIp) { removed += 1; return false; }
                    return true;
                });
                this.disposals.unshift({
                    id: this.disposals.length + 1, ts: nowText(), action: 'unblock', target: removeIp,
                    detail: '人工解封（释放 ' + removed + ' 条规则）', operator: 'dashboard', success: true
                });
                this._emitLists();
                return { success: true, message: removeIp + ' 解封完成（释放 ' + removed + ' 条规则）',
                         code: 'ok', detail: { released: removed } };
            }

            /* ---------- 白名单 ---------- */
            if (url === '/whitelist' && method === 'GET') {
                return { total: this.whitelist.length, items: this.whitelist };
            }
            if (url === '/whitelist' && method === 'POST') {
                var cidr = String(body.cidr || '').trim();
                if (!cidr) { throw new Error('CIDR 不能为空'); }
                if (this.whitelist.some(function (item) { return item.cidr === cidr; })) {
                    return { success: false, message: '白名单 ' + cidr + ' 已存在或非法', code: 'duplicated', detail: {} };
                }
                this.whitelist.push({ id: this.whitelist.length + 1, cidr: cidr,
                    note: body.note || '页面添加', operator: body.operator || 'dashboard',
                    created_at: nowText(), source: 'db' });
                this.disposals.unshift({ id: this.disposals.length + 1, ts: nowText(),
                    action: 'whitelist_add', target: cidr, detail: body.note || '', operator: 'dashboard', success: true });
                this._emitLists();
                return { success: true, message: '白名单 ' + cidr + ' 已添加', code: 'ok', detail: {} };
            }
            if ((match = url.match(/^\/whitelist\/(.+)$/)) && method === 'DELETE') {
                var removeCidr = decodeURIComponent(match[1]);
                var existed = this.whitelist.some(function (item) { return item.cidr === removeCidr; });
                this.whitelist = this.whitelist.filter(function (item) { return item.cidr !== removeCidr; });
                this.disposals.unshift({ id: this.disposals.length + 1, ts: nowText(),
                    action: 'whitelist_remove', target: removeCidr, detail: '移除白名单',
                    operator: 'dashboard', success: existed });
                return { success: existed, message: existed ? removeCidr + ' 已移除' : removeCidr + ' 不存在',
                         code: existed ? 'ok' : 'not_found', detail: {} };
            }

            /* ---------- 资产 ---------- */
            if (url === '/assets' && method === 'GET') {
                return this.assets.slice(0, Number(query.limit || 200));
            }
            if (url === '/assets/summary') {
                var riskDist = { critical: 0, high: 0, medium: 0, low: 0 };
                var portCount = {};
                this.assets.forEach(function (item) {
                    riskDist[item.risk_level] = (riskDist[item.risk_level] || 0) + 1;
                    (item.open_ports || []).forEach(function (port) {
                        portCount[port] = (portCount[port] || 0) + 1;
                    });
                });
                return {
                    total: this.assets.length, risk_distribution: riskDist,
                    top_ports: Object.keys(portCount).map(function (port) {
                        return { port: Number(port), count: portCount[port] };
                    }).sort(function (a, b) { return b.count - a.count; }).slice(0, 10),
                    tags: {}, updated_at: nowText()
                };
            }
            if ((match = url.match(/^\/assets\/([^/]+)\/rescan$/)) && method === 'POST') {
                var rescanIp = match[1];
                var asset = this.assets.filter(function (item) { return item.ip === rescanIp; })[0];
                var assetVulns = this.vulns.filter(function (item) { return item.asset_ip === rescanIp; });
                return {
                    ip: rescanIp, state: 'up', os_guess: asset ? asset.os_guess : '未知',
                    open_ports: asset ? asset.open_ports : [], services: (asset && asset.services) || [],
                    vulns: assetVulns, vulns_found: assetVulns.length, engine: 'banner-grab'
                };
            }
            if ((match = url.match(/^\/assets\/([^/]+)\/vuln-infer$/)) && method === 'POST') {
                /* 演示模式没有真实攻击流量，按该资产已有的漏洞给一个可读结论：
                   有漏洞就当作"疑似"（演示数据来自知识库匹配，不是响应证据）。 */
                var inferIp = match[1];
                var inferVulns = this.vulns.filter(function (item) { return item.asset_ip === inferIp; });
                return {
                    ip: inferIp, vulns_found: inferVulns.length, confirmed: 0,
                    suspected: inferVulns.length, vulns: inferVulns, duration_sec: 0.1,
                    judge: {
                        enabled: true, ai_enabled: true, client_available: false,
                        inspected: inferVulns.length, confirmed: 0,
                        suspected: inferVulns.length, dismissed: 0,
                        ai_ok: 0, ai_failed: 0, ai_skipped: inferVulns.length
                    }
                };
            }
            if ((match = url.match(/^\/assets\/([^/]+)$/)) && method === 'GET') {
                var detailIp = match[1];
                var detail = this.assets.filter(function (item) { return item.ip === detailIp; })[0];
                if (!detail) { return undefined; }
                var detailVulns = this.vulns.filter(function (item) { return item.asset_ip === detailIp; });
                return Object.assign({}, detail, {
                    alerts: this.alerts.filter(function (item) { return item.source_ip === detailIp; }).slice(0, 20),
                    vulnerabilities: detailVulns,
                    service_vulns: this._groupByService(detail, detailVulns)
                });
            }

            /* ---------- 漏洞列表 ---------- */
            if (url === '/vulns' && method === 'GET') {
                var vulnList = this.vulns;
                if (query.status) {
                    vulnList = vulnList.filter(function (item) { return item.status === query.status; });
                }
                if (query.severity) {
                    vulnList = vulnList.filter(function (item) { return item.severity === query.severity; });
                }
                return vulnList.slice(0, Number(query.limit || 100));
            }
            if (url === '/vulns/summary') {
                var vulnDist = { critical: 0, high: 0, medium: 0, low: 0 };
                var openCount = 0;
                this.vulns.forEach(function (item) {
                    if (item.status === 'open') {
                        openCount += 1;
                        vulnDist[item.severity] = (vulnDist[item.severity] || 0) + 1;
                    }
                });
                return { total: this.vulns.length, open: openCount, distribution: vulnDist,
                         kb: { rules: this.cveRules.length, version: 'demo' },
                         nmap_available: false, updated_at: nowText() };
            }
            if ((match = url.match(/^\/vulns\/(\d+)$/)) && method === 'PATCH') {
                var vulnId = Number(match[1]);
                var vuln = this.vulns.filter(function (item) { return item.id === vulnId; })[0];
                if (!vuln) { throw new Error('漏洞记录不存在'); }
                vuln.status = query.status;
                this._emitLists();
                return { success: true, message: '漏洞 ' + vulnId + ' 状态已更新为 ' + query.status,
                         code: 'ok', detail: {} };
            }

            /* ---------- 扫描任务 ---------- */
            if (url === '/vulns/scan' && method === 'POST') {
                var jobId = 'scan-' + (++this._scanSeq);
                var jobState = {
                    id: jobId, status: 'running', progress: 0, total: 3,
                    started_at: now, finished_at: null, error: '',
                    summary: { targets: 3, services_found: 0, vulns_found: 0 }, details: []
                };
                this.scanJobs.unshift(jobState);
                setTimeout(function () {
                    jobState.status = 'done';
                    jobState.progress = jobState.total;
                    jobState.finished_at = Date.now() / 1000;
                    jobState.summary.services_found = 7;
                    jobState.summary.vulns_found = 2;
                }, 6000);
                return { mode: 'async', job_id: jobId, status: 'running', total: 3,
                         message: '扫描任务已提交（演示模式）' };
            }
            if (url === '/vulns/scan/jobs') {
                return { total: this.scanJobs.length, items: this.scanJobs.slice(0, 10),
                         stats: { jobs: this.scanJobs.length, running: 0, max_concurrent: 2 } };
            }
            if ((match = url.match(/^\/vulns\/scan\/([^/]+)$/)) && method === 'GET') {
                var job = this.scanJobs.filter(function (item) { return item.id === match[1]; })[0];
                if (!job) { return undefined; }
                return Object.assign({}, job, {
                    percent: Math.round(job.progress / Math.max(1, job.total) * 1000) / 10,
                    duration_sec: Math.round(((job.finished_at || Date.now() / 1000) - job.started_at) * 10) / 10
                });
            }
            if (url === '/cve/kb') {
                return {
                    stats: { rules: this.cveRules.length, version: 'demo（内置样例）',
                             path: 'dashboard/js/mock.js' },
                    rules: this.cveRules
                };
            }
            if ((match = url.match(/^\/vulns\/(\d+)\/ai-advice$/)) && method === 'POST') {
                var aiVuln = this.vulns.filter(function (item) {
                    return item.id === Number(match[1]);
                })[0];
                if (!aiVuln) { throw new Error('漏洞记录不存在'); }
                var advice = {
                    source: 'local_rules', degraded: true,
                    summary: aiVuln.title + '：建议按修复建议处置，'
                        + '目标版本 ' + (aiVuln.fixed_version || '以厂商公告为准') + '。',
                    steps: ['备份配置与数据，确认变更窗口。',
                           '按厂商公告升级/打补丁（' + (aiVuln.fixed_version || '以公告为准') + '）。',
                           aiVuln.recommendation || '收紧服务暴露面。',
                           '变更后观察业务指标 30 分钟。'],
                    verification: '重新扫描该资产，确认漏洞记录不再出现。',
                    risk: (aiVuln.severity === 'critical' || aiVuln.severity === 'high') ? 'high' : 'medium',
                    generated_at: nowText()
                };
                aiVuln.ai_advice = advice;
                aiVuln.ai_source = advice.source;
                return Object.assign({ vuln_id: aiVuln.id }, advice);
            }
            if (url === '/scanner/webapp' && method === 'POST') {
                var scanBase = String(body.url || 'http://127.0.0.1:8080/');
                var store = this;
                var parsed = (function () {
                    var m = String(scanBase).match(/^https?:\/\/([^\/:]+)(?::(\d+))?/i);
                    return { host: m ? m[1] : '127.0.0.1', port: m && m[2] ? Number(m[2]) : 80 };
                })();
                var demoFindings = [
                    { cve: 'WEB-001', title: '缺少关键安全响应头（CSP / X-Frame-Options / HSTS）', severity: 'medium', cvss: 5.3, port: parsed.port },
                    { cve: 'WEB-005', title: '敏感文件可下载（.env / .git/config 等）', severity: 'high', cvss: 7.5, port: parsed.port },
                    { cve: 'WEB-003', title: '服务版本信息泄露（Server / X-Powered-By）', severity: 'low', cvss: 3.7, port: parsed.port }
                ];
                demoFindings.forEach(function (finding) {
                    if (!store.vulns.filter(function (item) { return item.cve === finding.cve; }).length) {
                        store.vulns.unshift(Object.assign({
                            id: 9000 + store.vulns.length, asset_ip: parsed.host, service: 'http',
                            evidence: 'GET ' + scanBase + ' 的响应未命中安全基线（状态码 + 响应头/内容取证）',
                            recommendation: '按通用 Web 安全基线修复：补齐安全响应头、移除敏感文件、'
                                + '关闭版本号回显。',
                            fixed_version: '按安全基线整改', status: 'open',
                            found_at: nowText(), ai_advice: null, ai_source: ''
                        }, finding));
                    }
                });
                store._emitLists();
                return {
                    url: scanBase, target_ip: parsed.host,
                    fingerprint: { url: scanBase, title: '业务系统（演示）', server: 'Apache/2.4.57',
                                   powered_by: 'PHP/8.1.2', logged_in: false,
                                   pages_scanned: 6, checks: demoFindings.length, duration_sec: 1.2,
                                   note: '演示模式：未执行真实 HTTP 探测' },
                    vulns: demoFindings, vulns_found: demoFindings.length
                };
            }
            if (url === '/ai/status') {
                return { enabled: true, model: 'demo', client_available: false,
                         alert_analysis: { sources: { local_rules: 1 } },
                         traffic_analysis: { total: 1, local_rules: 1 },
                         note: '演示模式：AI 结论由本地规则模拟，不调用外部 API。' };
            }
            if (url === '/ai/traffic/review') {
                var suspicious = this.alerts.length > 0;
                var aiCategories = {};
                this.alerts.slice(0, 50).forEach(function (item) {
                    aiCategories[item.category] = (aiCategories[item.category] || 0) + 1;
                });
                return {
                    source: 'local_rules', degraded: true,
                    verdict: suspicious ? 'suspicious' : 'normal',
                    confidence: 0.7,
                    summary: suspicious ? '窗口内存在告警信号，建议人工复核。'
                        : '窗口内未发现异常，流量指标位于正常区间。',
                    findings: suspicious ? ['窗口内告警 ' + this.alerts.length + ' 条']
                        : ['无告警与异常信号'],
                    recommendations: suspicious
                        ? ['复核告警证据并按需封禁来源 IP。', '确认是否为业务高峰或授权扫描。']
                        : ['保持监控。'],
                    generated_at: nowText(),
                    window: {
                        window: { minutes: Number(query.window_minutes || 10),
                                  bps_in: (this.lastMetrics || {}).bps_in || 0,
                                  pps_in: (this.lastMetrics || {}).pps_in || 0,
                                  conns: (this.lastMetrics || {}).conns || 0 },
                        alerts: { total: this.alerts.length, direct_count: 0, categories: aiCategories },
                        signals: {}, threshold: 6.0
                    }
                };
            }
            if (url === '/web/kb') {
                var byCategory = {};
                WEB_ATTACK_RULES.forEach(function (rule) {
                    byCategory[rule.category] = (byCategory[rule.category] || 0) + 1;
                });
                return {
                    stats: {
                        rules: WEB_ATTACK_RULES.length, categories: WEB_CATEGORIES.length,
                        version: 'demo（内置样例）', updated_at: nowText(), by_category: byCategory,
                        path: 'dashboard/js/mock.js',
                        description: '演示模式摘录：完整知识库见 backend/data/web_attack_rules.json'
                    },
                    categories: WEB_CATEGORIES,
                    rules: WEB_ATTACK_RULES,
                    field_help: {
                        patterns: '不区分大小写正则；匹配前先做 URL 解码 + HTML 实体解码 + SQL 注释归一化'
                    },
                    source: { name: 'demo', description: '演示模式不启动真实检测，仅展示知识库结构' }
                };
            }
            if (url === '/web/stats') {
                var webAlerts = this.alerts.filter(function (item) {
                    return String(item.category || '').indexOf('web_') === 0;
                }).length;
                return {
                    enabled: true, source_name: 'demo', source_running: false,
                    analyzed_requests: this.alerts.length * 6, matched_hits: webAlerts,
                    alerts_emitted: webAlerts, suppressed: 2, categories: {}, severity: {},
                    counters: {}, window_keys: 0, cooldown_sec: 60,
                    kb: { rules: WEB_ATTACK_RULES.length, categories: WEB_CATEGORIES.length,
                          version: 'demo（内置样例）' }
                };
            }
            if (url === '/web/inspect' && method === 'POST') {
                return {
                    event: body, hits: [], hit_count: 0, categories: [],
                    kb_version: 'demo（内置样例）',
                    hint: '演示模式不执行真实规则匹配，规则样例见「Web 攻击规则」抽屉'
                };
            }
            if (url === '/web/requests' && method === 'POST') {
                var accepted = (body.requests || []).length;
                return { accepted: accepted, alerts: [], alert_count: 0,
                         message: '演示模式已接收 ' + accepted + ' 条请求（不产生真实告警）' };
            }

            /* ---------- v2：评分 / 信号 / 阈值 / 规则来源 / AI 研判 ---------- */
            if (url === '/scoring/config') {
                var emitted = this.alerts.length;
                var suppressed = this._demotedSignals().length;
                var directCount = this.alerts.filter(function (item) {
                    return item.direct_alert; }).length;
                return {
                    window_sec: 300, threshold: 6.0, direct_alert_enabled: true,
                    direct_alert_weight: 6.0, cooldown_sec: 60, max_signals_per_window: 1000,
                    bonus: { multi_category_2: 1.2, multi_category_3: 1.5, critical: 1.3 },
                    weight_table: { critical: 5.0, high: 3.0, medium: 1.5, low: 0.5 },
                    confidence_factor: { high: 1.2, medium: 1.0, low: 0.8 },
                    stats: {
                        alert_emitted: emitted, alert_suppressed: suppressed,
                        aggregator: {
                            window_sec: 300, threshold: 6.0, active_windows: 3,
                            'signals.signals': emitted + suppressed,
                            'signals.emitted': emitted,
                            'signals.direct': directCount,
                            'signals.aggregated': emitted - directCount,
                            'signals.cooldown': 1,
                            'signals.below_threshold': suppressed - 1
                        },
                        enricher: {
                            queued: 0, workers: 1, done: emitted,
                            chain: { enabled: false, client_available: false,
                                     model: 'demo（演示模式不调用外部 API）',
                                     sources: { total: emitted, deepseek_v4_flash: 0,
                                                local_rules: 0, template: emitted, pending: 0 } }
                        }
                    },
                    note: '直达机制（direct_alert）不参与自适应阈值调整：规则固有属性，不随误报反馈变化。'
                };
            }
            if (url === '/signals') {
                var signals = this._demotedSignals().concat(this.alerts.map(function (item) {
                    return {
                        id: item.id, ts: item.ts, source_ip: item.source_ip,
                        rule_id: (item.contributing_rules || ['-'])[0], category: item.category,
                        severity: item.severity, weight: item.risk_score,
                        direct_alert: item.direct_alert, suppressed: false, suppressed_reason: '',
                        score_contribution: item.risk_score,
                        signal_window_id: item.signal_window_id
                    };
                }));
                if (query.source_ip) {
                    signals = signals.filter(function (item) {
                        return item.source_ip === query.source_ip; });
                }
                if (query.category) {
                    signals = signals.filter(function (item) {
                        return item.category === query.category; });
                }
                if (query.suppressed_only === 'true') {
                    signals = signals.filter(function (item) { return item.suppressed; });
                }
                return signals.slice(0, Number(query.limit || 50));
            }
            if ((match = url.match(/^\/signals\/window\/(.+)$/))) {
                var windowIp = decodeURIComponent(match[1]);
                var windowItems = this._demotedSignals().filter(function (item) {
                    return item.source_ip === windowIp;
                });
                return { source_ip: windowIp, window_sec: 300, threshold: 6.0,
                         total: windowItems.length, items: windowItems };
            }
            if (url === '/thresholds/static') {
                return {
                    enabled: true,
                    adaptive_types: ['traffic_spike', 'nonstandard_port', 'port_scan', 'brute_force'],
                    static_base: { traffic_spike: 3.5, nonstandard_port: 4.0, port_scan: 60,
                                   brute_force: 40 },
                    bounds: { min_factor: 0.5, max_factor: 2.0, fp_high: 0.5, fp_low: 0.1,
                              min_samples: 5 },
                    last_recompute_at: null,
                    last_recompute: { lookback_days: 14, dimensions: 4, updated: [], skipped: [],
                                      computed_at: nowText() },
                    note: '直达机制（direct_alert）不参与自适应调整：规则固有属性，不随误报反馈变化。'
                };
            }
            if (url === '/thresholds') {
                return { total: 4, items: this._thresholds(),
                         overview: this._route('GET', '/thresholds/static', {}, {}),
                         updated_at: nowText() };
            }
            if (url === '/thresholds/recompute' && method === 'POST') {
                return { success: true,
                         message: '阈值重算完成（演示模式：按模拟误报率调整 1 个维度）',
                         code: 'recomputed',
                         detail: { lookback_days: 14, dimensions: 4,
                                   updated: [{ detection_type: 'nonstandard_port',
                                               asset_class: 'unknown', time_bucket: 'workhour',
                                               fp_rate: 0.75, sample: 12, threshold: 5.2,
                                               previous: 4.0, static: 4.0, action: 'tighten' }],
                                   skipped: [], computed_at: nowText() } };
            }
            if ((match = url.match(/^\/thresholds\/(\d+)$/)) && method === 'PATCH') {
                var entry = this._thresholds().filter(function (item) {
                    return item.id === Number(match[1]); })[0];
                return { success: true,
                         message: '已人工覆盖 ' + (entry ? entry.detection_type : match[1])
                             + ' → ' + body.threshold_value,
                         code: 'overridden',
                         detail: { id: Number(match[1]), threshold_value: body.threshold_value,
                                   manual_override: true,
                                   override_reason: (body.reason || '页面人工覆盖') + '（dashboard）' } };
            }
            if (url === '/rules/sources') {
                return {
                    loaded_at: Date.now() / 1000, direct_alert_total: 19,
                    sources: [
                        { source: 'native',
                          label: '内置知识库（web_attack_rules.json / cve_rules.json）',
                          enabled: true, rules: WEB_ATTACK_RULES.length + 18,
                          web_rules: WEB_ATTACK_RULES.length,
                          mapped_to_web_category: WEB_ATTACK_RULES.length, direct_alert: 16,
                          by_category: {}, by_severity: {} },
                        { source: 'sigma', label: 'Sigma YAML（backend/data/sigma_rules）',
                          enabled: true, rules: 5, web_rules: 5, mapped_to_web_category: 5,
                          direct_alert: 3, by_category: { command_injection: 1, xxe: 1 },
                          by_severity: { critical: 2 } },
                        { source: 'et', label: 'Suricata / ET Open（backend/data/et_rules）',
                          enabled: true, rules: 6, web_rules: 6, mapped_to_web_category: 6,
                          direct_alert: 3, by_category: { sql_injection: 1, webshell: 1 },
                          by_severity: { high: 4 } },
                        { source: 'cve_ext', label: '扩展 CVE（cve_rules_extended.json）',
                          enabled: true, rules: 8, web_rules: 0, mapped_to_web_category: 0,
                          direct_alert: 0, by_category: {}, by_severity: { critical: 4 } }
                    ],
                    errors: [],
                    web_kb: { version: 'demo（内置样例）', rules: WEB_ATTACK_RULES.length,
                              categories: WEB_CATEGORIES.length, external_rules: 0,
                              direct_alert_rules: 16 },
                    direct_alert_categories: ['command_injection', 'file_inclusion', 'file_upload',
                                              'sql_injection', 'ssti', 'webshell', 'xxe']
                };
            }
            if (url === '/rules') {
                return { total: WEB_ATTACK_RULES.length, items: WEB_ATTACK_RULES,
                         stats: { native_web: WEB_ATTACK_RULES.length, direct_alert: 16,
                                  errors: [] } };
            }
            if (url === '/rules/reload' && method === 'POST') {
                return { success: true,
                         message: '规则已热加载（演示模式）：native=' + WEB_ATTACK_RULES.length
                             + '、sigma=5、et=6、cve_ext=8、直达=19',
                         code: 'reloaded',
                         detail: { native_web: WEB_ATTACK_RULES.length, sigma: 5, et: 6,
                                   cve_ext: 8, direct_alert: 19 } };
            }
            if ((match = url.match(/^\/alerts\/(\d+)\/reanalyze$/)) && method === 'POST') {
                var reanalysisTarget = this.alerts.filter(function (item) {
                    return item.id === Number(match[1]); })[0];
                if (!reanalysisTarget) { throw new Error('告警不存在'); }
                var reanalysis = this._analysis(reanalysisTarget.category,
                    reanalysisTarget.direct_alert);
                reanalysisTarget.llm_analysis = reanalysis;
                this._emitLists();
                return { success: true,
                         message: '研判完成：来源 ' + reanalysis.source + '，结论 '
                             + reanalysis.verdict + (reanalysis.degraded ? '（已降级）' : ''),
                         code: reanalysis.degraded ? 'degraded' : 'ok',
                         detail: { analysis: reanalysis } };
            }

            return undefined;
        },

        /* -------------------- 内部工具：封禁 / 会话模拟 -------------------- */
        _rulesFor: function (kind) {
            var table = {
                web_sql_injection: ['WEB-SQLI-002'], web_xss_reflected: ['WEB-XSSR-001'],
                web_command_injection: ['WEB-CMDI-001'], web_file_inclusion: ['WEB-LFI-001'],
                web_file_upload: ['WEB-UPLD-001'], web_brute_force: ['WEB-BF-001'],
                web_csrf: ['WEB-CSRF-001'], web_webshell: ['WEB-WS-001'],
                port_scan: ['STAT-PORT-SCAN'], brute_force: ['STAT-BRUTE-FORCE'],
                nonstandard_port: ['STAT-NONSTANDARD-PORT'], traffic_spike: ['STAT-TRAFFIC-SPIKE'],
            };
            return table[kind] || ['STAT-UNKNOWN'];
        },

        _analysis: function (kind, direct) {
            if (direct) {
                return {
                    source: 'deepseek_v4_flash', verdict: 'confirm', confidence: 0.92,
                    suggestion: 'block', degraded: false, direct_alert: true,
                    reason: '命中单条高置信度致命攻击规则（直达机制），证据一致，建议立即封禁并取证。',
                    evidence_refs: ['direct_alert=true（单条致命规则命中）',
                                    'risk_score=6.0', 'detector=web-kb'],
                    generated_at: nowText()
                };
            }
            if (kind === 'web_brute_force' || kind === 'web_csrf' || kind === 'web_xss_reflected') {
                return {
                    source: 'local_rules', verdict: 'confirm', confidence: 0.75,
                    suggestion: 'block', degraded: true, direct_alert: false,
                    reason: '本地规则综合评分判定：聚合风险分显著超过阈值，级别 high，建议立即封禁并取证。',
                    evidence_refs: ['risk_score=4.2', 'rules=' + this._rulesFor(kind)[0]],
                    generated_at: nowText()
                };
            }
            return {
                source: 'template', verdict: 'suspect', confidence: 0.6,
                suggestion: 'watch', degraded: true, direct_alert: false,
                reason: 'API 不可用时的模板研判：符合该攻击大类的典型特征，但单一证据不足以确认，建议继续观察。',
                evidence_refs: ['risk_score=3.6', 'detector=ewma-zscore'], generated_at: nowText()
            };
        },

        _demotedSignals: function () {
            /* 演示"聚合抑制"：未达阈值的信号同样可见（禁止静默丢弃） */
            var seeds = [
                ['198.51.100.23', 'web_csrf', 'WEB-CSRF-001', 'high', 1.8, 'below_threshold'],
                ['45.33.32.156', 'nonstandard_port', 'STAT-NONSTANDARD-PORT', 'medium', 1.5,
                 'below_threshold'],
                ['114.114.114.114', 'web_crlf_injection', 'WEB-CRLF-001', 'medium', 1.5,
                 'below_threshold'],
                ['203.0.113.66', 'port_scan', 'STAT-PORT-SCAN', 'high', 3.6, 'cooldown']
            ];
            return seeds.map(function (seed, index) {
                return {
                    id: 9000 + index, ts: nowText(Date.now() / 1000 - index * 40),
                    source_ip: seed[0], rule_id: seed[2], category: seed[1],
                    severity: seed[3], weight: seed[4], direct_alert: false,
                    suppressed: true, suppressed_reason: seed[5],
                    score_contribution: seed[4], signal_window_id: 'demo-win-' + index
                };
            });
        },

        _thresholds: function () {
            var base = { traffic_spike: 3.5, nonstandard_port: 4.0, port_scan: 60, brute_force: 40 };
            var bucket = new Date().getHours() >= 9 && new Date().getHours() < 19 ? 'workhour' : 'offhour';
            return Object.keys(base).map(function (key, index) {
                var tightened = key === 'nonstandard_port';
                return {
                    id: index + 1, dimension: 'detection_type', dimension_key: key + ':unknown:' + bucket,
                    detection_type: key, asset_class: key === 'traffic_spike' ? 'machine' : 'unknown',
                    time_bucket: bucket, static_value: base[key],
                    threshold_value: tightened ? Math.round(base[key] * 1.3 * 100) / 100 : base[key],
                    sample_count: 12 + index * 3, false_positive_count: tightened ? 9 : 1,
                    true_positive_count: tightened ? 3 : 11,
                    false_positive_rate: tightened ? 0.75 : 0.08,
                    manual_override: false, override_reason: '',
                    last_updated: nowText()
                };
            });
        },

        _block: function (ip, reason, category, severity, ttlSec) {
            var now = Date.now() / 1000;
            if (!ip) { throw new Error('封禁目标为空'); }
            var whitelisted = this.whitelist.some(function (item) {
                return item.cidr === ip + '/32' || item.cidr.indexOf(ip) === 0;
            });
            if (whitelisted) {
                return { success: false, message: '目标 ' + ip + ' 命中白名单，已拒绝封禁',
                         code: 'whitelisted', detail: { whitelisted: true } };
            }
            var existing = this.blocks.filter(function (item) { return item.ip === ip; })[0];
            if (existing) {
                existing.hits += 1;
                return { success: true, message: ip + ' 已在封禁中（命中次数 ' + existing.hits + '）',
                         code: 'duplicated', detail: { duplicated: true } };
            }
            var command = 'iptables -I INPUT 1 -s ' + ip + ' -m comment --comment SECOPS_BLOCK -j DROP';
            this.blocks.unshift({
                id: this.blocks.length + 1, ip: ip, reason: reason, category: category || 'manual',
                severity: severity || 'high', backend: 'iptables', source: 'auto', operator: 'dashboard',
                created_at: nowText(), expires_at: now + ttlSec, active: true, hits: 1, dry_run: true,
                remaining_sec: ttlSec, rule_spec: command
            });
            this.disposals.unshift({
                id: this.disposals.length + 1, ts: nowText(), action: 'block', target: ip,
                detail: '[' + category + '/' + severity + '] ' + reason + ' | 后端=iptables（DRY-RUN）',
                operator: 'dashboard', success: true
            });
            this._emitLists();
            return {
                success: true, message: '已封禁 ' + ip + '（' + ttlSec + ' 秒后自动解封）', code: 'ok',
                detail: { command: command, dry_run: true, expires_at: now + ttlSec }
            };
        },

        _sessions: function (top) {
            var seeds = [
                ['10.20.0.11', 44120, '192.168.1.10', 443], ['10.20.0.12', 51230, '192.168.1.15', 3306],
                ['10.20.0.13', 60122, '192.168.1.30', 6379], ['203.0.113.66', 33001, '192.168.1.20', 4444],
                ['198.51.100.23', 44880, '192.168.1.15', 22], ['10.20.0.14', 38911, '192.168.1.10', 80],
                ['45.33.32.156', 51000, '192.168.1.30', 31337], ['114.114.114.114', 12345, '192.168.1.10', 53]
            ];
            return seeds.slice(0, top).map(function (seed, index) {
                var duration = 30 + index * 47;
                var bytes = Math.floor(rnd(2e5, 3e8));
                return {
                    src_ip: seed[0], src_port: seed[1], dst_ip: seed[2], dst_port: seed[3],
                    protocol: seed[3] === 53 ? 'UDP' : 'TCP',
                    duration_sec: duration, idle_sec: Math.floor(rnd(0, 20)),
                    packets: Math.floor(bytes / 800), bytes: bytes,
                    bps: Math.round(bytes * 8 / duration),
                    pps: Math.round(bytes / 800 / duration * 10) / 10,
                    is_internal: seed[2].indexOf('192.168.') === 0
                };
            });
        }


    };

    global.SecMock = Mock;
})(window);




