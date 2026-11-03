/**
 * cloud.js —— 云端协同层（WorkBuddy 云服务接入）
 *
 * 设计原则
 *   1. 只在大屏侧做「云端协同」，不改动检测/采集/评分主链路：本地后端仍是唯一的检测引擎，
 *      云端只承载「跨设备可追溯的归档、可分享的证据文件、免密钥的大模型研判」三件事。
 *   2. SDK 用 CDN 形态（Form B）懒加载：本项目没有构建链（原生 JS + ECharts），
 *      为一个 SDK 引入 package.json 会破坏「双击即可打开」的部署形态。
 *   3. 云端不可用时整页降级为「离线」，四块功能各自给出明确原因，绝不静默失败、
 *      也不把本地 localStorage 伪装成云端存储。
 *
 * publicConfig 说明
 *   下面的 PUBLIC_CONFIG 就是 workbuddy_cloud_service 工具返回的 publicConfig，
 *   仅含可公开下发的值（resourceId / endpoint / oauthRelayBaseUrl / publishableKey）。
 *   publishableKey 只用于标识「哪个应用」，本身不带任何权限，服务端还会校验 Origin；
 *   真正的环境凭证、模型密钥全部留在服务端，前端拿不到也不需要。
 */
(function (global) {
    'use strict';

    var SDK_URL = 'https://cdn.jsdelivr.net/npm/@tencent-ai/workbuddy-cloud-sdk@dev/lib/index.global.js';

    var PUBLIC_CONFIG = {
        resourceId: 'wbcs_JRIeQXtiTi1gDJSc8sHPUc',
        endpoint: 'https://secops-traffic-guard.app.workbuddy.host',
        oauthRelayBaseUrl: 'https://www.workbuddy.cn/v2/as/genie-baas/oauth',
        publishableKey: 'wbpk_9KxYgKY6BivvmiRO3C90Uc_j93Sja6BEeCpOx7DfLqxwEASa31fOCCr'
    };

    /* 云端归档表（与云数据库中的 secops_archive 一一对应；RLS 按 owner_id 隔离） */
    var ARCHIVE_TABLE = 'secops_archive';
    /* 证据报告在云存储中的目录（users/<uid>/reports/<file>） */
    var REPORT_DIR = 'reports';

    var client = null;
    var loading = null;
    var session = null;
    var lastError = '';

    /* -------------------- SDK 懒加载与初始化 -------------------- */
    function loadSdk() {
        if (global.WorkBuddyCloud) {
            return Promise.resolve(global.WorkBuddyCloud);
        }
        if (loading) {
            return loading;
        }
        loading = new Promise(function (resolve, reject) {
            var script = document.createElement('script');
            script.src = SDK_URL;
            script.async = true;
            script.onload = function () {
                if (global.WorkBuddyCloud && global.WorkBuddyCloud.createWorkBuddyCloud) {
                    resolve(global.WorkBuddyCloud);
                } else {
                    reject(new Error('云端 SDK 已加载但未暴露 WorkBuddyCloud 全局对象'));
                }
            };
            script.onerror = function () {
                loading = null;
                reject(new Error('云端 SDK 加载失败：CDN 不可达或被网络策略拦截'));
            };
            document.head.appendChild(script);
        });
        return loading;
    }

    /* 同一个页面只初始化一次，Auth / Database / Storage / LLM 共用这一个 client */
    function init() {
        if (client) {
            return Promise.resolve(client);
        }
        return loadSdk().then(function (sdk) {
            if (client) {
                return client;
            }
            client = sdk.createWorkBuddyCloud({
                endpoint: PUBLIC_CONFIG.endpoint,
                oauthRelayBaseUrl: PUBLIC_CONFIG.oauthRelayBaseUrl,
                publishableKey: PUBLIC_CONFIG.publishableKey
            });
            return client;
        });
    }

    /* -------------------- 错误文案归一 --------------------
     * 云端各模块的错误形状不同：Auth 用 error.kind，LLM 用 error.error.code，
     * Database / Storage 用 message + PostgreSQL code。统一翻成人话，避免把原始报文糊到界面上。 */
    var AUTH_KIND_TEXT = {
        unauthenticated: '登录状态已失效，请重新登录',
        invalid_grant: '验证码不正确或已过期，请重新获取',
        network: '网络不可达，请检查网络后重试',
        'backend-unavailable': '云端认证服务暂时不可用，请稍后重试'
    };

    var LLM_CODE_TEXT = {
        request_stream_required: '模型调用参数不合法（缺少 stream）',
        auth_: '云端凭证校验未通过：当前访问域名与应用登记域名不一致',
        quota_: '云端模型额度已用尽或被限流，请稍后重试',
        gateway_: '模型网关暂时不可用，请稍后重试',
        model_: '模型服务暂时不可用，请稍后重试',
        internal_: '模型服务内部错误，请稍后重试'
    };

    var PG_CODE_TEXT = {
        '42P01': '云端数据表不存在，请先完成建表',
        '42501': '云端拒绝写入：当前账号没有该数据的权限',
        '23505': '云端已存在同一条记录'
    };

    function describeError(error, fallback) {
        if (!error) {
            return fallback || '未知错误';
        }
        if (error.kind && AUTH_KIND_TEXT[error.kind]) {
            return AUTH_KIND_TEXT[error.kind];
        }
        var code = (error.error && error.error.code) || error.code || '';
        if (code) {
            if (LLM_CODE_TEXT[code]) {
                return LLM_CODE_TEXT[code];
            }
            var prefix = String(code).split('_')[0] + '_';
            if (LLM_CODE_TEXT[prefix]) {
                return LLM_CODE_TEXT[prefix];
            }
            if (PG_CODE_TEXT[code]) {
                return PG_CODE_TEXT[code];
            }
        }
        var raw = String(error.message || '');
        /* 云端网关前面有 Web 应用防火墙：请求体里若带明显攻击特征（例如告警原文里的
           SQL 注入片段），会直接返回 403 的拦截页 HTML，而不是 JSON 错误。 */
        if (/WAF|<html|<!DOCTYPE/i.test(raw)) {
            return '请求被站点安全防护拦截（内容含攻击特征），已阻止本次提交';
        }
        return raw || fallback || '云端请求失败';
    }

    function fail(error, fallback) {
        lastError = describeError(error, fallback);
        var wrapped = new Error(lastError);
        wrapped.raw = error;
        return wrapped;
    }

    /* -------------------- 身份（Auth） -------------------- */
    function currentSession() {
        return init().then(function (cloud) {
            return cloud.auth.getSession();
        }).then(function (result) {
            if (result && result.error) {
                throw fail(result.error, '读取云端会话失败');
            }
            session = (result && result.data) || null;
            return session;
        });
    }

    /* 发送邮箱验证码：新老用户同一条路径，返回值里的 verificationId / isExistingUser
       必须原样带到校验步骤，中途不重新发送（重发会让上一个 verificationId 失效）。 */
    function sendEmailCode(email) {
        return init().then(function (cloud) {
            return cloud.auth.sendOtp({ email: email });
        }).then(function (result) {
            if (result.error) {
                throw fail(result.error, '验证码发送失败');
            }
            return result.data || {};
        });
    }

    function verifyEmailCode(pending, token) {
        return init().then(function (cloud) {
            return cloud.auth.verifyOtp({
                email: pending.email,
                verificationId: pending.verificationId,
                isExistingUser: pending.isExistingUser,
                token: token
            });
        }).then(function (result) {
            if (result.error) {
                throw fail(result.error, '验证码校验失败');
            }
            session = (result.data && result.data.session) || result.data || null;
            return session;
        });
    }

    function signOut() {
        return init().then(function (cloud) {
            return cloud.auth.signOut();
        }).then(function (result) {
            session = null;
            if (result && result.error) {
                throw fail(result.error, '退出失败');
            }
            return true;
        });
    }

    /* 所有云端数据操作的前置闸门：没有会话就返回 null，调用方展示登录引导，不发请求。 */
    function requireSession() {
        return currentSession().then(function (value) {
            return value && value.user && value.user.id ? value : null;
        });
    }

    function userLabel(value) {
        var user = (value && value.user) || {};
        return user.name || user.email || user.id || '云端用户';
    }

    /* -------------------- 归档（Database） -------------------- */
    function archiveInsert(rows) {
        if (!rows || !rows.length) {
            return Promise.resolve([]);
        }
        return requireSession().then(function (active) {
            if (!active) {
                throw new Error('请先登录云端账号，归档数据按账号隔离');
            }
            return init();
        }).then(function (cloud) {
            /* owner_id 一律不传：表上 DEFAULT auth.uid() 由服务端填充，RLS 的
               WITH CHECK (owner_id = auth.uid()) 会拒绝任何伪造归属。 */
            return cloud.database.from(ARCHIVE_TABLE).insert(rows).select();
        }).then(function (result) {
            if (result.error) {
                throw fail(result.error, '归档写入失败');
            }
            return result.data || [];
        });
    }

    function archiveList(limit) {
        return requireSession().then(function (active) {
            if (!active) {
                return { items: [], total: 0, signedIn: false };
            }
            return init().then(function (cloud) {
                return cloud.database
                    .from(ARCHIVE_TABLE)
                    .select('*', { count: 'exact' })
                    .order('created_at', { ascending: false })
                    .limit(limit || 50);
            }).then(function (result) {
                if (result.error) {
                    throw fail(result.error, '读取云端归档失败');
                }
                return {
                    items: result.data || [],
                    total: typeof result.count === 'number' ? result.count : (result.data || []).length,
                    signedIn: true
                };
            });
        });
    }

    function archiveDelete(id) {
        return requireSession().then(function (active) {
            if (!active) {
                throw new Error('请先登录云端账号');
            }
            return init();
        }).then(function (cloud) {
            return cloud.database.from(ARCHIVE_TABLE).delete().eq('id', id).select();
        }).then(function (result) {
            if (result.error) {
                throw fail(result.error, '删除失败');
            }
            var removed = result.data || [];
            /* RLS 过滤掉的行不会报错，只会返回空数组——必须当成"没删掉"来提示 */
            if (!removed.length) {
                throw new Error('这条归档不存在，或不属于当前账号');
            }
            return removed.length;
        });
    }

    /* -------------------- 证据报告（Storage） -------------------- */
    function reportPath(active, name) {
        var uid = active.user.id;
        return client.storage.userPath(uid, REPORT_DIR + '/' + name);
    }

    function uploadReport(name, text) {
        return requireSession().then(function (active) {
            if (!active) {
                throw new Error('请先登录云端账号，云端文件按账号隔离');
            }
            return init().then(function () {
                var body = new Blob([text], { type: 'text/html;charset=utf-8' });
                return client.storage.upload(reportPath(active, name), body, {
                    contentType: 'text/html;charset=utf-8',
                    upsert: true,
                    metadata: { purpose: 'secops-evidence-report' }
                });
            });
        }).then(function (result) {
            if (result && result.error) {
                throw fail(result.error, '上传失败');
            }
            return result && result.data ? result.data : {};
        });
    }

    function listReports(limit) {
        return requireSession().then(function (active) {
            if (!active) {
                return { items: [], signedIn: false };
            }
            return init().then(function () {
                return client.storage.list('users/' + active.user.id + '/' + REPORT_DIR, {
                    limit: limit || 50
                });
            }).then(function (result) {
                if (result && result.error) {
                    throw fail(result.error, '读取云端文件失败');
                }
                var data = (result && result.data) || {};
                var items = data.items || data.objects || data.files || (Array.isArray(data) ? data : []);
                return { items: items, signedIn: true };
            });
        });
    }

    /* 签名链接的返回结构在不同 SDK 版本里字段名不一致，这里做收敛取值，
       取不到就退回 download() 拿 Blob——两条路都走云端权限校验。 */
    function pickUrl(data) {
        if (!data) {
            return '';
        }
        if (typeof data === 'string') {
            return /^https?:/i.test(data) ? data : '';
        }
        var keys = ['signedUrl', 'signedURL', 'url', 'downloadUrl'];
        for (var i = 0; i < keys.length; i += 1) {
            if (typeof data[keys[i]] === 'string' && /^https?:/i.test(data[keys[i]])) {
                return data[keys[i]];
            }
        }
        return '';
    }

    function reportUrl(path) {
        return requireSession().then(function (active) {
            if (!active) {
                throw new Error('请先登录云端账号');
            }
            return init().then(function () {
                return client.storage.createSignedUrl(path, 600);
            });
        }).then(function (result) {
            if (result && result.error) {
                throw fail(result.error, '生成下载链接失败');
            }
            var url = pickUrl(result && result.data);
            if (url) {
                return url;
            }
            return client.storage.download(path).then(function (blob) {
                if (!blob) {
                    throw new Error('云端未返回文件内容');
                }
                var real = blob instanceof Blob ? blob : (blob.data instanceof Blob ? blob.data : null);
                if (!real) {
                    throw new Error('云端文件内容格式无法识别');
                }
                return URL.createObjectURL(real);
            });
        });
    }

    function removeReport(path) {
        return requireSession().then(function (active) {
            if (!active) {
                throw new Error('请先登录云端账号');
            }
            return init().then(function () {
                return client.storage.remove([path]);
            });
        }).then(function (result) {
            if (result && result.error) {
                throw fail(result.error, '删除云端文件失败');
            }
            return true;
        });
    }

    /* -------------------- 大模型（LLM） -------------------- */
    /* 首选与后端 AI 研判同族的 DeepSeek-V4.1-Flash；目录里没有它时退到服务端默认模型。
       绝不在目录为空时硬编码模型 id —— 那等于绕过可用性判断。 */
    var PREFERRED_MODEL = 'deepseek-v4.1-flash';

    function listModels() {
        return init().then(function (cloud) {
            return cloud.llm.models.list();
        }).then(function (models) {
            var list = (models && (models.data || models.models)) || models;
            if (!Array.isArray(list)) {
                return [];
            }
            return list.filter(function (item) {
                return item && item.disabled !== true && item.enabled !== false;
            });
        });
    }

    function pickModel(list) {
        if (!list || !list.length) {
            return null;
        }
        for (var i = 0; i < list.length; i += 1) {
            if (list[i].id === PREFERRED_MODEL) {
                return list[i];
            }
        }
        for (var j = 0; j < list.length; j += 1) {
            if (list[j].isDefault) {
                return list[j];
            }
        }
        return list[0];
    }

    /**
     * 流式生成。onDelta 用于增量渲染，返回整段文本。
     * 每一条 messages 的第一项必须是应用自带的 system 消息，否则服务端直接拒绝。
     */
    function generate(options) {
        var controller = new AbortController();
        var answer = '';
        var usage = null;

        var task = init().then(function (cloud) {
            return cloud.llm.chat.completions.create({
                model: options.model,
                messages: [
                    { role: 'system', content: options.system },
                    { role: 'user', content: options.user }
                ],
                stream: true,
                stream_options: { include_usage: true },
                temperature: options.temperature === undefined ? 0.3 : options.temperature,
                signal: controller.signal
            });
        }).then(function (stream) {
            return (async function () {
                /* eslint-disable no-restricted-syntax */
                for await (var chunk of stream) {
                    var delta = chunk && chunk.choices && chunk.choices[0] && chunk.choices[0].delta;
                    if (delta && delta.content) {
                        answer += delta.content;
                        if (options.onDelta) {
                            options.onDelta(delta.content);
                        }
                    }
                    if (chunk && chunk.usage) {
                        usage = chunk.usage;
                    }
                }
                return { text: answer, usage: usage };
            })();
        }).catch(function (error) {
            if (error && error.name === 'AbortError') {
                /* 用户主动停止：保留已生成内容，不当成失败 */
                return { text: answer, usage: usage, aborted: true };
            }
            var code = (error && error.error && error.error.code) || (error && error.code) || '';
            if (code === 'gateway_stream_interrupted') {
                var broken = new Error('模型输出流被中断，已保留已生成的内容，可重新生成');
                broken.partial = answer;
                throw broken;
            }
            throw fail(error, '模型调用失败');
        });

        task.abort = function () { controller.abort(); };
        return task;
    }

    /* -------------------- 对外接口 -------------------- */
    global.SecCloud = {
        config: PUBLIC_CONFIG,
        init: init,
        describeError: describeError,
        /* 身份 */
        getSession: currentSession,
        requireSession: requireSession,
        sendEmailCode: sendEmailCode,
        verifyEmailCode: verifyEmailCode,
        signOut: signOut,
        userLabel: userLabel,
        /* 归档 */
        archiveInsert: archiveInsert,
        archiveList: archiveList,
        archiveDelete: archiveDelete,
        /* 证据文件 */
        uploadReport: uploadReport,
        listReports: listReports,
        reportUrl: reportUrl,
        removeReport: removeReport,
        /* 大模型 */
        listModels: listModels,
        pickModel: pickModel,
        generate: generate,
        lastError: function () { return lastError; }
    };
})(window);
