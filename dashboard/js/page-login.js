/**
 * page-login.js —— 登录与首次改密（v6 P0）
 *
 * 只使用同源 Cookie 会话；CSRF Token 由登录响应返回，仅保存在本页内存中，
 * 改密后立即跳转，不写入 localStorage（降低 XSS 场景下的泄露面）。
 */
(function () {
    'use strict';

    var csrf = '';
    var apiBase = '/api/v1';
    var loginForm = document.getElementById('loginForm');
    var passwordForm = document.getElementById('passwordForm');
    var errorBox = document.getElementById('loginError');
    var passwordError = document.getElementById('passwordError');

    function showError(node, message) {
        node.textContent = message || '';
    }

    function target() {
        var params = new URLSearchParams(window.location.search);
        var next = params.get('next') || '/';
        // 只接受同源绝对路径；同时拒绝 //host 与 /\host（浏览器会把反斜杠归一化为 /）。
        if (next.charAt(0) !== '/' || next.charAt(1) === '/' || next.charAt(1) === '\\') {
            return '/';
        }
        try {
            var resolved = new URL(next, window.location.origin);
            if (resolved.origin !== window.location.origin) {
                return '/';
            }
            return resolved.pathname + resolved.search + resolved.hash;
        } catch (error) {
            return '/';
        }
    }

    function enter() {
        window.location.replace(target());
    }

    function request(method, path, body) {
        var options = {
            method: method,
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' },
            cache: 'no-store'
        };
        if (body !== undefined) {
            options.headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(body);
        }
        if (csrf) {
            options.headers['X-CSRF-Token'] = csrf;
        }
        return fetch(apiBase + path, options).then(function (response) {
            return response.text().then(function (text) {
                var data = null;
                try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
                if (!response.ok) {
                    var detail = (data && data.detail) || text || ('HTTP ' + response.status);
                    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
                }
                return data;
            });
        });
    }

    function showPasswordForm() {
        loginForm.classList.add('hidden');
        passwordForm.classList.remove('hidden');
        document.getElementById('currentPassword').focus();
    }

    // 已登录则直接进入，避免刷新登录页时重复登录
    request('GET', '/auth/me').then(function (data) {
        if (data && data.user && !data.user.must_change_password) {
            enter();
        } else if (data && data.user) {
            csrf = data.csrf_token || '';
            showPasswordForm();
        }
    }).catch(function () { /* 未登录：停留在登录表单 */ });

    loginForm.addEventListener('submit', function (event) {
        event.preventDefault();
        showError(errorBox, '');
        var username = document.getElementById('username').value.trim();
        var password = document.getElementById('password').value;
        if (!username || !password) {
            showError(errorBox, '请输入用户名与密码');
            return;
        }
        var button = document.getElementById('btnLogin');
        button.disabled = true;
        request('POST', '/auth/login', { username: username, password: password })
            .then(function (data) {
                csrf = data.csrf_token || '';
                if (data.must_change_password) {
                    document.getElementById('currentPassword').value = password;
                    showPasswordForm();
                } else {
                    enter();
                }
            })
            .catch(function (error) {
                showError(errorBox, error.message || '登录失败');
            })
            .finally(function () { button.disabled = false; });
    });

    passwordForm.addEventListener('submit', function (event) {
        event.preventDefault();
        showError(passwordError, '');
        var current = document.getElementById('currentPassword').value;
        var next = document.getElementById('newPassword').value;
        var confirm = document.getElementById('confirmPassword').value;
        if (next !== confirm) {
            showError(passwordError, '两次输入的新密码不一致');
            return;
        }
        var button = document.getElementById('btnChangePassword');
        button.disabled = true;
        request('POST', '/auth/password', {
            current_password: current, new_password: next
        }).then(function () {
            enter();
        }).catch(function (error) {
            showError(passwordError, error.message || '修改密码失败');
        }).finally(function () { button.disabled = false; });
    });
})();
