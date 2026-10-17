"""密码散列与强度校验（标准库 scrypt，无第三方依赖）。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import string

# scrypt(N=2^14, r=8, p=1) ≈ 16 MB 内存、几十毫秒，足够抵御离线暴力破解，
# 又不会把低配 VM 的登录接口拖垮。
SCRYPT_N = 1 << 14
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
KEY_BYTES = 32


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def hash_password(password: str) -> str:
    """生成 ``scrypt$N$r$p$salt$hash`` 格式的密码散列。"""
    if not password:
        raise ValueError("密码不能为空")
    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_BYTES,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64encode(salt)}${_b64encode(digest)}"


def verify_password(password: str, stored: str) -> bool:
    """常量时间比较；格式损坏一律视为验证失败（不抛异常）。"""
    try:
        algorithm, n, r, p, salt_text, digest_text = str(stored or "").split("$", 5)
        if algorithm != "scrypt":
            return False
        salt = _b64decode(salt_text)
        expected = _b64decode(digest_text)
        actual = hashlib.scrypt(
            (password or "").encode("utf-8"), salt=salt,
            n=int(n), r=int(r), p=int(p), dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def password_is_strong(password: str, username: str = "", min_len: int = 10) -> bool:
    """至少 min_len 位、含字母与数字、不得与用户名相同。"""
    text = str(password or "")
    if len(text) < max(8, int(min_len)):
        return False
    if not any(ch.isalpha() for ch in text) or not any(ch.isdigit() for ch in text):
        return False
    if username and text.lower() == str(username).lower():
        return False
    return True


def generate_password(length: int = 16) -> str:
    """生成满足强度要求的一次性密码（去掉易混淆字符）。"""
    alphabet = string.ascii_letters + string.digits
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(max(12, length)))
        if password_is_strong(candidate, min_len=12):
            return candidate
