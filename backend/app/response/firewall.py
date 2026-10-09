"""防火墙适配层：iptables / nftables / firewalld 三后端统一接口。

安全要点（生产环境务必遵守）：

* 所有命令以**列表参数**形式传给 ``subprocess``（等价于 shell=False），且先经 ``ipaddress`` 校验，
  从根上杜绝命令注入 —— 这是"自动封禁"功能最常见的失守点；
* ``DRY_RUN`` 默认开启：只记录待下发规则、不真正改内核表，人工确认后再关闭；
* 规则统一带 ``SECOPS`` 注释标记，便于审计、批量清理与故障回滚。
"""

from __future__ import annotations

import ipaddress
import logging
import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

RULE_TAG = "SECOPS_BLOCK"


class FirewallError(RuntimeError):
    """防火墙操作失败。"""


def validate_target(value: str) -> str:
    """校验 IP / CIDR；非法输入直接抛出，绝不拼接进命令行。"""
    value = (value or "").strip()
    if not value:
        raise FirewallError("封禁目标为空")
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError as exc:
        raise FirewallError(f"非法 IP/CIDR: {value}") from exc
    return value


class FirewallBackend(ABC):
    """统一防火墙接口：block / unblock / is_available。"""

    name = "none"

    def __init__(self, dry_run: bool = True, chain: str = "INPUT") -> None:
        self.dry_run = bool(dry_run)
        self.chain = chain

    # ---------------- 子类实现 ----------------
    @abstractmethod
    def block(self, target: str, ttl_sec: Optional[int] = None) -> Tuple[bool, str, List[str]]:
        """下发封禁，返回 (是否成功, 说明, 实际命令列表)。"""

    @abstractmethod
    def unblock(self, target: str) -> Tuple[bool, str, List[str]]:
        """解除封禁。"""

    @abstractmethod
    def is_available(self) -> bool:
        """后端是否可用（命令存在且具备执行权限）。"""

    # ---------------- 公共工具 ----------------
    def _run(self, args: Sequence[str], require: Optional[str] = None) -> Tuple[bool, str]:
        cmd = list(args)
        missing = bool(require) and shutil.which(require) is None

        # DRY-RUN：只预演命令、不要求二进制存在（因此可在 Windows/CI 上安全验证封禁链路）
        if self.dry_run:
            logger.info("[DRY-RUN]%s %s", "（当前环境缺少 %s）" % require if missing else "", " ".join(cmd))
            suffix = f"；注意：当前环境未安装 {require}，DRY_RUN=false 后将无法真正生效" if missing else ""
            return True, f"dry-run（未真正下发，DRY_RUN=false 后生效）{suffix}"

        if missing:
            return False, f"未找到命令 {require}，请先安装或检查 PATH"
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
        except subprocess.TimeoutExpired:
            return False, f"命令执行超时: {' '.join(cmd)}"
        except Exception as exc:  # pragma: no cover - 平台相关
            return False, f"命令执行异常: {exc}"
        if proc.returncode != 0:
            message = (proc.stderr or proc.stdout or "").strip() or f"退出码 {proc.returncode}"
            logger.warning("防火墙命令失败: %s -> %s", " ".join(cmd), message)
            return False, message
        return True, "ok"

    def describe(self) -> str:
        return f"{self.name}({'DRY-RUN' if self.dry_run else 'LIVE'})"


class IptablesBackend(FirewallBackend):
    """iptables：按来源地址 DROP（兼容 CentOS7 / Ubuntu20.04 等存量系统）。"""

    name = "iptables"

    def is_available(self) -> bool:
        return shutil.which("iptables") is not None

    def block(self, target: str, ttl_sec: Optional[int] = None) -> Tuple[bool, str, List[str]]:
        target = validate_target(target)
        args = ["iptables", "-I", self.chain, "1", "-s", target, "-m", "comment",
                "--comment", RULE_TAG, "-j", "DROP"]
        ok, message = self._run(args, require="iptables")
        return ok, message, args

    def unblock(self, target: str) -> Tuple[bool, str, List[str]]:
        target = validate_target(target)
        args = ["iptables", "-D", self.chain, "-s", target, "-m", "comment",
                "--comment", RULE_TAG, "-j", "DROP"]
        ok, message = self._run(args, require="iptables")
        if not ok and "does a matching rule exist" in message:
            return True, "规则不存在，视为已解封", args
        return ok, message, args


class NftablesBackend(FirewallBackend):
    """nftables：命名集合 + timeout 元素，支持内核级自动到期（省一条清理定时任务）。

    ``blocklist`` 存单 IP（兼容旧版本已创建的 timeout 集合）；
    ``blocklist_cidr`` 使用 ``flags interval,timeout`` 存 CIDR。分开是为了让
    已存在的旧集合无需删除重建，也能立刻支持网段封禁。
    """

    name = "nftables"
    table = "secops"
    set_name = "blocklist"
    cidr_set_name = "blocklist_cidr"

    def __init__(self, dry_run: bool = True, chain: str = "INPUT") -> None:
        super().__init__(dry_run=dry_run, chain=chain)
        self._initialized = False

    def is_available(self) -> bool:
        return shutil.which("nft") is not None

    def _ensure_set(self) -> Tuple[bool, str]:
        """建表/集合/**链与 drop 规则**（旧实现漏了最后一步，封禁在内核不生效）。"""
        if self._initialized:
            return True, "ok"
        table_args = ["nft", "add", "table", "inet", self.table]
        set_args = ["nft", "add", "set", "inet", self.table, self.set_name,
                    "{ type ipv4_addr; flags timeout; }"]
        cidr_set_args = ["nft", "add", "set", "inet", self.table, self.cidr_set_name,
                         "{ type ipv4_addr; flags interval,timeout; }"]
        hook = {"INPUT": "input", "FORWARD": "forward", "OUTPUT": "output"}.get(
            str(self.chain or "INPUT").upper(), "input")
        chain_args = ["nft", "add", "chain", "inet", self.table, hook,
                      f"{{ type filter hook {hook} priority 0; policy accept; }}"]
        rule_args = ["nft", "add", "rule", "inet", self.table, hook,
                     "ip", "saddr", f"@{self.set_name}", "drop"]
        cidr_rule_args = ["nft", "add", "rule", "inet", self.table, hook,
                          "ip", "saddr", f"@{self.cidr_set_name}", "drop"]
        for args in (table_args, set_args, cidr_set_args, chain_args,
                     rule_args, cidr_rule_args):
            ok, message = self._run(args, require="nft")
            if not ok and "File exists" not in message and "already exists" not in message:
                return False, message
        self._initialized = True
        return True, "ok"

    def _target_set(self, target: str) -> str:
        return self.cidr_set_name if "/" in target else self.set_name

    def block(self, target: str, ttl_sec: Optional[int] = None) -> Tuple[bool, str, List[str]]:
        target = validate_target(target)
        ok, message = self._ensure_set()
        if not ok:
            return False, message, []
        element = f"{{ {target} timeout {int(ttl_sec)}s }}" if ttl_sec else f"{{ {target} }}"
        args = ["nft", "add", "element", "inet", self.table,
                self._target_set(target), element]
        ok, message = self._run(args, require="nft")
        return ok, message, args

    def unblock(self, target: str) -> Tuple[bool, str, List[str]]:
        target = validate_target(target)
        args = ["nft", "delete", "element", "inet", self.table,
                self._target_set(target), "{", target, "}"]
        ok, message = self._run(args, require="nft")
        return ok, message, args


class FirewalldBackend(FirewallBackend):
    """firewalld：rich rule 方式，兼容 RHEL / openEuler 默认防火墙。"""

    name = "firewalld"

    def is_available(self) -> bool:
        return shutil.which("firewall-cmd") is not None

    def _rich_rule(self, target: str) -> str:
        return f'rule family="ipv4" source address="{target}" drop'

    def block(self, target: str, ttl_sec: Optional[int] = None) -> Tuple[bool, str, List[str]]:
        target = validate_target(target)
        args = ["firewall-cmd", "--permanent", f"--add-rich-rule={self._rich_rule(target)}"]
        ok, message = self._run(args, require="firewall-cmd")
        if not ok:
            return False, message, args
        ok, message = self._run(["firewall-cmd", "--reload"], require="firewall-cmd")
        if not ok:
            return False, f"规则已写入但重载失败: {message}", args
        return True, "ok", args

    def unblock(self, target: str) -> Tuple[bool, str, List[str]]:
        target = validate_target(target)
        args = ["firewall-cmd", "--permanent", f"--remove-rich-rule={self._rich_rule(target)}"]
        ok, message = self._run(args, require="firewall-cmd")
        if not ok:
            return False, message, args
        ok, message = self._run(["firewall-cmd", "--reload"], require="firewall-cmd")
        return ok, message, args


class NullFirewallBackend(FirewallBackend):
    """降级后端：环境无防火墙命令（如 Windows 开发机）时使用。

    此时封禁动作只落库、不落内核；大屏与接口会显式提示「未在内核生效」，
    避免产生"已封禁"的错觉。
    """

    name = "none"

    def is_available(self) -> bool:
        return False

    def block(self, target: str, ttl_sec: Optional[int] = None) -> Tuple[bool, str, List[str]]:
        target = validate_target(target)
        message = "未检测到 iptables/nft/firewall-cmd：封禁已入库记录，但未在内核生效"
        logger.warning("%s -> %s", message, target)
        return True, message, []

    def unblock(self, target: str) -> Tuple[bool, str, List[str]]:
        validate_target(target)
        return True, "无内核规则需要移除", []


def detect_backend_name() -> str:
    """探测本机可用的防火墙实现。"""
    for command, name in (("iptables", "iptables"), ("nft", "nftables"), ("firewall-cmd", "firewalld")):
        if shutil.which(command):
            return name
    return "none"


def build_backend(backend: str = "auto", dry_run: bool = True, chain: str = "INPUT") -> FirewallBackend:
    """按配置构建后端；``auto`` 表示自动探测。"""
    name = (backend or "auto").lower()
    if name == "auto":
        name = detect_backend_name()
    factory = {
        "iptables": IptablesBackend,
        "nftables": NftablesBackend,
        "firewalld": FirewalldBackend,
        "none": NullFirewallBackend,
    }.get(name, NullFirewallBackend)
    instance = factory(dry_run=dry_run, chain=chain)
    logger.info("防火墙后端: %s", instance.describe())
    return instance

