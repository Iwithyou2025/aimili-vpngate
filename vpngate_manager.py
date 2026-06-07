#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import os
import queue
import re
import select
import shlex
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import concurrent.futures
import sys
import uuid
from datetime import date, timedelta
import hashlib
import random

# Force socket to resolve IPv4 only to avoid slow AAAA (IPv6) DNS resolution timeouts (e.g. in WSL)
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0:
        family = socket.AF_INET
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_getaddrinfo

import vpn_utils
import proxy_server


def env_flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}

API_URL = "https://www.vpngate.net/api/iphone/"
FETCH_INTERVAL_SECONDS = int(os.environ.get("FETCH_INTERVAL_SECONDS", "960"))
CHECK_INTERVAL_SECONDS = int(os.environ.get("CHECK_INTERVAL_SECONDS", "960"))
TARGET_VALID_NODES = int(os.environ.get("TARGET_VALID_NODES", "3"))
MAX_SCAN_ROWS = int(os.environ.get("MAX_SCAN_ROWS", "300"))

PREFERRED_COUNTRIES = [
    c.strip().upper()
    for c in os.environ.get("PREFERRED_COUNTRIES", "JP,KR,US,CA").split(",")
    if c.strip()
]

PREFERRED_COUNTRY_MIN_NODES = int(os.environ.get("PREFERRED_COUNTRY_MIN_NODES", "10"))
PREFERRED_COUNTRY_SCAN_ROWS = int(os.environ.get("PREFERRED_COUNTRY_SCAN_ROWS", "2000"))
TEST_BATCH_SIZE = int(os.environ.get("TEST_BATCH_SIZE", "30"))



OPENVPN_PROBE_TIMEOUT_SECONDS = int(os.environ.get("OPENVPN_PROBE_TIMEOUT_SECONDS", "20"))


OPENVPN_TEST_TIMEOUT_SECONDS = int(os.environ.get("OPENVPN_TEST_TIMEOUT_SECONDS", "35"))
OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "0.0.0.0")
LOCAL_PROXY_PORT = int(os.environ.get("LOCAL_PROXY_PORT", "7928"))
PROXY_AUTH_ENABLED = os.environ.get("PROXY_AUTH_ENABLED", "0").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
PROXY_USERNAME = os.environ.get("PROXY_USERNAME", "")
PROXY_PASSWORD = os.environ.get("PROXY_PASSWORD", "")
PROXY_AUTH_ENV_FILE = Path(os.environ.get("AIMILIVPN_ENV_FILE", "/etc/default/aimilivpn"))
UI_HOST = os.environ.get("UI_HOST", "0.0.0.0")
UI_PORT = int(os.environ.get("UI_PORT", "8787"))
INVALID_BACKOFF_SECONDS = int(os.environ.get("INVALID_BACKOFF_SECONDS", str(30 * 60)))

LOGIN_FAIL_MAX_ATTEMPTS = max(
    1,
    int(os.environ.get("LOGIN_FAIL_MAX_ATTEMPTS", "5"))
)

LOGIN_FAIL_WINDOW_SECONDS = max(
    60,
    int(os.environ.get("LOGIN_FAIL_WINDOW_SECONDS", str(10 * 60)))
)

LOGIN_LOCK_SECONDS = max(
    60,
    int(os.environ.get("LOGIN_LOCK_SECONDS", str(10 * 60)))
)

TRUST_PROXY_HEADERS = env_flag("TRUST_PROXY_HEADERS", "0")

# IP 质量检测策略：自动切换时启用；手动连接仍允许临时测试
QUALITY_CHECK_ENABLED = env_flag("QUALITY_CHECK_ENABLED", "1")
IPPURE_API_URL = os.environ.get("IPPURE_API_URL", "https://my.ippure.com/v1/info")
QUALITY_HTTP_TIMEOUT_SECONDS = int(os.environ.get("QUALITY_HTTP_TIMEOUT_SECONDS", "12"))

IPAPI_API_URL = os.environ.get("IPAPI_API_URL", "https://api.ipapi.is")

# 是否启用 ipapi.is 补充检测
QUALITY_CHECK_IPAPI_ENABLED = env_flag("QUALITY_CHECK_IPAPI_ENABLED", "1")

# ipapi.is 请求失败时是否直接判定失败
# 建议默认 0，避免第三方 API 抽风导致误杀节点
QUALITY_IPAPI_STRICT = env_flag("QUALITY_IPAPI_STRICT", "0")

# ipapi.is 风险字段拦截开关
QUALITY_REJECT_IPAPI_BOGON = env_flag("QUALITY_REJECT_IPAPI_BOGON", "1")
QUALITY_REJECT_IPAPI_CRAWLER = env_flag("QUALITY_REJECT_IPAPI_CRAWLER", "1")
QUALITY_REJECT_IPAPI_DATACENTER = env_flag("QUALITY_REJECT_IPAPI_DATACENTER", "1")
QUALITY_REJECT_IPAPI_TOR = env_flag("QUALITY_REJECT_IPAPI_TOR", "1")
QUALITY_REJECT_IPAPI_PROXY = env_flag("QUALITY_REJECT_IPAPI_PROXY", "1")
QUALITY_REJECT_IPAPI_VPN = env_flag("QUALITY_REJECT_IPAPI_VPN", "1")
QUALITY_REJECT_IPAPI_ABUSER = env_flag("QUALITY_REJECT_IPAPI_ABUSER", "1")

# mobile / satellite 不一定代表差，默认先不拦截
QUALITY_REJECT_IPAPI_MOBILE = env_flag("QUALITY_REJECT_IPAPI_MOBILE", "0")
QUALITY_REJECT_IPAPI_SATELLITE = env_flag("QUALITY_REJECT_IPAPI_SATELLITE", "0")

QUALITY_MAX_FRAUD_SCORE = int(os.environ.get("QUALITY_MAX_FRAUD_SCORE", "30"))
QUALITY_REQUIRE_RESIDENTIAL = env_flag("QUALITY_REQUIRE_RESIDENTIAL", "1")
QUALITY_REQUIRE_NATIVE = env_flag("QUALITY_REQUIRE_NATIVE", "1")
QUALITY_MIN_HUMAN_RATIO = int(os.environ.get("QUALITY_MIN_HUMAN_RATIO", "0"))
QUALITY_FAIL_COOLDOWN_SECONDS = int(os.environ.get("QUALITY_FAIL_COOLDOWN_SECONDS", str(30 * 60)))

# 硬质量失败冷却：IPPure 超标 / ipapi 风险命中 / 非住宅 / 非原生等，默认 7 天
QUALITY_HARD_FAIL_COOLDOWN_SECONDS = int(
    os.environ.get("QUALITY_HARD_FAIL_COOLDOWN_SECONDS", str(7 * 24 * 60 * 60))
)

# 7928 代理出口测速：只下载前 16MB，低于 1MB/s 判定节点过慢
QUALITY_CHECK_SPEED_ENABLED = env_flag("QUALITY_CHECK_SPEED_ENABLED", "1")

QUALITY_SPEED_TEST_URL = os.environ.get(
    "QUALITY_SPEED_TEST_URL",
    "https://raw.githubusercontent.com/Iwithyou2025/aimili-vpngate/main/speedtest_80m.bin"
)

QUALITY_SPEED_TEST_BYTES = max(
    1024 * 1024,
    int(os.environ.get("QUALITY_SPEED_TEST_BYTES", str(16 * 1024 * 1024)))
)

QUALITY_MIN_DOWNLOAD_SPEED_BPS = max(
    1,
    int(os.environ.get("QUALITY_MIN_DOWNLOAD_SPEED_BPS", str(1024 * 1024)))
)

QUALITY_SPEED_CONNECT_TIMEOUT_SECONDS = max(
    3,
    int(os.environ.get("QUALITY_SPEED_CONNECT_TIMEOUT_SECONDS", "8"))
)

QUALITY_SPEED_HTTP_TIMEOUT_SECONDS = max(
    15,
    int(os.environ.get("QUALITY_SPEED_HTTP_TIMEOUT_SECONDS", "25"))
)

# 测速接口异常是否直接判定失败
# 默认 0：测速异常只记录，不误杀节点
QUALITY_SPEED_STRICT = env_flag("QUALITY_SPEED_STRICT", "0")

# 使用 Ookla speedtest CLI 通过 tun0 测速
SPEEDTEST_CMD = os.environ.get("SPEEDTEST_CMD", "speedtest")
SPEEDTEST_INTERFACE = os.environ.get("SPEEDTEST_INTERFACE", "tun0")

SPEEDTEST_TIMEOUT_SECONDS = max(
    30,
    int(os.environ.get("SPEEDTEST_TIMEOUT_SECONDS", "90"))
)

SPEEDTEST_RETRY_TIMES = max(
    1,
    int(os.environ.get("SPEEDTEST_RETRY_TIMES", "3"))
)

SPEEDTEST_RETRY_DELAY_SECONDS = max(
    0,
    int(os.environ.get("SPEEDTEST_RETRY_DELAY_SECONDS", "3"))
)

# speedtest 不存在时，是否自动安装
SPEEDTEST_AUTO_INSTALL = env_flag("SPEEDTEST_AUTO_INSTALL", "1")

SPEEDTEST_INSTALL_TIMEOUT_SECONDS = max(
    60,
    int(os.environ.get("SPEEDTEST_INSTALL_TIMEOUT_SECONDS", "240"))
)

PROXY_HEALTH_CONFIRM_TIMES = max(
    1,
    int(os.environ.get("PROXY_HEALTH_CONFIRM_TIMES", "2"))
)

PROXY_HEALTH_CONFIRM_DELAY_SECONDS = max(
    0,
    int(os.environ.get("PROXY_HEALTH_CONFIRM_DELAY_SECONDS", "2"))
)

# 自动切换策略：默认只在当前活动节点的同一国家内切换
AUTO_SWITCH_SAME_COUNTRY_ONLY = env_flag("AUTO_SWITCH_SAME_COUNTRY_ONLY", "1")
AUTO_SWITCH_MAX_ATTEMPTS = int(os.environ.get("AUTO_SWITCH_MAX_ATTEMPTS", "0"))  # 0 表示直到候选耗尽


ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"

SYSTEM_CA_BUNDLE = Path(os.environ.get("SYSTEM_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt"))

OPENVPN_CA_BUNDLE = Path(
    os.environ.get(
        "OPENVPN_CA_BUNDLE",
        str(ROOT_DIR / "certs" / "vpngate-ca-bundle.pem"),
    )
).resolve()

LE_GENY_CA_URLS = [
    ("root-yr.pem", "https://letsencrypt.org/certs/gen-y/root-yr.pem"),
    ("int-yr1.pem", "https://letsencrypt.org/certs/gen-y/int-yr1.pem"),
    ("int-yr2.pem", "https://letsencrypt.org/certs/gen-y/int-yr2.pem"),
    ("int-yr3.pem", "https://letsencrypt.org/certs/gen-y/int-yr3.pem"),
]

NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"
PROJECT_UPDATE_CONFIG_FILE = DATA_DIR / "project_update.json"
LAST_CONNECTED_NODE_FILE = DATA_DIR / "last_connected_node.json"
OPENVPN_FAILURE_REASONS_FILE = DATA_DIR / "openvpn_failure_reasons.json"
PROJECT_AUTO_UPDATE_INTERVAL_SECONDS = max(
    3,
    int(os.environ.get("PROJECT_AUTO_UPDATE_INTERVAL_SECONDS", "3"))
)
lock = threading.RLock()

project_update_lock = threading.Lock()

active_sessions: dict[str, float] = {}
active_openvpn_process: subprocess.Popen[str] | None = None
active_openvpn_node_id = ""
login_failures: dict[str, dict[str, float | int]] = {}
is_connecting = True
last_active_ping_time = 0.0
last_active_latency = 0

IPAPI_RISK_FIELD_LABELS = {
    "is_bogon": "保留/异常地址 bogon",
    "is_mobile": "移动网络 mobile",
    "is_satellite": "卫星网络 satellite",
    "is_crawler": "爬虫 crawler",
    "is_datacenter": "数据中心 datacenter",
    "is_tor": "Tor 网络",
    "is_proxy": "代理 proxy",
    "is_vpn": "VPN",
    "is_abuser": "滥用 IP abuser",
}


IPAPI_REJECT_CONFIG = {
    "is_bogon": lambda: QUALITY_REJECT_IPAPI_BOGON,
    "is_mobile": lambda: QUALITY_REJECT_IPAPI_MOBILE,
    "is_satellite": lambda: QUALITY_REJECT_IPAPI_SATELLITE,
    "is_crawler": lambda: QUALITY_REJECT_IPAPI_CRAWLER,
    "is_datacenter": lambda: QUALITY_REJECT_IPAPI_DATACENTER,
    "is_tor": lambda: QUALITY_REJECT_IPAPI_TOR,
    "is_proxy": lambda: QUALITY_REJECT_IPAPI_PROXY,
    "is_vpn": lambda: QUALITY_REJECT_IPAPI_VPN,
    "is_abuser": lambda: QUALITY_REJECT_IPAPI_ABUSER,
}
def ensure_openvpn_ca_bundle() -> None:
    """
    生成 OpenVPN 专用 CA bundle。

    用途：
    - 兼容部分 VPNGate 节点使用 Let's Encrypt YR1 / YR2 / YR3 证书链；
    - 避免 OpenVPN 报：
      VERIFY ERROR: unable to get local issuer certificate
    """
    try:
        if OPENVPN_CA_BUNDLE.is_file() and OPENVPN_CA_BUNDLE.stat().st_size > 0:
            return

        OPENVPN_CA_BUNDLE.parent.mkdir(parents=True, exist_ok=True)

        parts: list[bytes] = []
        got_root_yr = False
        got_intermediate = False

        for filename, url in LE_GENY_CA_URLS:
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "AimiliVPN/1.0"},
                )
                with urllib.request.urlopen(req, timeout=12) as resp:
                    data = resp.read()

                if b"BEGIN CERTIFICATE" not in data:
                    print(f"[CA] 跳过异常证书内容: {filename}", flush=True)
                    continue

                parts.append(data)

                if filename == "root-yr.pem":
                    got_root_yr = True
                elif filename.startswith("int-yr"):
                    got_intermediate = True

                print(f"[CA] 已下载 Let's Encrypt 证书: {filename}", flush=True)

            except Exception as e:
                print(f"[CA] 下载 {filename} 失败: {e}", flush=True)

        if SYSTEM_CA_BUNDLE.is_file():
            try:
                parts.append(SYSTEM_CA_BUNDLE.read_bytes())
            except Exception as e:
                print(f"[CA] 读取系统 CA bundle 失败: {e}", flush=True)

        if got_root_yr and got_intermediate and parts:
            tmp = OPENVPN_CA_BUNDLE.with_suffix(".tmp")
            tmp.write_bytes(b"\n".join(parts) + b"\n")
            tmp.replace(OPENVPN_CA_BUNDLE)

            try:
                OPENVPN_CA_BUNDLE.chmod(0o644)
            except OSError:
                pass

            print(f"[CA] OpenVPN CA bundle 已生成: {OPENVPN_CA_BUNDLE}", flush=True)
        else:
            print(
                "[CA] 警告: 未能生成完整的 Let's Encrypt YR CA bundle，"
                "部分 VPNGate 节点可能出现证书链验证失败。",
                flush=True,
            )

    except Exception as e:
        print(f"[CA] 初始化 OpenVPN CA bundle 失败: {e}", flush=True)

def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    CONFIG_DIR.mkdir(exist_ok=True)

    ensure_openvpn_ca_bundle()

    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass

def write_json(path: Path, data: Any) -> None:
    with lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

SENSITIVE_STATE_KEYS = {
    "proxy_username",
    "proxy_password",
}


def sanitize_state_for_disk(state: dict[str, Any]) -> dict[str, Any]:
    clean = dict(state)

    for key in SENSITIVE_STATE_KEYS:
        clean.pop(key, None)

    return clean

def read_json(path: Path, default: Any) -> Any:
    with lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default



OPENVPN_KNOWN_FAILURE_RULES: list[dict[str, str]] = [
    {
        "pattern": "connection refused",
        "message": "节点端口拒绝连接：对方 OpenVPN 服务未运行、节点已下线，或者端口已经变化。",
    },
    {
        "pattern": "no route to host",
        "message": "路由不可达：当前 VPS 到这个 VPNGate 节点的网络路径不可达，通常是节点掉线或中间路由异常。",
    },
    {
        "pattern": "network is unreachable",
        "message": "网络不可达：当前 VPS 网络无法到达目标节点，可能是路由、IPv4/IPv6 或上游网络问题。",
    },
    {
        "pattern": "server poll timeout",
        "message": "UDP 节点无响应：UDP 数据已发出，但没有收到服务端回应，常见于 UDP 节点掉线、丢包或被运营商过滤。",
    },
    {
        "pattern": "connection timed out",
        "message": "连接超时：节点没有在限定时间内响应，可能是节点慢、掉线或线路丢包。",
    },
    {
        "pattern": "timed out",
        "message": "连接超时：OpenVPN 等待节点响应超时，可能是节点慢、掉线或线路丢包。",
    },
    {
        "pattern": "tls handshake failed",
        "message": "TLS 握手失败：已经连接到节点，但加密握手没有完成，通常是节点异常、证书链异常或服务端响应中断。",
    },
    {
        "pattern": "unable to get local issuer certificate",
        "message": "TLS 证书链验证失败：OpenVPN 无法验证服务端证书链，通常需要更新或使用项目内置 CA bundle。",
    },
    {
        "pattern": "certificate verify failed",
        "message": "TLS 证书验证失败：服务端证书链无法被当前 OpenVPN 信任。",
    },
    {
        "pattern": "auth_failed",
        "message": "OpenVPN 认证失败：用户名或密码不正确，VPNGate 默认一般是 vpn / vpn。",
    },
    {
        "pattern": "authentication failed",
        "message": "OpenVPN 认证失败：用户名或密码不正确，VPNGate 默认一般是 vpn / vpn。",
    },
    {
        "pattern": "connection reset",
        "message": "连接被重置：对方节点或中间网络主动断开连接，通常是节点不稳定或已掉线。",
    },
    {
        "pattern": "cannot open tun/tap",
        "message": "TUN/TAP 设备打开失败：VPS 可能没有开启 TUN 权限，或者 /dev/net/tun 不存在。",
    },
    {
        "pattern": "cannot ioctl tunsetiff",
        "message": "TUN 设备权限不足：当前系统或容器没有创建 TUN 网卡的权限。",
    },
    {
        "pattern": "operation not permitted",
        "message": "权限不足：OpenVPN 无法执行所需网络操作，常见于容器未开启 TUN/TAP 或缺少 CAP_NET_ADMIN。",
    },
    {
        "pattern": "openvpn command not found",
        "message": "OpenVPN 未安装或命令不存在：请检查 openvpn 是否已安装，或者 OPENVPN_CMD 配置是否正确。",
    },
    {
        "pattern": "server not found",
        "message": "服务器未找到：节点域名或地址解析失败，可能是 DNS 问题或节点地址已经失效。",
    },
    {
        "pattern": "name or service not known",
        "message": "DNS 解析失败：系统无法解析节点域名。",
    },
    {
        "pattern": "temporary failure in name resolution",
        "message": "DNS 临时解析失败：当前 VPS 的 DNS 查询失败，稍后可能恢复。",
    },
    {
        "pattern": "verify ok",
        "message": "证书验证已经通过，但 OpenVPN 初始化没有完成：通常是节点后续握手卡住、响应太慢或服务端异常。",
    },
]


OPENVPN_GENERIC_FAILURE_LINES = [
    "exiting due to fatal error",
    "all connections have been connect-retry-max",
    "sigusr1",
    "restart pause",
    "process restarting",
]


def clean_openvpn_log_line(line: str) -> str:
    line = str(line or "").strip()

    # 去掉 OpenVPN 日志前面的时间戳：
    # 2026-06-07 11:14:37 xxx
    line = re.sub(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\s+us=\d+)?\s*", "", line)

    # 压缩空格
    line = re.sub(r"\s+", " ", line).strip()

    return line


def split_openvpn_failure_lines(raw_message: str) -> list[str]:
    raw_message = str(raw_message or "").replace("\n", " | ")
    parts = [clean_openvpn_log_line(x) for x in raw_message.split("|")]
    return [x for x in parts if x]


def extract_openvpn_core_reason(raw_message: str) -> str:
    """
    从 OpenVPN 多行日志里提取最有价值的一句真实原因。
    避免只显示 Exiting due to fatal error 这种无意义结尾。
    """
    lines = split_openvpn_failure_lines(raw_message)
    if not lines:
        return str(raw_message or "").strip() or "OpenVPN failed."

    priority_keywords = [
        "connection refused",
        "no route to host",
        "network is unreachable",
        "server poll timeout",
        "server not found",
        "name or service not known",
        "temporary failure in name resolution",
        "unable to get local issuer certificate",
        "certificate verify failed",
        "tls handshake failed",
        "auth_failed",
        "authentication failed",
        "connection reset",
        "connection timed out",
        "timed out",
        "cannot open tun/tap",
        "cannot ioctl",
        "operation not permitted",
        "error",
        "failed",
        "timeout",
        "cannot",
        "not found",
    ]

    # 优先找真正失败行
    for keyword in priority_keywords:
        for line in lines:
            if keyword in line.lower():
                return line

    # 如果只有 VERIFY OK，但没有 Initialization Sequence Completed，
    # 说明证书没问题，卡在后续初始化阶段
    raw_lower = str(raw_message or "").lower()
    if "verify ok" in raw_lower and "initialization sequence completed" not in raw_lower:
        for line in reversed(lines):
            if "verify ok" in line.lower():
                return line

    # 跳过无意义结尾
    for line in lines:
        lower = line.lower()
        if any(x in lower for x in OPENVPN_GENERIC_FAILURE_LINES):
            continue
        return line

    return lines[-1]


def normalize_openvpn_reason_key(text: str) -> str:
    """
    归一化失败原因，避免 IP、端口、时间不同导致每次都记录成新原因。
    """
    text = clean_openvpn_log_line(text).lower()

    # 替换 IPv4
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", text)

    # 替换 [AF_INET] 这类标记
    text = re.sub(r"\[af_inet6?\]", "[af_inet]", text)

    # 替换 <ip>:端口
    text = re.sub(r"<ip>:\d{1,5}", "<ip>:<port>", text)

    # 替换 sid、序列号等随机值
    text = re.sub(r"sid=[a-f0-9]+\s+[a-f0-9]+", "sid=<sid>", text)

    # 替换长数字，避免证书 serial、端口、时间造成重复
    text = re.sub(r"\b\d{4,}\b", "<num>", text)

    text = re.sub(r"\s+", " ", text).strip()
    return text


def match_builtin_openvpn_failure_reason(core_reason: str, raw_message: str) -> str | None:
    haystack = f"{core_reason} | {raw_message}".lower()

    for rule in OPENVPN_KNOWN_FAILURE_RULES:
        pattern = rule.get("pattern", "").lower()
        if pattern and pattern in haystack:
            return rule.get("message") or None

    return None


def match_or_record_custom_openvpn_failure_reason(core_reason: str) -> str:
    """
    未命中内置规则时：
    - 第一次：直接返回真实原因，并写入 openvpn_failure_reasons.json
    - 下次：如果规则文件里已有同类原因，直接返回记录里的 message
    """
    core_reason = clean_openvpn_log_line(core_reason)
    if not core_reason:
        return "OpenVPN 失败，但没有捕获到有效错误信息。"

    key = normalize_openvpn_reason_key(core_reason)
    now = int(time.time())

    with lock:
        rules = read_json(OPENVPN_FAILURE_REASONS_FILE, [])
        if not isinstance(rules, list):
            rules = []

        for item in rules:
            if not isinstance(item, dict):
                continue

            if item.get("pattern") == key:
                item["count"] = int(item.get("count") or 0) + 1
                item["last_seen"] = now

                examples = item.get("examples")
                if not isinstance(examples, list):
                    examples = []

                if core_reason not in examples:
                    examples.append(core_reason)
                    item["examples"] = examples[-3:]

                write_json(OPENVPN_FAILURE_REASONS_FILE, rules)
                return str(item.get("message") or core_reason)

        # 新原因：自动追加到列表。
        # message 默认用真实原因；以后你可以手动把 message 改成中文解释。
        rules.append(
            {
                "pattern": key,
                "message": core_reason,
                "count": 1,
                "first_seen": now,
                "last_seen": now,
                "examples": [core_reason],
                "note": "自动记录的新 OpenVPN 失败原因。可手动把 message 改成中文提示。",
            }
        )

        write_json(OPENVPN_FAILURE_REASONS_FILE, rules)

    return core_reason


def format_openvpn_failure_message(raw_message: str) -> str:
    """
    将 OpenVPN 原始失败日志转换成更容易理解的中文提示。
    """
    raw_message = str(raw_message or "").strip()
    core_reason = extract_openvpn_core_reason(raw_message)

    builtin_message = match_builtin_openvpn_failure_reason(core_reason, raw_message)
    if builtin_message:
        return f"{builtin_message} 原始原因: {core_reason}"

    # 未命中内置规则：显示真实原因，并自动记录到列表
    return match_or_record_custom_openvpn_failure_reason(core_reason)

def generate_random_password() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(random.choices(chars, k=12))
        # Ensure it contains at least one lowercase, one uppercase, and one digit
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        if has_lower and has_upper and has_digit:
            return pwd

def generate_random_username() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        uname = "".join(random.choices(chars, k=12))
        # Ensure it starts with a letter and contains at least one lowercase, one uppercase, and one digit
        if uname[0].isalpha():
            has_lower = any(c.islower() for c in uname)
            has_upper = any(c.isupper() for c in uname)
            has_digit = any(c.isdigit() for c in uname)
            if has_lower and has_upper and has_digit:
                return uname

def load_ui_config() -> dict[str, Any]:
    with lock:
        auth_file = DATA_DIR / "ui_auth.json"
        config = {
            "username": "",
            "secret_path": "EJsW2EeBo9lY",
            "password": "",
            "host": "0.0.0.0",
            "port": 8787
        }
        updated = False
        if auth_file.exists():
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items():
                    config[key] = val
            except Exception:
                pass
        
        if not config.get("username"):
            config["username"] = generate_random_username()
            updated = True
            
        if not config.get("password"):
            config["password"] = generate_random_password()
            updated = True
            
        if not auth_file.exists() or updated:
            try:
                DATA_DIR.mkdir(exist_ok=True, parents=True)
                auth_file.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
                
        return config

def load_project_update_config() -> dict[str, Any]:
    cfg = read_json(PROJECT_UPDATE_CONFIG_FILE, {})
    return {
        "enabled": cfg.get("enabled", True) is not False,
        "last_check_at": cfg.get("last_check_at", 0),
        "last_message": cfg.get("last_message", "尚未检测项目更新"),
        "last_local_commit": cfg.get("last_local_commit", ""),
        "last_remote_commit": cfg.get("last_remote_commit", ""),
    }


def save_project_update_config(**kwargs: Any) -> dict[str, Any]:
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    cfg = load_project_update_config()
    cfg.update(kwargs)
    write_json(PROJECT_UPDATE_CONFIG_FILE, cfg)
    return cfg


def project_auto_update_enabled() -> bool:
    return load_project_update_config().get("enabled", True) is not False


def run_git_cmd(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def detect_git_upstream_ref() -> str:
    p = run_git_cmd(
        ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
        timeout=10,
    )
    if p.returncode == 0 and p.stdout.strip():
        return p.stdout.strip()

    for ref in ("origin/main", "origin/master"):
        p = run_git_cmd(["git", "rev-parse", "--verify", ref], timeout=10)
        if p.returncode == 0:
            return ref

    raise RuntimeError("未找到 origin/main 或 origin/master，无法检测项目更新")


def start_project_update_unit(upstream_ref: str) -> None:
    log_file = DATA_DIR / "project_update.log"
    lock_file = "/tmp/aimilivpn_project_update.lock"

    shell_script = f"""
set -e
exec 9>{shlex.quote(lock_file)}
flock -n 9 || exit 0

cd {shlex.quote(str(ROOT_DIR))}

echo "[$(date '+%F %T')] 开始自动更新项目，目标版本: {shlex.quote(upstream_ref)}" >> {shlex.quote(str(log_file))}

git fetch --all --prune >> {shlex.quote(str(log_file))} 2>&1
git reset --hard {shlex.quote(upstream_ref)} >> {shlex.quote(str(log_file))} 2>&1
find . -type d -name "__pycache__" -exec rm -rf {{}} + >> {shlex.quote(str(log_file))} 2>&1 || true

bash install.sh >> {shlex.quote(str(log_file))} 2>&1

echo "[$(date '+%F %T')] 项目自动更新完成" >> {shlex.quote(str(log_file))}
"""

    subprocess.Popen(
        [
            "systemd-run",
            "--unit=aimilivpn-project-update",
            "--collect",
            "--property",
            f"WorkingDirectory={str(ROOT_DIR)}",
            "/bin/bash",
            "-lc",
            shell_script,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def check_and_start_project_update() -> dict[str, Any]:
    if not project_update_lock.acquire(blocking=False):
        return {"ok": False, "message": "项目更新检测已在运行，跳过本次检测"}

    try:
        if (ROOT_DIR / ".local_dev").exists():
            cfg = save_project_update_config(
                last_check_at=time.time(),
                last_message="检测到 .local_dev，本地开发模式下跳过项目自动更新",
            )
            return {"ok": True, **cfg}

        if not (ROOT_DIR / ".git").exists():
            cfg = save_project_update_config(
                last_check_at=time.time(),
                last_message="当前目录不是 Git 仓库，无法自动更新项目",
            )
            return {"ok": False, **cfg}

        fetch = run_git_cmd(["git", "fetch", "--all", "--prune"], timeout=60)
        if fetch.returncode != 0:
            msg = fetch.stderr.strip() or fetch.stdout.strip() or "git fetch 失败"
            cfg = save_project_update_config(
                last_check_at=time.time(),
                last_message=f"项目更新检测失败: {msg}",
            )
            return {"ok": False, **cfg}

        upstream_ref = detect_git_upstream_ref()

        local_commit = run_git_cmd(["git", "rev-parse", "HEAD"], timeout=10).stdout.strip()
        remote_commit = run_git_cmd(["git", "rev-parse", upstream_ref], timeout=10).stdout.strip()

        if local_commit == remote_commit:
            cfg = save_project_update_config(
                last_check_at=time.time(),
                last_message="项目已是最新版本",
                last_local_commit=local_commit,
                last_remote_commit=remote_commit,
            )
            return {"ok": True, "updated": False, **cfg}

        save_project_update_config(
            last_check_at=time.time(),
            last_message=f"检测到项目新版本，准备从 {local_commit[:8]} 更新到 {remote_commit[:8]}",
            last_local_commit=local_commit,
            last_remote_commit=remote_commit,
        )

        start_project_update_unit(upstream_ref)

        cfg = save_project_update_config(
            last_check_at=time.time(),
            last_message=f"已启动项目自动更新任务: {local_commit[:8]} -> {remote_commit[:8]}",
            last_local_commit=local_commit,
            last_remote_commit=remote_commit,
        )

        return {"ok": True, "updated": True, **cfg}

    finally:
        project_update_lock.release()

def project_auto_update_loop() -> None:
    while True:
        try:
            if project_auto_update_enabled():
                check_and_start_project_update()
        except Exception as exc:
            save_project_update_config(
                last_check_at=time.time(),
                last_message=f"项目自动更新异常: {exc}",
            )

        time.sleep(PROJECT_AUTO_UPDATE_INTERVAL_SECONDS)

def get_session_token(password: str, username: str = "admin") -> str:
    salt = "aimilivpn_secure_salt_2026"
    return hashlib.sha256((username + ":" + password + salt).encode("utf-8")).hexdigest()


def get_request_ip(handler: BaseHTTPRequestHandler) -> str:
    ip = ""

    if TRUST_PROXY_HEADERS:
        cf_ip = handler.headers.get("CF-Connecting-IP", "").strip()
        if cf_ip:
            return cf_ip

        real_ip = handler.headers.get("X-Real-IP", "").strip()
        if real_ip:
            return real_ip

        forwarded_for = handler.headers.get("X-Forwarded-For", "").strip()
        if forwarded_for:
            return forwarded_for.split(",", 1)[0].strip()

    try:
        ip = str(handler.client_address[0])
    except Exception:
        ip = "unknown"

    return ip or "unknown"


def cleanup_login_failures(now: float | None = None) -> None:
    now = now or time.time()

    expired_keys = []
    for key, info in login_failures.items():
        locked_until = float(info.get("locked_until", 0) or 0)
        first_failed_at = float(info.get("first_failed_at", 0) or 0)

        if locked_until > now:
            continue

        if first_failed_at and now - first_failed_at > LOGIN_FAIL_WINDOW_SECONDS:
            expired_keys.append(key)

    for key in expired_keys:
        login_failures.pop(key, None)


def get_login_lock_status(client_ip: str) -> tuple[bool, int]:
    now = time.time()

    with lock:
        cleanup_login_failures(now)
        info = login_failures.get(client_ip) or {}
        locked_until = float(info.get("locked_until", 0) or 0)

        if locked_until > now:
            return True, int(locked_until - now)

    return False, 0


def register_login_failure(client_ip: str) -> dict[str, Any]:
    now = time.time()

    with lock:
        cleanup_login_failures(now)

        info = login_failures.get(client_ip)
        if not info:
            info = {
                "count": 0,
                "first_failed_at": now,
                "locked_until": 0,
            }

        first_failed_at = float(info.get("first_failed_at", now) or now)

        if now - first_failed_at > LOGIN_FAIL_WINDOW_SECONDS:
            info = {
                "count": 0,
                "first_failed_at": now,
                "locked_until": 0,
            }

        count = int(info.get("count", 0) or 0) + 1
        info["count"] = count

        locked = False
        remaining_seconds = 0

        if count >= LOGIN_FAIL_MAX_ATTEMPTS:
            locked = True
            info["locked_until"] = now + LOGIN_LOCK_SECONDS
            remaining_seconds = LOGIN_LOCK_SECONDS

        login_failures[client_ip] = info

        return {
            "count": count,
            "max_attempts": LOGIN_FAIL_MAX_ATTEMPTS,
            "locked": locked,
            "remaining_seconds": remaining_seconds,
        }


def clear_login_failure(client_ip: str) -> None:
    with lock:
        login_failures.pop(client_ip, None)


def format_seconds_zh(seconds: int) -> str:
    seconds = max(0, int(seconds))
    minutes = seconds // 60
    remain = seconds % 60

    if minutes > 0:
        return f"{minutes}分{remain}秒"

    return f"{remain}秒"

def cleanup_old_logs(logs_dir: Path) -> None:
    try:
        now = time.time()
        three_days_sec = 3 * 24 * 60 * 60
        for path in logs_dir.glob("*.json"):
            match = re.match(r"^(\d{4}-\d{2}-\d{2})\.json$", path.name)
            if match:
                date_str = match.group(1)
                try:
                    file_time = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
                    today_str = time.strftime("%Y-%m-%d", time.localtime())
                    today_time = time.mktime(time.strptime(today_str, "%Y-%m-%d"))
                    if today_time - file_time >= three_days_sec:
                        path.unlink()
                        print(f"[清理] 已删除3天前的旧日志文件: {path.name}", flush=True)
                except Exception:
                    if now - path.stat().st_mtime > three_days_sec:
                        path.unlink()
    except Exception as e:
        print(f"[清理错误] 清理旧日志失败: {e}", flush=True)

def log_to_json(level: str, module: str, message: str) -> None:
    try:
        logs_dir = DATA_DIR / "logs"
        logs_dir.mkdir(exist_ok=True, parents=True)
        date_str = time.strftime("%Y-%m-%d", time.localtime())
        log_file = logs_dir / f"{date_str}.json"
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "level": level,
            "module": module,
            "message": message
        }
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        cleanup_old_logs(logs_dir)
    except Exception as e:
        print(f"[Log Error] Failed to write JSON log: {e}", flush=True)

def set_state(**updates: Any) -> None:
    state = get_state()
    state.update(updates)
    write_json(STATE_FILE, sanitize_state_for_disk(state))

def save_last_connected_node(node_id: str, node: dict[str, Any] | None = None) -> None:
    if not node_id:
        return

    data = {
        "id": node_id,
        "saved_at": time.time(),
    }

    if node:
        data.update({
            "country": node.get("country", ""),
            "country_short": node.get("country_short", ""),
            "ip": node.get("ip") or node.get("remote_host") or "",
            "remote_port": node.get("remote_port", ""),
            "proto": node.get("proto", ""),
        })

    write_json(LAST_CONNECTED_NODE_FILE, data)


def load_last_connected_node_id() -> str:
    data = read_json(LAST_CONNECTED_NODE_FILE, {})
    return str(data.get("id") or "")


def clear_last_connected_node() -> None:
    try:
        if LAST_CONNECTED_NODE_FILE.exists():
            LAST_CONNECTED_NODE_FILE.unlink()
    except Exception:
        pass
def format_switch_duration(seconds: Any) -> str:
    """
    节点切换耗时展示格式：xx时xx分xx秒
    """
    try:
        total = max(0, int(float(seconds or 0)))
    except (TypeError, ValueError):
        total = 0

    hours = total // 3600
    minutes = (total % 3600) // 60
    secs = total % 60

    return f"{hours:02d}时{minutes:02d}分{secs:02d}秒"


def mark_node_switch_start(reason: str = "") -> None:
    """
    记录本轮节点切换开始时间。

    注意：
    如果已经存在开始时间，不重复覆盖。
    这样连续切换多个失败节点时，统计的是：
    第一次发现故障 -> 最终新节点测速达标 的总耗时。
    """
    state = read_json(STATE_FILE, {})

    if state.get("node_switch_started_at"):
        return

    set_state(
        node_switch_started_at=time.time(),
        node_switch_reason=reason,
    )


def finish_node_switch_duration(reason: str = "") -> None:
    """
    新节点连接成功，并且质量 / 测速达标后，结算本轮切换耗时。
    结果写入 state.json，所以服务重启后仍然显示上次耗时。
    """
    state = read_json(STATE_FILE, {})

    try:
        started_at = float(state.get("node_switch_started_at") or 0)
    except (TypeError, ValueError):
        started_at = 0

    if started_at <= 0:
        return

    finished_at = time.time()
    duration_seconds = max(0, int(finished_at - started_at))
    duration_text = format_switch_duration(duration_seconds)
    duration_reason = reason or state.get("node_switch_reason", "")

    history = state.get("node_switch_duration_history", [])
    if not isinstance(history, list):
        history = []

    history.append({
        "finished_at": finished_at,
        "duration_seconds": duration_seconds,
        "duration_text": duration_text,
        "reason": duration_reason,
    })

    history = prune_switch_duration_history(history, 10)

    set_state(
        node_switch_started_at=None,
        last_node_switch_finished_at=finished_at,
        last_node_switch_duration_seconds=duration_seconds,
        last_node_switch_duration_text=duration_text,
        last_node_switch_reason=duration_reason,
        node_switch_duration_history=history,
    )


def prune_switch_duration_history(history: Any, max_items: int = 10) -> list[dict[str, Any]]:
    """
    只保留最近 max_items 次切换耗时记录。
    """
    if not isinstance(history, list):
        history = []

    cleaned: list[dict[str, Any]] = []

    for item in history:
        if not isinstance(item, dict):
            continue

        try:
            duration_seconds = max(0, int(item.get("duration_seconds", 0) or 0))
        except (TypeError, ValueError):
            duration_seconds = 0

        try:
            finished_at = float(item.get("finished_at", 0) or 0)
        except (TypeError, ValueError):
            finished_at = 0

        cleaned.append({
            "finished_at": finished_at,
            "duration_seconds": duration_seconds,
            "duration_text": item.get("duration_text") or format_switch_duration(duration_seconds),
            "reason": item.get("reason") or "",
        })

    return cleaned[-max_items:]


def build_switch_duration_chart(history: Any, max_items: int = 10) -> list[dict[str, Any]]:
    """
    构建最近 10 次节点切换耗时图表数据。

    - 柱子底部 label：节点切换完成时的系统时间
    - 柱子顶部 text：节点切换耗时
    - 柱高由前端根据真实 seconds 绘制
    """
    items = prune_switch_duration_history(history, max_items)
    items = sorted(
        items,
        key=lambda x: float(x.get("finished_at", 0) or 0)
    )
    chart: list[dict[str, Any]] = []

    for index, item in enumerate(items, start=1):
        duration_seconds = max(0, int(item.get("duration_seconds", 0) or 0))

        try:
            finished_at = float(item.get("finished_at", 0) or 0)
        except (TypeError, ValueError):
            finished_at = 0

        if finished_at > 0:
            finished_label = time.strftime(
                "%m-%d %H:%M:%S",
                time.localtime(finished_at),
            )
        else:
            finished_label = "-"

        chart.append({
            "index": index,
            "label": finished_label,
            "finished_at": finished_at,
            "seconds": duration_seconds,
            "text": item.get("duration_text") or format_switch_duration(duration_seconds),
            "reason": item.get("reason") or "",
        })

    return chart

def normalize_uptime_ip(ip: Any) -> str:
    ip = str(ip or "").strip()
    if not ip or ip in {"-", "0.0.0.0", "unknown", "None"}:
        return ""
    return ip


def format_ip_uptime_duration(seconds: Any) -> str:
    """
    IP 连接时长展示：xx天 xx时 xx分
    """
    try:
        total = max(0, int(float(seconds or 0)))
    except (TypeError, ValueError):
        total = 0

    days = total // 86400
    hours = (total % 86400) // 3600
    minutes = (total % 3600) // 60

    return f"{days}天 {hours}时 {minutes}分"
def round_ip_uptime_hours(seconds: Any) -> float:
    """
    IP 连接时长换算为“小时”，按以下规则取值：
    - 不足 0.5 小时，按 0.5 小时
    - 超过 0.5 小时但不足 1 小时，按 1 小时
    - 大于 1 小时时：
      整数小时部分保留；
      小数部分 <= 0.5，补 0.5 小时；
      小数部分 > 0.5，补 1 小时

    例子：
    10 分钟   -> 0.5
    25 分钟   -> 0.5
    40 分钟   -> 1
    1小时10分 -> 1.5
    1小时40分 -> 2
    3小时05分 -> 3.5
    3小时35分 -> 4
    """
    try:
        total = max(0, int(float(seconds or 0)))
    except (TypeError, ValueError):
        total = 0

    if total <= 0:
        return 0.5

    hours = total / 3600.0
    whole = int(hours)
    frac = hours - whole

    if whole == 0:
        return 0.5 if frac <= 0.5 else 1.0

    if frac == 0:
        return float(whole)

    return float(whole + 0.5) if frac <= 0.5 else float(whole + 1)

def prune_ip_uptime_history(history: Any, max_items: int = 10) -> list[dict[str, Any]]:
    """
    清理 IP 持续时长历史。

    修复点：
    - 按 ended_at 从旧到新排序；
    - 如果连续两条记录 IP 相同，则合并成一条；
    - 避免图表里出现连续两个相同 IP；
    - 最终只保留最近 max_items 条。
    """
    if not isinstance(history, list):
        history = []

    cleaned: list[dict[str, Any]] = []

    for item in history:
        if not isinstance(item, dict):
            continue

        ip = normalize_uptime_ip(item.get("ip"))
        if not ip:
            continue

        try:
            started_at = float(item.get("started_at", 0) or 0)
        except (TypeError, ValueError):
            started_at = 0

        try:
            ended_at = float(item.get("ended_at", 0) or 0)
        except (TypeError, ValueError):
            ended_at = 0

        try:
            duration_seconds = max(0, int(item.get("duration_seconds", 0) or 0))
        except (TypeError, ValueError):
            duration_seconds = 0

        if duration_seconds <= 0 and started_at > 0 and ended_at > 0:
            duration_seconds = max(0, int(ended_at - started_at))

        cleaned.append({
            "ip": ip,
            "node_id": str(item.get("node_id") or ""),
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_seconds": duration_seconds,
            "duration_text": item.get("duration_text") or format_ip_uptime_duration(duration_seconds),
            "end_reason": item.get("end_reason") or "",
            "active": False,
        })

    cleaned = sorted(
        cleaned,
        key=lambda x: float(x.get("ended_at", 0) or 0)
    )

    merged: list[dict[str, Any]] = []

    for item in cleaned:
        if merged and merged[-1].get("ip") == item.get("ip"):
            prev = merged[-1]

            prev_started = float(prev.get("started_at", 0) or 0)
            prev_ended = float(prev.get("ended_at", 0) or 0)

            item_started = float(item.get("started_at", 0) or 0)
            item_ended = float(item.get("ended_at", 0) or 0)

            # 只有短时间内连续出现的相同 IP 才合并。
            # 例如：连通性检测失败后，又连回同一个 IP。
            # 如果隔了很久，比如几小时 / 几天后又出现同一个 IP，则算新的历史记录。
            same_ip_gap_seconds = (
                item_started - prev_ended
                if prev_ended > 0 and item_started > 0
                else 0
            )

            if same_ip_gap_seconds > 30 * 60:
                merged.append(item)
                continue

            valid_starts = [v for v in [prev_started, item_started] if v > 0]
            valid_ends = [v for v in [prev_ended, item_ended] if v > 0]

            new_started_at = min(valid_starts) if valid_starts else 0
            new_ended_at = max(valid_ends) if valid_ends else 0

            if new_started_at > 0 and new_ended_at > 0:
                new_duration_seconds = max(0, int(new_ended_at - new_started_at))
            else:
                new_duration_seconds = (
                        int(prev.get("duration_seconds", 0) or 0)
                        + int(item.get("duration_seconds", 0) or 0)
                )

            prev.update({
                "node_id": item.get("node_id") or prev.get("node_id", ""),
                "started_at": new_started_at,
                "ended_at": new_ended_at,
                "duration_seconds": new_duration_seconds,
                "duration_text": format_ip_uptime_duration(new_duration_seconds),
                "end_reason": item.get("end_reason") or prev.get("end_reason", ""),
                "active": False,
            })

            continue

        merged.append(item)

    return merged[-max_items:]


def finish_current_ip_uptime(reason: str = "", ended_at: float | None = None) -> None:
    """
    结束当前 IP 的连接时长统计。

    触发场景：
    - 节点确认不通
    - 自动切换
    - 手动切换
    - 手动断开
    - OpenVPN 进程异常退出
    - 出口 IP 发生变化
    """
    state = read_json(STATE_FILE, {})

    ip = normalize_uptime_ip(state.get("current_ip_uptime_ip"))
    if not ip:
        return

    try:
        started_at = float(state.get("current_ip_uptime_started_at") or 0)
    except (TypeError, ValueError):
        started_at = 0

    if started_at <= 0:
        return

    if ended_at is None:
        ended_at = time.time()

    duration_seconds = max(0, int(float(ended_at) - started_at))

    history = state.get("ip_uptime_history", [])
    if not isinstance(history, list):
        history = []

    history.append({
        "ip": ip,
        "node_id": str(state.get("current_ip_uptime_node_id") or ""),
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_seconds": duration_seconds,
        "duration_text": format_ip_uptime_duration(duration_seconds),
        "end_reason": reason,
        "active": False,
    })

    history = prune_ip_uptime_history(history, 10)

    set_state(
        current_ip_uptime_ip="",
        current_ip_uptime_node_id="",
        current_ip_uptime_started_at=None,
        current_ip_uptime_last_seen_at=None,
        current_ip_uptime_reason="",
        current_ip_uptime_pending_ended_at=None,
        current_ip_uptime_pending_end_reason="",
        ip_uptime_history=history,
    )

def mark_current_ip_uptime_pending_end(reason: str = "") -> None:
    """
    标记当前 IP 疑似结束，但暂不写入历史。

    用途：
    - 节点确认不通后，先不要立刻把当前 IP 写入历史；
    - 等新节点连接成功后，如果出口 IP 还是同一个，则继续累计；
    - 如果出口 IP 变了，再把旧 IP 写入历史。
    """
    state = read_json(STATE_FILE, {})

    ip = normalize_uptime_ip(state.get("current_ip_uptime_ip"))
    if not ip:
        return

    try:
        started_at = float(state.get("current_ip_uptime_started_at") or 0)
    except (TypeError, ValueError):
        started_at = 0

    if started_at <= 0:
        return

    set_state(
        current_ip_uptime_pending_ended_at=time.time(),
        current_ip_uptime_pending_end_reason=reason,
    )

def begin_or_continue_ip_uptime(ip: Any, node_id: str = "", reason: str = "") -> None:
    """
    开始或续算当前出口 IP 的连接时间。

    关键点：
    - 如果 IP 没变，不重置 started_at；
    - 如果之前只是连通性检测失败，但又连回同一个 IP，则继续累计；
    - 如果 IP 变了，旧 IP 才真正结算进历史，新 IP 从当前时间重新计时。
    """
    ip = normalize_uptime_ip(ip)
    if not ip:
        return

    state = read_json(STATE_FILE, {})

    old_ip = normalize_uptime_ip(state.get("current_ip_uptime_ip"))

    try:
        old_started_at = float(state.get("current_ip_uptime_started_at") or 0)
    except (TypeError, ValueError):
        old_started_at = 0

    try:
        pending_ended_at = float(state.get("current_ip_uptime_pending_ended_at") or 0)
    except (TypeError, ValueError):
        pending_ended_at = 0

    pending_reason = str(state.get("current_ip_uptime_pending_end_reason") or "")

    now = time.time()

    # IP 没变：说明之前只是连通性检测失败，后面又连回了同一个出口 IP
    # 不写入历史，继续沿用原来的 started_at
    if old_ip == ip and old_started_at > 0:
        set_state(
            current_ip_uptime_node_id=node_id or state.get("current_ip_uptime_node_id", ""),
            current_ip_uptime_last_seen_at=now,
            current_ip_uptime_reason=reason or state.get("current_ip_uptime_reason", ""),
            current_ip_uptime_pending_ended_at=None,
            current_ip_uptime_pending_end_reason="",
        )
        return

    # IP 变了：旧 IP 才真正结算进历史
    if old_ip and old_ip != ip and old_started_at > 0:
        finish_current_ip_uptime(
            pending_reason or f"出口 IP 变化: {old_ip} -> {ip}",
            ended_at=pending_ended_at if pending_ended_at > 0 else now,
            )

    # 关键：开始统计新 IP
    # 包括两种情况：
    # 1. 之前没有 old_ip；
    # 2. old_ip 已经结算，当前 ip 是新的出口 IP。
    set_state(
        current_ip_uptime_ip=ip,
        current_ip_uptime_node_id=node_id,
        current_ip_uptime_started_at=now,
        current_ip_uptime_last_seen_at=now,
        current_ip_uptime_reason=reason,
        current_ip_uptime_pending_ended_at=None,
        current_ip_uptime_pending_end_reason="",
    )


def touch_ip_uptime_seen_ip(ip: Any, node_id: str = "", reason: str = "") -> None:
    """
    后台健康检测看到当前出口 IP 时调用。

    用途：
    - IP 一样：刷新 last_seen；
    - IP 不一样：说明同一连接期间出口 IP 变了，结算旧 IP，并记录新 IP。
    """
    ip = normalize_uptime_ip(ip)
    if not ip:
        return

    state = read_json(STATE_FILE, {})
    current_ip = normalize_uptime_ip(state.get("current_ip_uptime_ip"))

    if not current_ip:
        return

    begin_or_continue_ip_uptime(
        ip,
        node_id=node_id,
        reason=reason or "后台健康检测确认出口 IP",
    )


def build_ip_uptime_chart(history: Any, state: dict[str, Any], max_items: int = 10) -> list[dict[str, Any]]:
    """
    构建最近 10 个已结束 IP 的连接时长图表。
    图表单位改为：小时
    """
    items = prune_ip_uptime_history(history, max_items)
    items = sorted(
        items,
        key=lambda x: float(x.get("ended_at", 0) or 0)
    )

    # 当前正在连接的 IP 不应该作为“最近一条历史记录”显示。
    # 只判断最后一条，不全量删除，避免误删几天前出现过的同 IP 历史。
    current_ip = normalize_uptime_ip(
        state.get("current_ip_uptime_ip")
        or state.get("proxy_ip")
        or ""
    )

    if current_ip and items:
        latest_ip = normalize_uptime_ip(items[-1].get("ip"))
        if latest_ip == current_ip:
            items = items[:-1]

    # 隐藏尾部当前 IP 后，再保留最近 max_items 条
    items = items[-max_items:]

    chart: list[dict[str, Any]] = []

    for index, item in enumerate(items, start=1):
        duration_seconds = max(0, int(item.get("duration_seconds", 0) or 0))
        hours = round_ip_uptime_hours(duration_seconds)

        ip = normalize_uptime_ip(item.get("ip"))

        chart.append({
            "index": index,
            "ip": ip,
            "label": ip,
            "hours": hours,
            "seconds": duration_seconds,
            "text": item.get("duration_text") or format_ip_uptime_duration(duration_seconds),
            "reason": item.get("end_reason") or "",
        })

    return chart

def build_auto_switch_daily_chart(
        counts: dict[str, Any] | None = None,
        days: int = 15,
) -> list[dict[str, Any]]:
    """
    生成最近 15 个完整自然日的自动切换统计。
    注意：截止到昨日，不包含今天。
    """
    counts = counts or {}
    today = date.today()
    chart: list[dict[str, Any]] = []

    for offset in range(days, 0, -1):
        day = today - timedelta(days=offset)
        key = day.isoformat()

        try:
            count = max(0, int(counts.get(key, 0) or 0))
        except (TypeError, ValueError):
            count = 0

        chart.append({
            "date": key,
            "label": f"{day.month}/{day.day}",
            "count": count,
        })

    return chart


def prune_auto_switch_daily_counts(counts: dict[str, Any]) -> dict[str, int]:
    """
    只保留今天 + 最近 15 个完整自然日。
    前端只展示截止昨日的 15 日；今天的数据先保留，明天再进入图表。
    """
    today = date.today()
    keep = {
        (today - timedelta(days=offset)).isoformat()
        for offset in range(0, 16)
    }

    pruned: dict[str, int] = {}

    for key in sorted(keep):
        try:
            value = max(0, int(counts.get(key, 0) or 0))
        except (TypeError, ValueError):
            value = 0

        if value > 0:
            pruned[key] = value

    return pruned


def record_auto_node_switch(node_id: str = "", reason: str = "") -> None:
    """
    记录自动更换节点次数。
    手动 /api/connect 不调用此函数，所以不会被统计。
    """
    state = read_json(STATE_FILE, {})

    counts = state.get("auto_switch_daily_counts", {})
    if not isinstance(counts, dict):
        counts = {}

    today_key = date.today().isoformat()

    try:
        current = max(0, int(counts.get(today_key, 0) or 0))
    except (TypeError, ValueError):
        current = 0

    counts[today_key] = current + 1
    counts = prune_auto_switch_daily_counts(counts)

    set_state(
        auto_switch_daily_counts=counts,
        last_auto_switch_recorded_at=time.time(),
        last_auto_switch_node_id=node_id,
        last_auto_switch_reason=reason,
    )
def init_state_on_start() -> None:
    """
    服务启动时初始化 state.json。

    只重置运行态字段，不覆盖历史统计数据：
    - auto_switch_daily_counts
    - node_switch_duration_history
    - ip_uptime_history
    - current_ip_uptime_xxx
    """
    old_state = read_json(STATE_FILE, {})
    if not isinstance(old_state, dict):
        old_state = {}

    # 防止历史版本遗留敏感字段
    for key in SENSITIVE_STATE_KEYS:
        old_state.pop(key, None)

    # 这些是启动时需要刷新的运行态字段
    runtime_updates = {
        "api_url": API_URL,
        "target_valid_nodes": TARGET_VALID_NODES,
        "fetch_interval_seconds": FETCH_INTERVAL_SECONDS,
        "check_interval_seconds": CHECK_INTERVAL_SECONDS,
        "local_proxy": f"http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",

        "active_openvpn_node_id": "",
        "last_fetch_status": "starting",
        "last_check_message": "服务已启动，正在初始化网络并获取候选 VPN 节点...",
        "is_connecting": True,
        "active_node_latency": "正在准备",
        "connected_at": None,

        # 启动后不要继承“正在切换中”的状态，避免重启后算出异常超长切换耗时
        "node_switch_started_at": None,
        "node_switch_reason": "",
        "is_maintaining": False,
        "maintenance_message": "",
    }

    old_state.update(runtime_updates)

    # 这些统计字段只补默认值，不覆盖已有数据
    old_state.setdefault("auto_switch_daily_counts", {})
    old_state.setdefault("last_auto_switch_recorded_at", None)
    old_state.setdefault("last_auto_switch_node_id", "")
    old_state.setdefault("last_auto_switch_reason", "")

    old_state.setdefault("node_switch_duration_history", [])
    old_state.setdefault("last_node_switch_duration_seconds", 0)
    old_state.setdefault("last_node_switch_duration_text", "-")
    old_state.setdefault("last_node_switch_finished_at", None)
    old_state.setdefault("last_node_switch_reason", "")

    old_state.setdefault("ip_uptime_history", [])
    old_state.setdefault("current_ip_uptime_ip", "")
    old_state.setdefault("current_ip_uptime_node_id", "")
    old_state.setdefault("current_ip_uptime_started_at", None)
    old_state.setdefault("current_ip_uptime_last_seen_at", None)
    old_state.setdefault("current_ip_uptime_reason", "")

    # 顺手裁剪，避免文件无限变大
    old_state["node_switch_duration_history"] = prune_switch_duration_history(
        old_state.get("node_switch_duration_history", []),
        10,
    )

    old_state["ip_uptime_history"] = prune_ip_uptime_history(
        old_state.get("ip_uptime_history", []),
        10,
    )

    counts = old_state.get("auto_switch_daily_counts", {})
    if not isinstance(counts, dict):
        counts = {}

    old_state["auto_switch_daily_counts"] = prune_auto_switch_daily_counts(counts)

    write_json(STATE_FILE, sanitize_state_for_disk(old_state))

def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, is_connecting
    state = read_json(STATE_FILE, {})

    # 防止历史版本已经写入 state.json 的代理账号密码被继续带出来
    for key in SENSITIVE_STATE_KEYS:
        state.pop(key, None)
    state["active_openvpn_node_id"] = resolve_active_openvpn_node_id()
    state["is_connecting"] = is_connecting
    state.setdefault("api_url", API_URL)
    state.setdefault("target_valid_nodes", TARGET_VALID_NODES)
    state.setdefault("fetch_interval_seconds", FETCH_INTERVAL_SECONDS)
    state.setdefault("check_interval_seconds", CHECK_INTERVAL_SECONDS)
    state.setdefault("local_proxy", f"http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}")
    state.setdefault("last_fetch_status", "not_started")
    state.setdefault("is_maintaining", False)
    state.setdefault("maintenance_message", "")
    state.setdefault("last_check_message", "")
    state.setdefault("blacklisted_nodes", 0)
    state.setdefault("node_switch_started_at", None)
    state.setdefault("last_node_switch_duration_seconds", 0)
    state.setdefault("last_node_switch_duration_text", "-")
    state.setdefault("last_node_switch_finished_at", None)
    state.setdefault("last_node_switch_reason", "")
    state.setdefault("node_switch_duration_history", [])

    state["node_switch_duration_history"] = prune_switch_duration_history(
        state.get("node_switch_duration_history", []),
        10,
    )

    state["switch_duration_chart"] = build_switch_duration_chart(
        state["node_switch_duration_history"],
        10,
    )
    state.setdefault("ip_uptime_history", [])
    state.setdefault("current_ip_uptime_ip", "")
    state.setdefault("current_ip_uptime_node_id", "")
    state.setdefault("current_ip_uptime_started_at", None)
    state.setdefault("current_ip_uptime_last_seen_at", None)
    state.setdefault("current_ip_uptime_reason", "")

    state["ip_uptime_history"] = prune_ip_uptime_history(
        state.get("ip_uptime_history", []),
        10,
    )

    state["ip_uptime_chart"] = build_ip_uptime_chart(
        state["ip_uptime_history"],
        state,
        10,
    )

    state.setdefault("auto_switch_daily_counts", {})
    state.setdefault("last_auto_switch_recorded_at", None)
    state.setdefault("last_auto_switch_node_id", "")
    state.setdefault("last_auto_switch_reason", "")

    counts = state.get("auto_switch_daily_counts", {})
    if not isinstance(counts, dict):
        counts = {}

    state["auto_switch_daily_counts"] = prune_auto_switch_daily_counts(counts)
    state["auto_switch_chart"] = build_auto_switch_daily_chart(
        state["auto_switch_daily_counts"]
    )

    state["quality_check_enabled"] = QUALITY_CHECK_ENABLED
    state["quality_max_fraud_score"] = QUALITY_MAX_FRAUD_SCORE
    state["quality_require_residential"] = QUALITY_REQUIRE_RESIDENTIAL
    state["quality_require_native"] = QUALITY_REQUIRE_NATIVE
    state["quality_min_human_ratio"] = QUALITY_MIN_HUMAN_RATIO
    state["auto_switch_same_country_only"] = AUTO_SWITCH_SAME_COUNTRY_ONLY
    
    # Pre-populate settings inputs in UI
    ui_cfg = load_ui_config()
    state["username"] = ui_cfg.get("username", "admin")
    state["port"] = ui_cfg.get("port", 8787)
    state["secret_path"] = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
    proxy_auth_cfg = load_proxy_auth_config()
    state["proxy_auth_enabled"] = bool(proxy_auth_cfg.get("enabled"))
    state["proxy_username"] = proxy_auth_cfg.get("username", "")
    state["proxy_password"] = proxy_auth_cfg.get("password", "")
    
    return state

def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("._") or "node"

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
def parse_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0

def check_ui_port_available(host: str, port: int) -> tuple[bool, str]:
    bind_host = str(host or "0.0.0.0").strip() or "0.0.0.0"

    # 当前管理后台使用 ThreadingHTTPServer，默认 IPv4 监听
    family = socket.AF_INET

    if bind_host == "::":
        bind_host = "0.0.0.0"

    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_host, port))
        sock.close()
        return True, ""
    except OSError as exc:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

        if exc.errno == 98:
            return False, f"端口 {port} 已被占用，请换一个端口，或先停止占用该端口的服务"
        if exc.errno == 13:
            return False, f"端口 {port} 权限不足，请换用 1024 以上端口，或确认服务以 root 权限运行"

        return False, f"端口 {port} 不可用：{exc}"

def get_internal_curl_proxy_args(scheme: str = "socks5h", host: str = "127.0.0.1") -> list[str]:
    args = [
        "-x",
        f"{scheme}://{host}:{LOCAL_PROXY_PORT}",
    ]

    if PROXY_AUTH_ENABLED and PROXY_USERNAME and PROXY_PASSWORD:
        args.extend([
            "--proxy-user",
            f"{PROXY_USERNAME}:{PROXY_PASSWORD}",
        ])

    return args
def normalize_env_bool(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def load_proxy_auth_config() -> dict[str, Any]:
    cfg = {
        "enabled": PROXY_AUTH_ENABLED,
        "username": PROXY_USERNAME,
        "password": PROXY_PASSWORD,
    }

    try:
        if PROXY_AUTH_ENV_FILE.exists():
            for line in PROXY_AUTH_ENV_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                value = value.strip().strip('"').strip("'")

                if key == "PROXY_AUTH_ENABLED":
                    cfg["enabled"] = normalize_env_bool(value)
                elif key == "PROXY_USERNAME":
                    cfg["username"] = value
                elif key == "PROXY_PASSWORD":
                    cfg["password"] = value
    except Exception as exc:
        print(f"[代理认证] 读取代理认证配置失败: {exc}", flush=True)

    return cfg


def validate_proxy_credential(name: str, value: str, min_len: int, max_len: int) -> str:
    value = str(value or "").strip()

    if not (min_len <= len(value) <= max_len):
        raise ValueError(f"{name}长度必须在 {min_len} 到 {max_len} 位之间")

    if not re.match(r"^[A-Za-z0-9_.@-]+$", value):
        raise ValueError(f"{name}只能包含英文字母、数字、下划线、点、@ 和短横线")

    return value


def write_proxy_auth_env(enabled: bool, username: str, password: str) -> None:
    PROXY_AUTH_ENV_FILE.parent.mkdir(parents=True, exist_ok=True)

    old_lines: list[str] = []
    if PROXY_AUTH_ENV_FILE.exists():
        old_lines = PROXY_AUTH_ENV_FILE.read_text(encoding="utf-8", errors="replace").splitlines()

    skip_keys = {
        "PROXY_AUTH_ENABLED",
        "PROXY_USERNAME",
        "PROXY_PASSWORD",
    }

    new_lines: list[str] = []
    for line in old_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            new_lines.append(line)
            continue

        key = stripped.split("=", 1)[0]
        if key in skip_keys:
            continue

        new_lines.append(line)

    new_lines.extend([
        f"PROXY_AUTH_ENABLED={'1' if enabled else '0'}",
        f"PROXY_USERNAME={username}",
        f"PROXY_PASSWORD={password}",
    ])

    tmp_path = PROXY_AUTH_ENV_FILE.with_suffix(".tmp")
    tmp_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    tmp_path.replace(PROXY_AUTH_ENV_FILE)

    try:
        PROXY_AUTH_ENV_FILE.chmod(0o600)
    except OSError:
        pass


def apply_proxy_auth_runtime(enabled: bool, username: str, password: str) -> None:
    global PROXY_AUTH_ENABLED, PROXY_USERNAME, PROXY_PASSWORD

    PROXY_AUTH_ENABLED = enabled
    PROXY_USERNAME = username
    PROXY_PASSWORD = password

    os.environ["PROXY_AUTH_ENABLED"] = "1" if enabled else "0"
    os.environ["PROXY_USERNAME"] = username
    os.environ["PROXY_PASSWORD"] = password

    # 关键：同步修改 proxy_server 模块里的全局变量，保证无需重启实时生效
    proxy_server.PROXY_AUTH_ENABLED = enabled
    proxy_server.PROXY_USERNAME = username
    proxy_server.PROXY_PASSWORD = password

def get_proxy_authorization_header() -> str:
    if not (PROXY_AUTH_ENABLED and PROXY_USERNAME and PROXY_PASSWORD):
        return ""

    raw = f"{PROXY_USERNAME}:{PROXY_PASSWORD}".encode("utf-8")
    token = base64.b64encode(raw).decode("ascii")
    return f"Proxy-Authorization: Basic {token}\r\n"

def parse_float(value: Any) -> float:
    try:
        if value is None:
            return 0.0
        if isinstance(value, str):
            value = value.strip().replace("%", "")
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def normalize_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"1", "true", "yes", "y", "on", "是", "原生", "原生ip", "residential", "住宅", "家庭宽带"}:
            return True
        if v in {"0", "false", "no", "n", "off", "否", "非原生", "广播", "广播ip", "hosting", "datacenter", "data center", "机房", "idc"}:
            return False
    return None


def deep_find_value(data: Any, candidates: set[str]) -> Any:
    """在第三方 API 返回里递归查找字段，兼容 camelCase/snake_case/大小写。"""
    normalized = {re.sub(r"[^a-z0-9]+", "", key.lower()) for key in candidates}
    if isinstance(data, dict):
        for key, value in data.items():
            nk = re.sub(r"[^a-z0-9]+", "", str(key).lower())
            if nk in normalized:
                return value
        for value in data.values():
            found = deep_find_value(value, candidates)
            if found is not None:
                return found
    elif isinstance(data, list):
        for item in data:
            found = deep_find_value(item, candidates)
            if found is not None:
                return found
    return None


def text_contains_any(value: Any, keywords: list[str]) -> bool:
    s = str(value or "").lower()
    return any(keyword.lower() in s for keyword in keywords)


def fetch_api_text() -> str:
    request = urllib.request.Request(
        API_URL,
        headers={
            "User-Agent": "Mozilla/5.0 vpngate-openvpn-manager/2.0",
            "Accept": "text/plain,*/*",
        },
    )
    with urllib.request.urlopen(request, timeout=12) as response:
        return response.read().decode("utf-8", errors="replace")

def parse_vpngate_rows(text: str) -> list[dict[str, str]]:
    lines = [line for line in text.splitlines() if line and not line.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    return list(csv.DictReader(lines))

def decode_config(encoded: str) -> str:
    return base64.b64decode(encoded.encode("ascii"), validate=False).decode("utf-8", errors="replace")
def get_country_code(item: dict[str, Any]) -> str:
    return str(
        item.get("CountryShort")
        or item.get("country_short")
        or ""
    ).upper()


def select_candidate_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    selected: list[dict[str, str]] = []
    seen_ips: set[str] = set()
    country_counts = {code: 0 for code in PREFERRED_COUNTRIES}

    def add_row(row: dict[str, str]) -> bool:
        ip = row.get("IP", "")
        encoded = row.get("OpenVPN_ConfigData_Base64", "")

        if not ip or not encoded:
            return False

        if ip in seen_ips:
            return False

        selected.append(row)
        seen_ips.add(ip)

        code = get_country_code(row)
        if code in country_counts:
            country_counts[code] += 1

        return True

    # 保留原来的逻辑：先取前 MAX_SCAN_ROWS 行
    for row in rows[:MAX_SCAN_ROWS]:
        add_row(row)

    # 额外补充指定国家
    for row in rows[:PREFERRED_COUNTRY_SCAN_ROWS]:
        code = get_country_code(row)

        if code not in country_counts:
            continue

        if country_counts[code] >= PREFERRED_COUNTRY_MIN_NODES:
            continue

        add_row(row)

        if all(count >= PREFERRED_COUNTRY_MIN_NODES for count in country_counts.values()):
            break

    return selected

def load_blacklist() -> dict[str, dict[str, Any]]:
    return {}

def mark_blacklisted(node: dict[str, Any], message: str) -> None:
    pass

def row_to_node(row: dict[str, str], config_text: str) -> dict[str, Any]:
    ip = row.get("IP", "")
    country_short = row.get("CountryShort", "")
    remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, ip)
    node_id = safe_name("_".join([country_short or "XX", ip or remote_host, str(remote_port), proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    
    country_long = row.get("CountryLong", "")
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    return {
        "id": node_id,
        "country": country_zh,
        "country_short": country_short,
        "host_name": row.get("HostName", ""),
        "ip": ip,
        "score": parse_int(row.get("Score")),
        "ping": parse_int(row.get("Ping")),
        "speed": parse_int(row.get("Speed")),
        "sessions": parse_int(row.get("NumVpnSessions")),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": config_text,
        "proto": proto,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "",
        "probed_at": 0,
        "quality_status": "unknown",
        "quality_checked_at": 0,
        "quality_fail_reason": "",
        "quality_fail_until": 0,
        "exit_ip": "",
        "ippure_score": 0,
        "human_ratio": 0,
        "native_ip": None,
        "is_residential": None,
        "quality_source": "",
    }

def fetch_candidates() -> list[dict[str, Any]]:
    blacklist = load_blacklist()
    candidates: list[dict[str, Any]] = []
    seen_ips = set()
    
    # 检查本地是否有节点缓存，以确定最大重试尝试次数
    has_cache = len(cached_nodes()) > 0
    max_attempts = 1 if has_cache else 2
    
    log_to_json("INFO", "Main", f"开始拉取官方 API 节点列表 (最大尝试次数: {max_attempts})...")
    for i in range(max_attempts):
        if i > 0:
            time.sleep(1.5)
        try:
            api_text = fetch_api_text()
            rows = parse_vpngate_rows(api_text)
            selected_rows = select_candidate_rows(rows)

            for row in selected_rows:
                ip = row.get("IP", "")
                if not ip or ip in seen_ips:
                    continue

                encoded = row.get("OpenVPN_ConfigData_Base64", "")
                if not encoded:
                    continue

                config_text = decode_config(encoded)
                node = row_to_node(row, config_text)
                candidates.append(node)
                seen_ips.add(ip)

        except Exception as e:
            print(f"[fetch_candidates] Fetch {i+1} failed: {e}", flush=True)
            log_to_json("WARNING", "Main", f"第 {i+1} 次拉取 API 节点失败: {e}")
            if i == max_attempts - 1 and not candidates:
                log_to_json("ERROR", "Main", f"获取官方 API 节点失败: {e}")
                raise
                
    set_state(
        last_fetch_at=time.time(),
        last_fetch_status="ok",
        last_fetch_message=f"Fetched {len(candidates)} unique candidates across multiple attempts.",
        blacklisted_nodes=len(blacklist),
    )
    log_to_json("INFO", "Main", f"成功获取官方 API 节点，共 {len(candidates)} 个候选节点")
    return candidates

def cached_nodes() -> list[dict[str, Any]]:
    return read_json(NODES_FILE, [])

_openvpn_version = None

def get_openvpn_version() -> float:
    global _openvpn_version
    if _openvpn_version is not None:
        return _openvpn_version
    try:
        cmd = shlex.split(OPENVPN_CMD, posix=False) or ["openvpn"]
        res = subprocess.run([cmd[0], "--version"], capture_output=True, text=True, timeout=2)
        match = re.search(r"OpenVPN\s+(\d+\.\d+)", res.stdout or res.stderr)
        if match:
            _openvpn_version = float(match.group(1))
            return _openvpn_version
    except Exception:
        pass
    _openvpn_version = 2.4
    return _openvpn_version

def openvpn_command(config_file: str, route_nopull: bool, dev: str = "tun0") -> list[str]:
    command = shlex.split(OPENVPN_CMD, posix=False) or ["openvpn"]
    command.extend(
        [
            "--config",
            config_file,
            "--dev",
            dev,
            "--dev-type",
            "tun",
            "--pull-filter",
            "ignore",
            "route-ipv6",
            "--pull-filter",
            "ignore",
            "ifconfig-ipv6",
            "--route-delay",
            "2",
            "--connect-retry-max",
            "1",
            "--connect-timeout",
            "15",
            "--auth-user-pass",
            str(AUTH_FILE),
            "--auth-nocache",
        ]
    )
    
    version = get_openvpn_version()
    if version >= 2.5:
        command.extend(["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])
    else:
        command.extend(["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])

    # 使用项目生成的 CA bundle，修复 Let's Encrypt YR1 / Root YR 链验证失败问题。
    if OPENVPN_CA_BUNDLE.is_file():
        command.extend(["--ca", str(OPENVPN_CA_BUNDLE)])

    command.extend(["--verb", "3"])
    
    try:
        content = Path(config_file).read_text(encoding="utf-8", errors="replace")
        if vpn_utils.is_config_tcp(content):
            ptype, host, port = vpn_utils.get_upstream_proxy()
            if ptype == "socks" and host and port:
                command.extend(["--socks-proxy", host, str(port)])
            elif ptype == "http" and host and port:
                command.extend(["--http-proxy", host, str(port)])
    except Exception:
        pass
        
    if route_nopull:
        command.append("--route-nopull")
    return command

def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()

def kill_existing_openvpn_processes() -> None:
    if not sys.platform.startswith("linux"):
        return
    try:
        # Terminate existing openvpn processes managing tun0 or using our vpngate configuration
        subprocess.run(["pkill", "-f", "openvpn.*tun0"], capture_output=True, timeout=2)
        subprocess.run(["pkill", "-f", "openvpn.*vpngate_data"], capture_output=True, timeout=2)
        print("[Cleanup] Terminated existing AimiliVPN OpenVPN processes.", flush=True)
    except Exception as e:
        print(f"[Cleanup Error] Failed to kill existing OpenVPN processes: {e}", flush=True)

def update_handshake_status(line_lower: str) -> None:
    status_map = {
        "resolving": ("解析域名", "正在解析服务器域名与 IP 地址..."),
        "udp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tcp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tls: initial packet": ("证书握手", "已成功发送首包，正在与远程服务器建立 TLS 安全通道..."),
        "verify ok": ("证书校验", "服务器证书校验成功，正在进行身份验证..."),
        "peer connection initiated": ("协商加密", "控制通道已建立，已初始化与服务器的加密对等连接..."),
        "push_request": ("请求配置", "正在向服务器发送 PUSH_REQUEST 请求配置参数与 IP 分配..."),
        "push_reply": ("应用配置", "已接收服务器 PUSH_REPLY，获取到 IP 分配，正在准备配置网卡..."),
        "tun/tap device": ("创建网卡", "正在创建虚拟通道并打开 TUN 虚拟网卡设备..."),
        "do_ifconfig": ("网卡配置", "正在为虚拟网卡配置 IP 地址及相关网络属性..."),
    }
    for key, (short_status, detailed_desc) in status_map.items():
        if key in line_lower:
            set_state(active_node_latency=short_status, last_check_message=detailed_desc)
            break

def run_openvpn_until_ready(config_file: str, keep_alive: bool, route_nopull: bool, timeout: int | None = None, dev: str = "tun0") -> tuple[bool, str, subprocess.Popen[str] | None]:
    limit = timeout if timeout is not None else OPENVPN_TEST_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            openvpn_command(config_file, route_nopull, dev),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT_DIR),
        )
    except FileNotFoundError:
        return False, "openvpn command not found", None
    except OSError as exc:
        return False, f"openvpn start failed: {exc}", None

    lines: queue.Queue[str | None] = queue.Queue()
    startup_done = [False]

    def reader() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            if not startup_done[0]:
                lines.put(line.rstrip())
            else:
                if keep_alive:
                    print(f"[OpenVPN] {line.rstrip()}", flush=True)
        if not startup_done[0]:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.time()
    tail: list[str] = []
    ok = False
    message = "OpenVPN did not complete initialization."
    while time.time() - started < limit:
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if process.poll() is not None:
                break
            continue
        if line is None:
            break
        if line:
            tail.append(line)
            tail = tail[-8:]
            if keep_alive:
                print(f"[OpenVPN] {line}", flush=True)
        lower = line.lower()
        if keep_alive:
            update_handshake_status(lower)
        if "initialization sequence completed" in lower:
            ok = True
            message = f"OpenVPN connected in {int((time.time() - started) * 1000)} ms."
            break
        if "auth_failed" in lower or "authentication failed" in lower:
            message = "AUTH_FAILED"
            break
        if "cannot ioctl" in lower or "fatal error" in lower:
            message = line[-220:]
            break
    else:
        message = f"OpenVPN timeout after {limit}s."
    if not ok:
        raw_message = message

        if tail:
            tail_message = " | ".join(tail[-5:])[-700:]

            # 如果前面已经产生了 timeout 信息，不要被 tail 覆盖掉
            if raw_message and raw_message.startswith("OpenVPN timeout"):
                raw_message = f"{raw_message} | {tail_message}"
            else:
                raw_message = tail_message

        message = format_openvpn_failure_message(raw_message)

    startup_done[0] = True
    if not keep_alive or not ok:
        stop_process(process)
        process = None
    return ok, message, process

def set_rp_filter_loose(interface: str = "tun0") -> None:
    """
    设置 rp_filter=2 loose 模式。
    在策略路由 + tun0 场景下，避免严格反向路径过滤导致回包被内核丢弃。
    """
    targets = ["all", "default"]

    if interface:
        targets.append(interface)

    for target in targets:
        try:
            subprocess.run(
                ["sysctl", "-w", f"net.ipv4.conf.{target}.rp_filter=2"],
                capture_output=True,
                timeout=2,
            )
        except Exception:
            pass


def setup_policy_routing(interface: str = "tun0") -> None:
    set_rp_filter_loose(interface)

    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    try:
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass

    success = False
    for attempt in range(1, 4):
        try:
            set_rp_filter_loose(interface)

            subprocess.run(["ip", "route", "add", "default", "dev", interface, "table", "100"], check=True, timeout=2)
            subprocess.run(["ip", "rule", "add", "oif", interface, "table", "100"], check=True, timeout=2)

            set_rp_filter_loose(interface)

            print(
                f"[policy_routing] Enabled policy routing for interface {interface} "
                f"(attempt {attempt} success, rp_filter=2)",
                flush=True,
            )
            success = True
            break
        except Exception as e:
            print(f"[policy_routing] Attempt {attempt} failed to enable policy routing: {e}", flush=True)
            time.sleep(1)

    if not success:
        print("[policy_routing] Failed to enable policy routing after 3 attempts", flush=True)

def cleanup_policy_routing() -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
        print("[policy_routing] Cleared policy routing table 100", flush=True)
    except Exception:
        pass

def stop_active_openvpn() -> None:
    global active_openvpn_process, active_openvpn_node_id
    cleanup_policy_routing()
    config_to_delete = None
    if active_openvpn_node_id:
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == active_openvpn_node_id), None)
        if node:
            config_to_delete = node.get("config_file")

    active_openvpn_process = None
    active_openvpn_node_id = ""
    set_state(connected_at=None)
    kill_existing_openvpn_processes()
    
    if config_to_delete:
        try:
            path = Path(config_to_delete)
            if path.exists():
                path.unlink()
        except Exception:
            pass

def active_openvpn_running() -> bool:
    return active_openvpn_process is not None and active_openvpn_process.poll() is None

def resolve_active_openvpn_node_id() -> str:
    """
    修正活动节点 ID。

    避免 OpenVPN 实际还在运行，但 active_openvpn_node_id 临时为空，
    导致 UI 显示“活动节点：无”。
    """
    global active_openvpn_node_id

    if active_openvpn_node_id:
        return active_openvpn_node_id

    if active_openvpn_process is not None and active_openvpn_process.poll() is None:
        args = active_openvpn_process.args

        if isinstance(args, str):
            try:
                args = shlex.split(args)
            except Exception:
                args = []

        if isinstance(args, list):
            for i, arg in enumerate(args):
                if arg == "--config" and i + 1 < len(args):
                    node_id = Path(str(args[i + 1])).stem
                    if node_id:
                        active_openvpn_node_id = node_id
                        return node_id

    nodes = read_json(NODES_FILE, [])
    active_node = next((n for n in nodes if n.get("active")), None)

    if active_node and active_openvpn_running():
        node_id = str(active_node.get("id") or "")
        if node_id:
            active_openvpn_node_id = node_id
            return node_id

    return ""


def has_active_vpn_connection() -> bool:
    return bool(resolve_active_openvpn_node_id() and active_openvpn_running())


def set_maintenance_progress(message: str) -> None:
    """
    后台维护进度。

    如果当前已经有可用 VPN 连接，不要把 is_connecting 改成 True，
    否则 UI 会误显示“正在连接 / 测试中”。
    """
    if has_active_vpn_connection():
        set_state(
            is_maintaining=True,
            maintenance_message=message,
        )
    else:
        set_state(
            is_connecting=True,
            last_check_message=message,
        )


def finish_maintenance_progress() -> None:
    if has_active_vpn_connection():
        set_state(
            is_maintaining=False,
            maintenance_message="",
        )

def sort_all_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    now = time.time()

    def ipapi_risk_count(node: dict[str, Any]) -> int:
        return sum(
            1
            for field in IPAPI_RISK_FIELD_LABELS
            if node.get(field) is True
        )

    def quality_status_rank(node: dict[str, Any]) -> int:
        status = str(node.get("quality_status") or "")

        if node.get("active"):
            return 0

        if status == "passed":
            return 1

        if status == "":
            return 2

        if status == "failed":
            return 3

        return 4

    def ippure_rank(node: dict[str, Any]) -> int:
        score = parse_int(node.get("ippure_score"))

        # 没有检测过的放后面，但不要当成 0 分优质节点
        if score <= 0 and node.get("quality_status") != "passed":
            return 999

        return score

    def speed_rank(node: dict[str, Any]) -> int:
        speed = parse_int(node.get("download_speed_bps"))

        # 速度越高越靠前
        return -speed if speed > 0 else 0

    available_nodes = sorted(
        [
            n for n in nodes
            if n.get("probe_status") == "available" or n.get("active")
        ],
        key=lambda n: (
            0 if n.get("active") else 1,
            1 if should_skip_candidate_by_quality(n, now) else 0,
            quality_status_rank(n),
            ippure_rank(n),
            ipapi_risk_count(n),
            0 if n.get("is_residential") is True else 1,
            0 if n.get("native_ip") is True else 1,
            -parse_int(n.get("human_ratio")),
            speed_rank(n),
            parse_int(n.get("latency_ms")) or 999999,
            -parse_int(n.get("score")),
        )
    )

    untested_nodes = sorted(
        [
            n for n in nodes
            if n.get("probe_status") == "not_checked"
               and not n.get("active")
        ],
        key=lambda n: (
            1 if should_skip_candidate_by_quality(n, now) else 0,
            0 if get_country_code(n) in PREFERRED_COUNTRIES else 1,
            preferred_country_priority(n),
            -parse_int(n.get("score")),
            parse_int(n.get("ping")),
        )
    )

    unavailable_nodes = sorted(
        [
            n for n in nodes
            if n.get("probe_status") == "unavailable"
               and not n.get("active")
        ],
        key=lambda n: (
            1 if should_skip_candidate_by_quality(n, now) else 0,
            -parse_int(n.get("score")),
            -float(n.get("probed_at", 0)),
        )
    )

    return available_nodes + untested_nodes + unavailable_nodes

active_test_indexes = set()
test_indexes_lock = threading.Lock()

def preferred_country_priority(node: dict[str, Any]) -> int:
    code = get_country_code(node)

    try:
        return PREFERRED_COUNTRIES.index(code)
    except ValueError:
        return len(PREFERRED_COUNTRIES)

def is_hard_quality_fail_reason(reason: str) -> bool:
    """
    判断是否属于“硬质量失败”。
    这类失败短时间内重复检测意义不大，因此使用更长冷却期。

    注意：测速低于阈值不放进 hard，避免因为临时带宽波动长期跳过节点。
    """
    reason = str(reason or "")

    hard_keywords = [
        "IPPure 系数",
        "ipapi.is 风险命中",
        "IP 类型不是住宅",
        "IP 来源不是原生",
        "人机流量比",
    ]

    return any(keyword in reason for keyword in hard_keywords)


def should_skip_candidate_by_quality(node: dict[str, Any], now: float | None = None) -> bool:
    """
    维护线程 / 自动切换候选预过滤。

    只跳过：
    1. hard fail 冷却期内的节点；
    2. 兼容旧数据：IPPure 超标且仍在冷却期内的节点。

    不跳过测速失败/测速低速等 soft fail，避免临时波动导致候选池过窄。
    """
    if not node:
        return True

    now = now or time.time()
    quality_fail_until = float(node.get("quality_fail_until") or 0)

    if quality_fail_until <= now:
        return False

    quality_fail_type = str(node.get("quality_fail_type") or "")
    quality_fail_reason = str(node.get("quality_fail_reason") or "")
    ippure_score = parse_int(node.get("ippure_score"))

    if quality_fail_type == "hard":
        return True

    if "IPPure 系数" in quality_fail_reason:
        return True

    if ippure_score > QUALITY_MAX_FRAUD_SCORE:
        return True

    return False


QUALITY_CACHE_FIELDS = {
    "quality_status",
    "quality_checked_at",
    "quality_fail_reason",
    "quality_fail_until",
    "quality_fail_type",
    "quality_fail_cooldown_seconds",
    "exit_ip",
    "ippure_score",
    "human_ratio",
    "native_ip",
    "is_residential",
    "quality_source",
    "ipapi_checked",
    "ipapi_error",
    "ipapi_ip",
    "ipapi_asn",
    "ipapi_org",
    "speed_test_checked",
    "speed_test_error",
    "speed_test_url",
    "speed_test_http_code",
    "speed_test_size_bytes",
    "speed_test_time_seconds",
    "download_speed_bps",
    "download_speed_mbps",
    "download_speed_mib_s",
}


def merge_cached_quality_fields(new_node: dict[str, Any], old_node: dict[str, Any] | None) -> dict[str, Any]:
    """
    拉取 VPNGate 新列表时，保留同 ID 节点已有的质量检测缓存。
    否则每次 fetch_candidates() 都会把 quality_fail_until 等字段冲掉。
    """
    if not old_node:
        return new_node

    merged = dict(new_node)

    for field in QUALITY_CACHE_FIELDS:
        if field in old_node:
            merged[field] = old_node.get(field)

    for field in IPAPI_RISK_FIELD_LABELS:
        if field in old_node:
            merged[field] = old_node.get(field)

    return merged

def pick_nodes_to_test(nodes: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    now = time.time()

    pending_all = [
        n for n in nodes
        if not n.get("active")
           and n.get("probe_status") == "not_checked"
    ]

    pending = [
        n for n in pending_all
        if not should_skip_candidate_by_quality(n, now)
    ]

    skipped_count = len(pending_all) - len(pending)
    if skipped_count > 0:
        print(
            f"[维护线程] 已跳过 {skipped_count} 个 IPPure 超标或 hard fail 冷却期内节点",
            flush=True,
        )
        log_to_json(
            "INFO",
            "Quality",
            f"维护线程跳过 {skipped_count} 个 IPPure 超标或 hard fail 冷却期内节点",
        )

    pending.sort(
        key=lambda n: (
            0 if get_country_code(n) in PREFERRED_COUNTRIES else 1,
            preferred_country_priority(n),
            -parse_int(n.get("score")),
            parse_int(n.get("ping")),
        )
    )

    return pending[:limit]

def get_free_test_index() -> int:
    with test_indexes_lock:
        for idx in range(2, 100):
            if idx not in active_test_indexes:
                active_test_indexes.add(idx)
                return idx
        return 99

def release_test_index(idx: int) -> None:
    with test_indexes_lock:
        active_test_indexes.discard(idx)

def test_node_by_id(node_id: str) -> dict[str, Any]:
    with lock:
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        config_file = str(node["config_file"])
        config_text = node.get("config_text") or ""
        h = str(node.get("remote_host") or node.get("ip"))
        p = parse_int(node.get("remote_port"))
        fallback_ping = parse_int(node.get("ping"))

    temp_path = Path(config_file)
    try:
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        temp_path.write_text(config_text, encoding="utf-8")
    except Exception as e:
        raise RuntimeError(f"Failed to write temp config file: {e}")

    latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
    
    idx = get_free_test_index()
    try:
        ok, message, _ = run_openvpn_until_ready(config_file, keep_alive=False, route_nopull=True, timeout=OPENVPN_PROBE_TIMEOUT_SECONDS, dev=f"tun{idx}")
    finally:
        release_test_index(idx)
    
    try:
        if temp_path.exists():
            temp_path.unlink()
    except Exception:
        pass

    temp_node = {
        "id": node_id,
        "ip": h,
        "remote_host": h,
        "remote_port": p,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
    }
    if ok:
        vpn_utils.enrich_ip_info([temp_node])

    with lock:
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if node:
            node["latency_ms"] = latency
            node["probe_status"] = "available" if ok else "unavailable"
            node["probe_message"] = message
            node["probed_at"] = time.time()
            if ok:
                node["owner"] = temp_node["owner"]
                node["asn"] = temp_node["asn"]
                node["as_name"] = temp_node["as_name"]
                node["location"] = temp_node["location"]
                node["ip_type"] = temp_node["ip_type"]
                node["quality"] = temp_node["quality"]
            
            sorted_nodes = sort_all_nodes(nodes)
            write_json(NODES_FILE, sorted_nodes)
            res = next((item for item in sorted_nodes if item.get("id") == node_id), node)
            return res
        else:
            return {}

def test_multiple_nodes(node_ids: list[str]) -> list[dict[str, Any]]:
    with lock:
        nodes = read_json(NODES_FILE, [])
        to_test = [n for n in nodes if n.get("id") in node_ids]

    def test_worker(args: tuple[int, dict[str, Any]]) -> dict[str, Any]:
        idx, n_info = args
        node_id = n_info["id"]
        config_file = n_info["config_file"]
        config_text = n_info.get("config_text") or ""
        h = str(n_info.get("remote_host") or n_info.get("ip"))
        p = parse_int(n_info.get("remote_port"))
        fallback_ping = parse_int(n_info.get("ping"))

        temp_path = Path(config_file)
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            temp_path.write_text(config_text, encoding="utf-8")
        except Exception:
            pass

        latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
        dev_name = f"tun{idx + 1}"

        ok, message, _ = run_openvpn_until_ready(
            config_file,
            keep_alive=False,
            route_nopull=True,
            timeout=OPENVPN_PROBE_TIMEOUT_SECONDS,
            dev=dev_name,
        )

        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass

        temp_node = {
            "id": node_id,
            "latency_ms": latency,
            "probe_status": "available" if ok else "unavailable",
            "probe_message": message,
            "probed_at": time.time(),
            "owner": "",
            "asn": "",
            "as_name": "",
            "location": "",
            "ip_type": "",
            "quality": "",
        }

        if ok:
            ip_to_enrich = {
                "ip": n_info.get("ip"),
                "remote_host": h,
                "owner": "",
                "asn": "",
                "as_name": "",
                "location": "",
                "ip_type": "",
                "quality": "",
            }
            vpn_utils.enrich_ip_info([ip_to_enrich])
            temp_node.update(ip_to_enrich)

        return temp_node

    updated_nodes_map = {}
    total = len(to_test)

    if total == 0:
        set_state(

            last_check_message="没有需要检测的优先国家节点，准备进入下一步...",
        )
    else:
        set_state(

            last_check_message=f"正在并发检测优先国家节点，进度 0/{total}...",
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, total)) as executor:
        futures = {
            executor.submit(test_worker, (idx, n)): n["id"]
            for idx, n in enumerate(to_test)
        }

        done_count = 0

        # 注意：这个 for 必须放在 with 里面。
        # 否则 ThreadPoolExecutor 退出时会先等待全部任务完成，导致看不到实时进度。
        for future in concurrent.futures.as_completed(futures):
            nid = futures[future]
            done_count += 1

            try:
                res = future.result()
                updated_nodes_map[nid] = res

                status = res.get("probe_status")
                msg = res.get("probe_message") or ""

                progress_msg = (
                    f"节点检测进度 {done_count}/{total}: "
                    f"{nid} => {status} / {msg}"
                )

                print(f"[维护线程] {progress_msg}", flush=True)

                set_state(

                    last_check_message=progress_msg,
                )

            except Exception as e:
                err_msg = f"Test exception: {e}"

                updated_nodes_map[nid] = {
                    "id": nid,
                    "probe_status": "unavailable",
                    "probe_message": err_msg,
                    "latency_ms": 0,
                }

                progress_msg = (
                    f"节点检测进度 {done_count}/{total}: "
                    f"{nid} => exception: {e}"
                )

                print(f"[维护线程] {progress_msg}", flush=True)

                set_state(

                    last_check_message=progress_msg,
                )

    with lock:
        current_nodes = read_json(NODES_FILE, [])
        for n in current_nodes:
            nid = n.get("id")
            if nid in updated_nodes_map:
                n.update(updated_nodes_map[nid])

        sorted_nodes = sort_all_nodes(current_nodes)
        write_json(NODES_FILE, sorted_nodes)

    return list(updated_nodes_map.values())

def get_active_country_code(nodes: list[dict[str, Any]], preferred_node_id: str = "") -> str:
    if preferred_node_id:
        node = next((n for n in nodes if n.get("id") == preferred_node_id), None)
        if node:
            return get_country_code(node)

    active_node = next((n for n in nodes if n.get("active")), None)
    if active_node:
        return get_country_code(active_node)

    return ""


def quality_cooldown_active(node: dict[str, Any]) -> bool:
    return float(node.get("quality_fail_until") or 0) > time.time()


def get_auto_switch_candidates(
        nodes: list[dict[str, Any]],
        country_code: str = "",
        attempted_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    attempted_ids = attempted_ids or set()
    target_country = (country_code or "").upper()

    base_candidates = [
        n for n in nodes
        if n.get("probe_status") == "available"
           and not n.get("active")
           and n.get("id") not in attempted_ids
    ]

    if AUTO_SWITCH_SAME_COUNTRY_ONLY and target_country:
        base_candidates = [
            n for n in base_candidates
            if get_country_code(n) == target_country
        ]

    candidates = [
        n for n in base_candidates
        if not should_skip_candidate_by_quality(n)
    ]

    skipped_count = len(base_candidates) - len(candidates)

    if skipped_count > 0:
        print(
            f"[自动切换] 已跳过 {skipped_count} 个 IPPure 超标或 hard fail 冷却期内节点",
            flush=True,
        )
        log_to_json(
            "INFO",
            "Quality",
            f"自动切换跳过 {skipped_count} 个 IPPure 超标或 hard fail 冷却期内节点",
        )

    candidates.sort(
        key=lambda n: (
            parse_int(n.get("ippure_score")) if n.get("quality_status") == "passed" else 999,
            -parse_int(n.get("human_ratio")),
            parse_int(n.get("latency_ms")) or 999999,
            -parse_int(n.get("score")),
        )
    )

    return candidates


def auto_switch_node(
        attempt: int = 0,
        country_code: str = "",
        attempted_ids: set[str] | None = None,
        record_switch: bool = False,
) -> None:
    attempted_ids = attempted_ids or set()

    with lock:
        nodes = read_json(NODES_FILE, [])
        target_country = (country_code or get_active_country_code(nodes, active_openvpn_node_id)).upper()
        candidates = get_auto_switch_candidates(nodes, target_country, attempted_ids)

    if AUTO_SWITCH_MAX_ATTEMPTS > 0 and attempt >= AUTO_SWITCH_MAX_ATTEMPTS:
        msg = f"自动切换已达到最大尝试次数 {AUTO_SWITCH_MAX_ATTEMPTS}，停止切换"
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("WARNING", "VPN", msg)
        return

    if candidates:
        next_node = candidates[0]
        attempted_ids.add(str(next_node.get("id")))

        scope = f"{target_country} 国家内" if (AUTO_SWITCH_SAME_COUNTRY_ONLY and target_country) else "全部国家"
        msg = f"当前连接失效或 IP 质量不达标，正在{scope}切换至备用节点: {next_node['id']}"
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("INFO", "VPN", msg)

        try:
            connect_node_with_quality_check(next_node["id"])
            if record_switch:
                record_auto_node_switch(
                    str(next_node.get("id") or ""),
                    "自动切换成功",
                )
            return

        except Exception as e:
            err_msg = f"切换到备用节点 {next_node['id']} 失败: {e}，继续尝试下一个"
            print(f"[自动切换] {err_msg}", flush=True)
            log_to_json("WARNING", "VPN", err_msg)
            auto_switch_node(
                attempt + 1,
                target_country,
                attempted_ids,
                record_switch=record_switch,
                )
            return

    if AUTO_SWITCH_SAME_COUNTRY_ONLY and target_country:
        msg = f"{target_country} 国家内暂无更多符合条件的可切换节点，正在拉取新节点，稍后继续尝试切换"
    else:
        msg = "没有可用的备选节点，将自动断开并清理当前连接状态，同时在后台异步获取新节点"

    print(f"[自动切换] {msg}", flush=True)
    log_to_json("WARNING", "VPN", msg)
    finish_current_ip_uptime(msg)
    stop_active_openvpn()
    with lock:
        nodes = read_json(NODES_FILE, [])
        for item in nodes:
            item["active"] = False
        write_json(NODES_FILE, nodes)
    set_state(active_openvpn_node_id="", last_check_message=msg)

    def bg_fetch_and_switch() -> None:
        try:
            maintain_valid_nodes(force=False)
            # 补齐后仍优先在原国家内继续尝试
            auto_switch_node(
                country_code=target_country,
                record_switch=record_switch,
            )
        except Exception as e:
            print(f"[自动切换后台补齐] 获取并测试节点失败: {e}", flush=True)

    threading.Thread(target=bg_fetch_and_switch, daemon=True).start()


def connect_node(node_id: str) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting

    previous_node_id = ""

    with lock:
        if is_connecting:
            print("[连接] 正在建立其他连接中，跳过此请求", flush=True)
            return "Already connecting"

        previous_node_id = active_openvpn_node_id

        is_connecting = True
        active_openvpn_node_id = node_id
        set_state(active_openvpn_node_id=node_id, is_connecting=True, active_node_latency="正在连接", last_check_message="正在初始化连接配置...")
        
    try:
        log_to_json("INFO", "VPN", f"开始连接节点: {node_id}")
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")

        set_state(active_node_latency="清理连接", last_check_message="正在关闭与清理旧的 VPN 连接及网卡...")

        # 不要在“节点 ID 变化”时结算 IP 持续时长。
        # IP 持续时长只应该在以下情况结算：
        # 1. 当前 IP 确认不可用
        # 2. 手动断开
        # 3. 更新节点导致连接关闭
        # 4. OpenVPN 异常退出
        # 5. 新节点质量检测通过后，发现出口 IP 真的变了
        #
        # 如果节点变了但出口 IP 没变，应该继续累计同一个 IP 的持续时长。
        stop_active_openvpn()

        set_state(active_node_latency="写入配置", last_check_message="正在写入 OpenVPN 节点配置文件...")
        config_path = Path(node["config_file"])
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            config_path.write_text(node.get("config_text") or "", encoding="utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to write configuration: {e}")

        set_state(active_node_latency="启动核心", last_check_message="正在启动 OpenVPN Core 核心服务并建立连接...")
        ok, message, process = run_openvpn_until_ready(str(node["config_file"]), keep_alive=True, route_nopull=True)
        if not ok or process is None:
            try:
                if config_path.exists():
                    config_path.unlink()
            except Exception:
                pass
            node["probe_status"] = "unavailable"
            node["probe_message"] = message
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
            log_to_json("ERROR", "VPN", f"连接节点 {node_id} 失败: {message}")
            mark_current_ip_uptime_pending_end(f"连接节点 {node_id} 失败: {message}")
            set_state(
                active_openvpn_node_id="",
                is_connecting=False,
                active_node_latency="无活动连接",
                last_check_message=f"连接失败: {message}",
                connected_at=None,
            )
            with lock:
                active_openvpn_node_id = ""
            raise RuntimeError(message)
            
        active_openvpn_process = process
        active_openvpn_node_id = node_id
        
        set_state(active_node_latency="配置路由", last_check_message="正在配置策略路由规则与流量转发...")
        setup_policy_routing("tun0")
        
        global last_active_ping_time, last_active_latency
        last_active_ping_time = time.time()
        last_active_latency = 0
        
        set_state(active_node_latency="测试延迟", last_check_message="正在直连测试代理出口延迟与可用性...")
        try:
            ip = node.get("ip") or node.get("remote_host")
            port = parse_int(node.get("remote_port"))
            fallback = parse_int(node.get("ping"))
            latency = vpn_utils.ping_latency_ms(ip, port, fallback)
            if latency > 0:
                last_active_latency = latency
        except Exception:
            pass
            
        for item in nodes:
            item["active"] = item.get("id") == node_id
            if item["active"]:
                item["probe_message"] = f"Active node. HTTP proxy: http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}"
        write_json(NODES_FILE, nodes)
        
        set_state(last_check_message="正在测试本地代理出站联通性与出口 IP...")
        res = check_proxy_health()
        if res["ok"]:
            set_state(
                proxy_ok=True,
                proxy_ip=res["ip"],
                proxy_latency_ms=res["latency_ms"],
                proxy_error=""
            )
        else:
            set_state(
                proxy_ok=False,
                proxy_ip="-",
                proxy_latency_ms=0,
                proxy_error=res.get("error", "未知错误")
            )

        latency_str = f"{last_active_latency} ms" if last_active_latency > 0 else "检测超时"

        set_state(
            active_openvpn_node_id=node_id,
            is_connecting=False,
            last_check_message=f"Connected {node_id}",
            active_node_latency=latency_str,
            connected_at=time.time(),
        )

        log_to_json("INFO", "VPN", f"节点 {node_id} 连接成功，出口网卡 tun0 已启用")
        return f"Connected {node_id}"
    finally:
        with lock:
            is_connecting = False


class QualityCheckFailed(RuntimeError):
    pass


def parse_ippure_quality(raw: dict[str, Any]) -> dict[str, Any]:
    fraud_score_raw = deep_find_value(raw, {
        "fraudScore", "fraud_score", "riskScore", "risk_score",
        "ippureScore", "ippure_score", "score", "risk"
    })
    human_ratio_raw = deep_find_value(raw, {
        "humanRatio", "human_ratio", "humanScore", "human_score",
        "botScore", "bot_score", "cfBotScore", "cloudflareBotScore"
    })
    residential_raw = deep_find_value(raw, {
        "isResidential", "is_residential", "residential", "isISP", "isp"
    })
    native_raw = deep_find_value(raw, {
        "isNative", "is_native", "native", "nativeIP", "native_ip",
        "isOriginal", "originalIP", "original_ip"
    })
    broadcast_raw = deep_find_value(raw, {
        "isBroadcast", "is_broadcast", "broadcast", "broadcastIP", "broadcast_ip"
    })
    ip_type_raw = deep_find_value(raw, {
        "ipType", "ip_type", "type", "usageType", "usage_type",
        "connectionType", "connection_type"
    })

    asn_raw = deep_find_value(raw, {"asn", "asNumber", "as_number"})
    org_raw = deep_find_value(raw, {"org", "organization", "asOrganization", "as_organization", "isp", "owner"})
    ip_raw = deep_find_value(raw, {"ip", "query", "address"})

    has_ippure_score = fraud_score_raw is not None and str(fraud_score_raw).strip() != ""
    fraud_score = parse_int(fraud_score_raw)
    human_ratio = parse_int(human_ratio_raw)

    is_residential = normalize_bool(residential_raw)
    if is_residential is None and ip_type_raw is not None:
        is_residential = text_contains_any(ip_type_raw, ["residential", "住宅", "家庭宽带", "isp"])

    native_ip = normalize_bool(native_raw)
    broadcast_bool = normalize_bool(broadcast_raw)
    if native_ip is None and broadcast_bool is not None:
        native_ip = not broadcast_bool

    if native_ip is None:
        native_text = deep_find_value(raw, {"nativeStatus", "native_status", "source", "ipSource", "ip_source"})
        if native_text is not None:
            if text_contains_any(native_text, ["原生", "native", "original"]):
                native_ip = True
            elif text_contains_any(native_text, ["广播", "broadcast", "non-native", "非原生"]):
                native_ip = False

    return {
        "source": "ippure",
        "raw": raw,
        "ip": str(ip_raw or ""),
        "has_ippure_score": has_ippure_score,
        "ippure_score": fraud_score,
        "fraud_score": fraud_score,
        "human_ratio": human_ratio,
        "is_residential": is_residential,
        "native_ip": native_ip,
        "ip_type": str(ip_type_raw or ""),
        "asn": str(asn_raw or ""),
        "org": str(org_raw or ""),
    }


def fetch_ippure_quality() -> dict[str, Any]:
    cmd = [
        "curl", "-4", "-s",
        *get_internal_curl_proxy_args("socks5h", "127.0.0.1"),
        IPPURE_API_URL,
        "--max-time", str(QUALITY_HTTP_TIMEOUT_SECONDS),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=QUALITY_HTTP_TIMEOUT_SECONDS + 3)
    if res.returncode != 0:
        raise RuntimeError(f"IPPure 请求失败: curl={res.returncode}, stderr={res.stderr.strip()}")

    body = res.stdout.strip()
    if not body:
        raise RuntimeError("IPPure 返回为空")

    try:
        raw = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"IPPure 返回不是 JSON: {exc}; body={body[:200]}")

    return parse_ippure_quality(raw)

def parse_ipapi_quality(raw: dict[str, Any]) -> dict[str, Any]:
    result = {
        "source": "ipapi.is",
        "raw": raw,
        "ipapi_checked": True,
        "ipapi_ip": str(deep_find_value(raw, {"ip", "query", "address"}) or ""),
        "ipapi_asn": str(deep_find_value(raw, {"asn", "asNumber", "as_number"}) or ""),
        "ipapi_org": "",
    }

    company_raw = raw.get("company")
    if isinstance(company_raw, dict):
        result["ipapi_org"] = str(
            company_raw.get("name")
            or company_raw.get("domain")
            or company_raw.get("type")
            or ""
        )
    else:
        result["ipapi_org"] = str(
            deep_find_value(raw, {"org", "organization", "isp", "owner"}) or ""
        )

    for field in IPAPI_RISK_FIELD_LABELS:
        result[field] = normalize_bool(raw.get(field))

    return result


def fetch_ipapi_quality() -> dict[str, Any]:
    cmd = [
        "curl", "-4", "-s",
        *get_internal_curl_proxy_args("socks5h", "127.0.0.1"),
        IPAPI_API_URL,
        "--max-time", str(QUALITY_HTTP_TIMEOUT_SECONDS),
    ]

    res = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=QUALITY_HTTP_TIMEOUT_SECONDS + 3,
    )

    if res.returncode != 0:
        raise RuntimeError(
            f"ipapi.is 请求失败: curl={res.returncode}, stderr={res.stderr.strip()}"
        )

    body = res.stdout.strip()
    if not body:
        raise RuntimeError("ipapi.is 返回为空")

    try:
        raw = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"ipapi.is 返回不是 JSON: {exc}; body={body[:200]}")

    return parse_ipapi_quality(raw)

def strip_ansi(text: str) -> str:
    """
    去掉 speedtest 输出里的 ANSI 颜色控制字符。
    """
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", str(text or ""))


def parse_data_used_to_bytes(value: str, unit: str) -> int:
    """
    把 speedtest 输出里的 data used 转成 bytes。
    例如：
    98.7 MB -> 103494451
    """
    try:
        n = float(value)
    except (TypeError, ValueError):
        return 0

    unit = str(unit or "").upper()

    if unit == "KB":
        return int(n * 1024)

    if unit == "MB":
        return int(n * 1024 * 1024)

    if unit == "GB":
        return int(n * 1024 * 1024 * 1024)

    if unit == "B":
        return int(n)

    return 0


def convert_speed_to_mbps(value: str, unit: str) -> float:
    """
    把 speedtest 输出的速度统一转为 Mbps。
    常见单位：
    Kbps / Mbps / Gbps
    """
    try:
        n = float(value)
    except (TypeError, ValueError):
        return 0.0

    unit = str(unit or "").lower()

    if unit == "kbps":
        return n / 1000

    if unit == "mbps":
        return n

    if unit == "gbps":
        return n * 1000

    return 0.0


def check_speedtest_available() -> bool:
    try:
        res = subprocess.run(
            ["which", SPEEDTEST_CMD],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return res.returncode == 0
    except Exception:
        return False


def install_speedtest_cli() -> None:
    """
    自动安装 Ookla speedtest CLI。

    注意：
    - 项目本身只支持 Ubuntu，所以这里按 Ubuntu packagecloud 源安装；
    - 如果系统不是 root 运行，会直接失败；
    - 正常情况下建议在 install.sh 里安装，这里只是兜底。
    """
    if check_speedtest_available():
        return

    if not SPEEDTEST_AUTO_INSTALL:
        raise RuntimeError("speedtest 未安装，且 SPEEDTEST_AUTO_INSTALL=0，跳过自动安装")

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise RuntimeError("speedtest 未安装，当前进程不是 root，无法自动安装")

    print("[测速] speedtest 未安装，正在自动安装 Ookla speedtest CLI...", flush=True)
    log_to_json("INFO", "Speed", "speedtest 未安装，正在自动安装 Ookla speedtest CLI")

    install_cmd = r"""
set -e
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y curl gnupg ca-certificates lsb-release

curl -fsSL https://packagecloud.io/ookla/speedtest-cli/gpgkey \
  | gpg --dearmor -o /usr/share/keyrings/ookla-speedtest.gpg

echo "deb [signed-by=/usr/share/keyrings/ookla-speedtest.gpg] https://packagecloud.io/ookla/speedtest-cli/ubuntu/ $(lsb_release -cs) main" \
  > /etc/apt/sources.list.d/ookla-speedtest.list

apt-get update -qq
apt-get install -y speedtest
"""

    res = subprocess.run(
        ["bash", "-lc", install_cmd],
        capture_output=True,
        text=True,
        timeout=SPEEDTEST_INSTALL_TIMEOUT_SECONDS,
    )

    if res.returncode != 0:
        raise RuntimeError(
            f"安装 speedtest 失败: returncode={res.returncode}, stderr={res.stderr.strip()}"
        )

    if not check_speedtest_available():
        raise RuntimeError("speedtest 安装后仍不可用")

    print("[测速] speedtest 安装完成", flush=True)
    log_to_json("INFO", "Speed", "speedtest 安装完成")

def ensure_speedtest_interface_exists(interface: str) -> None:
    """
    确认测速网卡存在。
    默认要求 tun0 已经创建成功，否则不进行测速。
    """
    iface = str(interface or "").strip()
    if not iface:
        raise RuntimeError("speedtest 测速接口为空")

    iface_path = Path("/sys/class/net") / iface

    if not iface_path.exists():
        raise RuntimeError(f"speedtest 测速接口 {iface} 不存在，请确认 OpenVPN 已成功创建 tun0")

def build_speedtest_env() -> dict[str, str]:
    """
    给 Ookla speedtest CLI 补齐运行环境。

    修复：
    systemd 服务环境下 HOME / USER / LOGNAME 等变量可能为空，
    speedtest CLI 可能因此崩溃：
    basic_string::_M_construct null not valid
    """
    env = os.environ.copy()

    env.setdefault("HOME", "/root")
    env.setdefault("USER", "root")
    env.setdefault("LOGNAME", "root")
    env.setdefault("LANG", "C.UTF-8")
    env.setdefault("LC_ALL", "C.UTF-8")

    # 给 speedtest 写配置 / 缓存用，避免 HOME 异常
    config_home = DATA_DIR / ".config"
    cache_home = DATA_DIR / ".cache"

    try:
        config_home.mkdir(parents=True, exist_ok=True)
        cache_home.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    env.setdefault("XDG_CONFIG_HOME", str(config_home))
    env.setdefault("XDG_CACHE_HOME", str(cache_home))

    return env


def ensure_speedtest_interface_ready(interface: str) -> None:
    """
    确认 tun0 已存在并且已有 IPv4 地址。
    """
    iface = str(interface or "").strip()
    if not iface:
        raise RuntimeError("speedtest 测速接口为空")

    iface_path = Path("/sys/class/net") / iface
    if not iface_path.exists():
        raise RuntimeError(f"speedtest 测速接口 {iface} 不存在，请确认 OpenVPN 已成功创建 tun0")

    res = subprocess.run(
        ["ip", "-4", "addr", "show", "dev", iface],
        capture_output=True,
        text=True,
        timeout=5,
    )

    if res.returncode != 0 or "inet " not in res.stdout:
        raise RuntimeError(f"speedtest 测速接口 {iface} 没有 IPv4 地址，请确认 OpenVPN 已完成初始化")

def is_retryable_speedtest_error(message: str) -> bool:
    """
    判断 speedtest 错误是否适合重试。

    重点处理：
    - Cannot open socket
    - Download: FAILED
    """
    s = str(message or "").lower()

    retry_keywords = [
        "cannot open socket",
        "download: failed",
        "download failed",
        "unable to connect",
        "connection timed out",
        "timed out",
        "network is unreachable",
        "temporary failure",
    ]

    return any(k in s for k in retry_keywords)

def run_speedtest_once(speedtest_env: dict[str, str], attempt: int, max_attempts: int) -> dict[str, Any]:
    """
    单次 speedtest 测速。
    失败时抛 RuntimeError，由 fetch_proxy_speed_quality() 负责判断是否重试。
    """
    print(
        f"[测速] 开始使用 speedtest 通过 {SPEEDTEST_INTERFACE} 测试出口下载速度..."
        f" 第 {attempt}/{max_attempts} 次",
        flush=True,
    )
    log_to_json(
        "INFO",
        "Speed",
        f"开始使用 speedtest 通过 {SPEEDTEST_INTERFACE} 测试出口下载速度，第 {attempt}/{max_attempts} 次",
    )

    cmd = [
        SPEEDTEST_CMD,
        "--interface", SPEEDTEST_INTERFACE,
        "--accept-license",
        "--accept-gdpr",
        "--progress=no",
    ]

    started_at = time.time()

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        env=speedtest_env,
        cwd=str(DATA_DIR),
    )

    download_mbps = None
    data_used_bytes = 0
    last_lines: list[str] = []

    try:
        assert process.stdout is not None

        for raw_line in process.stdout:
            line = strip_ansi(raw_line).strip()

            if line:
                last_lines.append(line)
                last_lines = last_lines[-20:]

            for part in re.split(r"[\r\n]+", line):
                part = part.strip()
                if not part:
                    continue

                # 只接受完整下载结果：
                # Download: 67.45 Mbps (data used: 98.7 MB)
                match = re.search(
                    r"Download:\s+([\d.]+)\s+([KMG]bps)\s+\(data used:\s+([\d.]+)\s+([KMG]?B)\)",
                    part,
                    re.IGNORECASE,
                )

                if not match:
                    continue

                download_mbps = convert_speed_to_mbps(match.group(1), match.group(2))
                data_used_bytes = parse_data_used_to_bytes(match.group(3), match.group(4))

            if download_mbps and download_mbps > 0 and data_used_bytes > 0:
                try:
                    process.terminate()
                    process.wait(timeout=3)
                except Exception:
                    try:
                        process.kill()
                    except Exception:
                        pass
                break

            if time.time() - started_at > SPEEDTEST_TIMEOUT_SECONDS:
                try:
                    process.kill()
                except Exception:
                    pass

                raise RuntimeError(
                    f"speedtest 超时，超过 {SPEEDTEST_TIMEOUT_SECONDS}s 未获取下载速度，最近输出: "
                    + " | ".join(last_lines[-8:])
                )

        if download_mbps is None or download_mbps <= 0 or data_used_bytes <= 0:
            try:
                process.wait(timeout=3)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass

            raise RuntimeError(
                "未能从 speedtest 输出中获取完整下载速度，最近输出: "
                + " | ".join(last_lines[-8:])
            )

        time_total = time.time() - started_at

        speed_bps = int(download_mbps * 1000 * 1000 / 8)
        speed_mib_s = speed_bps / 1024 / 1024

        print(
            f"[测速] speedtest 下载测速完成: "
            f"{speed_mib_s:.2f} MB/s | {download_mbps:.2f} Mbps, "
            f"数据量 {data_used_bytes} bytes, 耗时 {time_total:.2f}s",
            flush=True,
        )
        log_to_json(
            "INFO",
            "Speed",
            f"speedtest 下载测速完成: {speed_mib_s:.2f} MB/s | {download_mbps:.2f} Mbps, "
            f"数据量 {data_used_bytes} bytes, 耗时 {time_total:.2f}s",
        )

        return {
            "speed_test_checked": True,
            "speed_test_url": f"speedtest://interface/{SPEEDTEST_INTERFACE}",
            "speed_test_http_code": "speedtest",
            "speed_test_size_bytes": data_used_bytes,
            "speed_test_time_seconds": round(time_total, 2),
            "download_speed_bps": speed_bps,
            "download_speed_mbps": round(download_mbps, 2),
            "download_speed_mib_s": round(speed_mib_s, 2),
            "speed_test_timeout": False,
        }

    finally:
        if process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=3)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass


def fetch_proxy_speed_quality() -> dict[str, Any]:
    """
    使用 Ookla speedtest CLI 通过 tun0 测试下载速度。

    增强：
    - Cannot open socket / Download: FAILED 自动重试；
    - 只接受包含 data used 的完整下载结果；
    - 数据量为 0 不算测速完成。
    """
    install_speedtest_cli()
    ensure_speedtest_interface_ready(SPEEDTEST_INTERFACE)

    speedtest_env = build_speedtest_env()

    last_error: Exception | None = None

    for attempt in range(1, SPEEDTEST_RETRY_TIMES + 1):
        try:
            return run_speedtest_once(
                speedtest_env=speedtest_env,
                attempt=attempt,
                max_attempts=SPEEDTEST_RETRY_TIMES,
            )

        except Exception as exc:
            last_error = exc
            msg = str(exc)

            can_retry = is_retryable_speedtest_error(msg)
            is_last = attempt >= SPEEDTEST_RETRY_TIMES

            if not can_retry or is_last:
                raise

            print(
                f"[测速] speedtest 第 {attempt}/{SPEEDTEST_RETRY_TIMES} 次失败，可重试错误: {msg}，"
                f"{SPEEDTEST_RETRY_DELAY_SECONDS}s 后重试...",
                flush=True,
            )
            log_to_json(
                "WARNING",
                "Speed",
                f"speedtest 第 {attempt}/{SPEEDTEST_RETRY_TIMES} 次失败，可重试错误: {msg}，"
                f"{SPEEDTEST_RETRY_DELAY_SECONDS}s 后重试",
            )

            time.sleep(SPEEDTEST_RETRY_DELAY_SECONDS)

    raise RuntimeError(f"speedtest 测速失败: {last_error}")

def evaluate_ip_quality(info: dict[str, Any]) -> tuple[bool, str]:
    score = parse_int(info.get("ippure_score"))

    if not info.get("has_ippure_score"):
        return False, "无法读取 IPPure 风控系数"

    if score > QUALITY_MAX_FRAUD_SCORE:
        return False, f"IPPure 系数 {score}% 超过阈值 {QUALITY_MAX_FRAUD_SCORE}%"

    if QUALITY_IPAPI_STRICT and info.get("ipapi_error"):
        return False, f"ipapi.is 检测异常: {info.get('ipapi_error')}"

    if QUALITY_CHECK_IPAPI_ENABLED and info.get("ipapi_checked"):
        for field, label in IPAPI_RISK_FIELD_LABELS.items():
            reject_enabled = IPAPI_REJECT_CONFIG[field]()

            if reject_enabled and info.get(field) is True:
                return False, f"ipapi.is 风险命中: {label}=true"

    if QUALITY_SPEED_STRICT and info.get("speed_test_error"):
        return False, f"出口测速异常: {info.get('speed_test_error')}"

    if QUALITY_CHECK_SPEED_ENABLED and info.get("speed_test_checked"):
        speed_bps = parse_int(info.get("download_speed_bps"))

        if speed_bps < QUALITY_MIN_DOWNLOAD_SPEED_BPS:
            speed_mib = speed_bps / 1024 / 1024
            min_mib = QUALITY_MIN_DOWNLOAD_SPEED_BPS / 1024 / 1024
            return False, f"出口下载速度 {speed_mib:.2f} MB/s 低于阈值 {min_mib:.2f} MB/s"

    if QUALITY_REQUIRE_RESIDENTIAL and info.get("is_residential") is not True:
        return False, "IP 类型不是住宅/家庭宽带 IP"

    if QUALITY_REQUIRE_NATIVE and info.get("native_ip") is not True:
        return False, "IP 来源不是原生 IP"

    if QUALITY_MIN_HUMAN_RATIO > 0:
        human_ratio = parse_int(info.get("human_ratio"))
        if human_ratio < QUALITY_MIN_HUMAN_RATIO:
            return False, f"人机流量比 {human_ratio}% 低于阈值 {QUALITY_MIN_HUMAN_RATIO}%"

    return True, "IP 质量达标"


def update_node_quality(node_id: str, quality_info: dict[str, Any], passed: bool, reason: str) -> None:
    with lock:
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)

        if not node:
            return

        now = time.time()

        node["quality_status"] = "passed" if passed else "failed"
        node["quality_checked_at"] = now
        node["quality_fail_reason"] = "" if passed else reason

        if passed:
            node["quality_fail_until"] = 0
            node["quality_fail_type"] = ""
            node["quality_fail_cooldown_seconds"] = 0
        else:
            is_hard_fail = is_hard_quality_fail_reason(reason)
            cooldown = (
                QUALITY_HARD_FAIL_COOLDOWN_SECONDS
                if is_hard_fail
                else QUALITY_FAIL_COOLDOWN_SECONDS
            )

            node["quality_fail_until"] = now + cooldown
            node["quality_fail_type"] = "hard" if is_hard_fail else "soft"
            node["quality_fail_cooldown_seconds"] = cooldown

        # IPPure 基础质量信息

        node["exit_ip"] = quality_info.get("ip") or node.get("exit_ip") or ""
        node["ippure_score"] = parse_int(quality_info.get("ippure_score"))
        node["human_ratio"] = parse_int(quality_info.get("human_ratio"))
        node["native_ip"] = quality_info.get("native_ip")
        node["is_residential"] = quality_info.get("is_residential")

        if quality_info.get("asn"):
            node["asn"] = quality_info.get("asn")

        if quality_info.get("org"):
            node["as_name"] = quality_info.get("org")

        if quality_info.get("ip_type"):
            node["ip_type"] = quality_info.get("ip_type")

        # ipapi.is 风险字段
        node["ipapi_checked"] = quality_info.get("ipapi_checked", False)
        node["ipapi_error"] = quality_info.get("ipapi_error", "")
        node["ipapi_ip"] = quality_info.get("ipapi_ip", "")
        node["ipapi_asn"] = quality_info.get("ipapi_asn", "")
        node["ipapi_org"] = quality_info.get("ipapi_org", "")

        for field in IPAPI_RISK_FIELD_LABELS:
            node[field] = quality_info.get(field)

        # 7928 出口测速字段
        node["speed_test_checked"] = quality_info.get("speed_test_checked", False)
        node["speed_test_error"] = quality_info.get("speed_test_error", "")
        node["speed_test_url"] = quality_info.get("speed_test_url", "")
        node["speed_test_http_code"] = quality_info.get("speed_test_http_code", "")
        node["speed_test_size_bytes"] = parse_int(quality_info.get("speed_test_size_bytes"))
        node["speed_test_time_seconds"] = parse_float(quality_info.get("speed_test_time_seconds"))
        node["download_speed_bps"] = parse_int(quality_info.get("download_speed_bps"))
        node["download_speed_mbps"] = parse_float(quality_info.get("download_speed_mbps"))
        node["download_speed_mib_s"] = parse_float(quality_info.get("download_speed_mib_s"))

        # 质量来源
        quality_sources = ["ippure"]

        if quality_info.get("ipapi_checked"):
            quality_sources.append("ipapi")

        if quality_info.get("speed_test_checked"):
            quality_sources.append("speedtest")

        node["quality_source"] = "+".join(quality_sources)

        if not passed:
            node["active"] = False
            node["probe_message"] = f"IP质量不达标: {reason}"

        write_json(NODES_FILE, sort_all_nodes(nodes))


def check_active_exit_ip_quality(node_id: str) -> tuple[bool, str, dict[str, Any]]:
    if not QUALITY_CHECK_ENABLED:
        return True, "IP质量检测未启用", {}

    # 1. 先做原有 IPPure 检测
    quality_info = fetch_ippure_quality()

    # 2. 再做 ipapi.is 补充检测
    if QUALITY_CHECK_IPAPI_ENABLED:
        try:
            ipapi_info = fetch_ipapi_quality()

            for field in IPAPI_RISK_FIELD_LABELS:
                quality_info[field] = ipapi_info.get(field)

            quality_info["ipapi_checked"] = True
            quality_info["ipapi_ip"] = ipapi_info.get("ipapi_ip", "")
            quality_info["ipapi_asn"] = ipapi_info.get("ipapi_asn", "")
            quality_info["ipapi_org"] = ipapi_info.get("ipapi_org", "")
            quality_info["ipapi_error"] = ""

        except Exception as exc:
            quality_info["ipapi_checked"] = False
            quality_info["ipapi_error"] = str(exc)

    # 3. 先按原有 IPPure + ipapi 质量逻辑判断
    # 如果这里已经不达标，就不要再测速，减少对节点的影响
    passed, reason = evaluate_ip_quality(quality_info)

    # 4. 只有前面的 IP 质量通过后，才进行 7928 出口测速
    if passed and QUALITY_CHECK_SPEED_ENABLED:
        set_state(last_check_message=f"正在通过 {SPEEDTEST_INTERFACE} 使用 speedtest 进行出口下载测速...")

        try:
            speed_info = fetch_proxy_speed_quality()

            quality_info["speed_test_checked"] = True
            quality_info["speed_test_error"] = ""
            quality_info["speed_test_url"] = speed_info.get("speed_test_url", "")
            quality_info["speed_test_http_code"] = speed_info.get("speed_test_http_code", "")
            quality_info["speed_test_size_bytes"] = speed_info.get("speed_test_size_bytes", 0)
            quality_info["speed_test_time_seconds"] = speed_info.get("speed_test_time_seconds", 0)
            quality_info["download_speed_bps"] = speed_info.get("download_speed_bps", 0)
            quality_info["download_speed_mbps"] = speed_info.get("download_speed_mbps", 0)
            quality_info["download_speed_mib_s"] = speed_info.get("download_speed_mib_s", 0)

        except Exception as exc:
            quality_info["speed_test_checked"] = False
            quality_info["speed_test_error"] = str(exc)

            print(f"[测速] speedtest tun0 出口测速失败: {exc}", flush=True)
            log_to_json("WARNING", "Speed", f"speedtest tun0 出口测速失败: {exc}")

        # 5. 加入测速结果后，再完整判断一次
        passed, reason = evaluate_ip_quality(quality_info)

    # 6. 写入节点质量结果
    update_node_quality(node_id, quality_info, passed, reason)

    # 7. 写入全局状态
    state_updates = {
        "proxy_quality_ok": passed,
        "proxy_quality_error": "" if passed else reason,
        "proxy_ippure_score": parse_int(quality_info.get("ippure_score")),
        "proxy_human_ratio": parse_int(quality_info.get("human_ratio")),
        "proxy_native_ip": quality_info.get("native_ip"),
        "proxy_is_residential": quality_info.get("is_residential"),

        "proxy_ipapi_checked": quality_info.get("ipapi_checked", False),
        "proxy_ipapi_error": quality_info.get("ipapi_error", ""),
        "proxy_ipapi_ip": quality_info.get("ipapi_ip", ""),
        "proxy_ipapi_asn": quality_info.get("ipapi_asn", ""),
        "proxy_ipapi_org": quality_info.get("ipapi_org", ""),

        "proxy_speed_test_checked": quality_info.get("speed_test_checked", False),
        "proxy_speed_test_error": quality_info.get("speed_test_error", ""),
        "proxy_download_speed_bps": parse_int(quality_info.get("download_speed_bps")),
        "proxy_download_speed_mbps": parse_float(quality_info.get("download_speed_mbps")),
        "proxy_download_speed_mib_s": parse_float(quality_info.get("download_speed_mib_s")),
        "proxy_speed_test_size_bytes": parse_int(quality_info.get("speed_test_size_bytes")),
        "proxy_speed_test_time_seconds": parse_float(quality_info.get("speed_test_time_seconds")),
    }

    for field in IPAPI_RISK_FIELD_LABELS:
        state_updates[f"proxy_{field}"] = quality_info.get(field)

    set_state(**state_updates)

    return passed, reason, quality_info


def connect_node_with_quality_check(node_id: str) -> str:
    """
    连接节点并执行 IP 质量 / 速度检测。

    修复点：
    - 如果是从一个已有活动节点切换到另一个节点，但外层没有提前 mark_node_switch_start，
      这里自动补一条开始时间；
    - 避免节点已经切换成功，但“最近 10 次节点切换耗时”图表没有新增记录。
    """
    previous_node_id = active_openvpn_node_id

    state = read_json(STATE_FILE, {})
    if (
            previous_node_id
            and previous_node_id != node_id
            and not state.get("node_switch_started_at")
    ):
        mark_node_switch_start(
            f"切换节点: {previous_node_id} -> {node_id}"
        )

    result = connect_node(node_id)

    set_state(last_check_message="正在检测出口 IP 质量与 7928 代理下载速度...")
    print("[质量检测] 正在检测出口 IP 质量与 7928 代理下载速度...", flush=True)

    try:
        passed, reason, quality_info = check_active_exit_ip_quality(node_id)
    except Exception as exc:
        reason = f"IP质量检测异常: {exc}"
        update_node_quality(node_id, {}, False, reason)
        set_state(proxy_quality_ok=False, proxy_quality_error=reason)
        mark_current_ip_uptime_pending_end(reason)
        stop_active_openvpn()
        raise QualityCheckFailed(reason) from exc

    if not passed:
        log_to_json("WARNING", "Quality", f"节点 {node_id} IP质量不达标: {reason}")
        mark_current_ip_uptime_pending_end(f"IP质量或测速不达标: {reason}")
        stop_active_openvpn()
        raise QualityCheckFailed(reason)

    # 只有 OpenVPN 连接成功，并且 IPPure / ipapi / 速度检测全部通过后，才保存为上次成功节点
    nodes = read_json(NODES_FILE, [])
    node = next((item for item in nodes if item.get("id") == node_id), None)
    save_last_connected_node(node_id, node)

    print(f"[质量检测] 节点 {node_id} 已通过质量检测，保存为上次成功节点", flush=True)
    log_to_json("INFO", "Quality", f"节点 {node_id} IP质量达标，已保存为上次成功节点: {quality_info}")


    finish_node_switch_duration(f"已切换到 {node_id}，IP质量与测速达标")

    exit_ip = (
            quality_info.get("ip")
            or quality_info.get("ipapi_ip")
            or read_json(STATE_FILE, {}).get("proxy_ip")
            or ""
    )

    begin_or_continue_ip_uptime(
        exit_ip,
        node_id=node_id,
        reason="IP质量与测速达标，开始统计连接时间",
    )

    set_state(
        is_connecting=False,
        is_maintaining=False,
        maintenance_message="",
        active_openvpn_node_id=node_id,
        last_check_message=f"Connected {node_id}; IP质量达标",
    )
    return result

def connect_saved_node_without_quality_check(node_id: str) -> str:
    """
    启动恢复专用：
    只要求 OpenVPN 连接成功，并且 7928 代理可以访问网络。
    不执行 IPPure / ipapi / 下载测速，避免服务重启后恢复时间过长。
    """
    result = connect_node(node_id)

    set_state(last_check_message="正在验证上次节点的 7928 代理出站能力...")

    res = check_proxy_health()

    if not res.get("ok"):
        reason = res.get("error", "7928 代理出站检测失败")

        set_state(
            proxy_ok=False,
            proxy_ip="-",
            proxy_latency_ms=0,
            proxy_error=reason,
            last_check_message=f"恢复上次节点失败: {reason}",
        )
        finish_current_ip_uptime(f"启动恢复上次节点失败: {reason}")
        stop_active_openvpn()
        raise RuntimeError(reason)

    set_state(
        proxy_ok=True,
        proxy_ip=res.get("ip", "-"),
        proxy_latency_ms=res.get("latency_ms", 0),
        proxy_error="",
        is_connecting=False,
        is_maintaining=False,
        maintenance_message="",
        active_openvpn_node_id=node_id,
        last_check_message=f"已恢复上次节点: {node_id}",
    )

    begin_or_continue_ip_uptime(
        res.get("ip", ""),
        node_id=node_id,
        reason="启动恢复上次已达标节点，继续统计连接时间",
    )

    print(f"[启动恢复] 上次节点 7928 出站检测通过: {node_id}", flush=True)
    log_to_json("INFO", "VPN", f"上次节点 7928 出站检测通过: {node_id}")

    return result


def maintain_valid_nodes(force: bool = False) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    ensure_dirs()
    is_connecting = not has_active_vpn_connection()
    try:
        if force:
            with lock:
                if active_openvpn_node_id:
                    mark_node_switch_start(
                        f"手动检测补齐 / 更新节点，准备从 {active_openvpn_node_id} 切换"
                    )

                finish_current_ip_uptime("手动更新节点，关闭当前连接")
                stop_active_openvpn()
        elif not active_openvpn_running():
            has_active_id = False
            with lock:
                if active_openvpn_node_id:
                    has_active_id = True

                    mark_node_switch_start(
                        f"当前 OpenVPN 进程已意外退出，准备从 {active_openvpn_node_id} 自动切换"
                    )

                    finish_current_ip_uptime("当前 OpenVPN 进程已意外退出")
                    stop_active_openvpn()
            if has_active_id:
                print("[维护线程] 检测到当前 OpenVPN 进程已意外退出，准备自动切换节点", flush=True)
                is_connecting = False
                auto_switch_node(record_switch=True)
                is_connecting = True

        try:
            set_maintenance_progress("正在拉取最新的免费 VPN 节点列表...")
            candidates = fetch_candidates()
        except Exception as exc:
            vpn_utils.check_and_fix_dns()
            set_state(last_fetch_at=time.time(), last_fetch_status="error", last_fetch_message=str(exc))
            candidates = []

        if not candidates:
            is_connecting = False
            return "没有拉取到新节点"


        with lock:
            current_nodes = read_json(NODES_FILE, [])

            active_node = None
            if active_openvpn_node_id:
                active_node = next(
                    (n for n in current_nodes if n.get("id") == active_openvpn_node_id),
                    None,
                )

            merged: list[dict[str, Any]] = []
            seen_ids: set[str] = set()

            existing_by_id = {
                str(n.get("id")): n
                for n in current_nodes
                if n.get("id")
            }

            if active_node:
                merged.append(active_node)
                seen_ids.add(active_node["id"])

            for cand in candidates:
                if cand["id"] not in seen_ids:
                    cached_node = existing_by_id.get(str(cand["id"]))
                    merged.append(merge_cached_quality_fields(cand, cached_node))
                    seen_ids.add(cand["id"])

            if len(merged) > 1000:
                merged = merged[:1000]
                
            for n in merged:
                config_path = Path(n["config_file"])
                if not config_path.exists():
                    try:
                        config_path.write_text(n["config_text"], encoding="utf-8")
                    except Exception:
                        pass
                        
            write_json(NODES_FILE, merged)

        # Test the first 10 non-active nodes from the new list
        with lock:
            current_nodes = read_json(NODES_FILE, [])
            to_test = pick_nodes_to_test(current_nodes, TEST_BATCH_SIZE)
            to_test_ids = [n["id"] for n in to_test]

        print(f"[维护线程] 正在检测优先国家节点，数量 {len(to_test_ids)}: {to_test_ids}", flush=True)
        set_state(
            last_check_message=f"正在并发检测筛选可用节点，进度 0/{len(to_test_ids)}，这可能需要 5-30 秒...",
        )
        test_multiple_nodes(to_test_ids)

        is_connecting = False

        should_auto_switch = False

        with lock:
            merged = read_json(NODES_FILE, [])

            if not active_openvpn_running():
                available_candidates = [
                    n for n in merged
                    if n.get("probe_status") == "available"
                       and not should_skip_candidate_by_quality(n)
                ]

                should_auto_switch = bool(available_candidates)

        if should_auto_switch:
            print(
                "[维护线程] 当前没有运行中的 OpenVPN，检测到可用节点，准备自动连接",
                flush=True,
            )
            log_to_json(
                "INFO",
                "VPN",
                "当前没有运行中的 OpenVPN，检测到可用节点，准备自动连接",
            )

            auto_switch_node()

        valid_nodes_count = len([n for n in merged if n.get("probe_status") == "available"])

        message = f"Fetched {len(candidates)} nodes. Tested {len(to_test_ids)} prioritized nodes."
        if has_active_vpn_connection():
            finish_maintenance_progress()
            set_state(
                last_check_at=time.time(),
                active_openvpn_node_id=resolve_active_openvpn_node_id(),
                valid_nodes=valid_nodes_count,
            )
        else:
            is_connecting = False
            set_state(
                is_connecting=False,
                last_check_at=time.time(),
                last_check_message=message,
                active_openvpn_node_id=active_openvpn_node_id,
                valid_nodes=valid_nodes_count,
            )
        return message
    except Exception as e:
        is_connecting = False
        raise e

def restore_last_connected_node(max_attempts: int = 2) -> bool:
    """
    服务重启 / GitHub 更新后，优先尝试恢复上次成功连接的节点。
    连续失败 max_attempts 次后返回 False，由原有维护线程继续拉取和自动切换。
    """
    global is_connecting, active_openvpn_node_id

    node_id = load_last_connected_node_id()
    if not node_id:
        print("[启动恢复] 没有保存的上次连接节点，跳过快速恢复", flush=True)
        return False

    nodes = read_json(NODES_FILE, [])
    node = next((n for n in nodes if n.get("id") == node_id), None)

    if not node:
        print(f"[启动恢复] 保存的节点 {node_id} 不在 nodes.json 中，跳过快速恢复", flush=True)
        clear_last_connected_node()
        return False

    if not node.get("config_text"):
        print(f"[启动恢复] 保存的节点 {node_id} 缺少 config_text，跳过快速恢复", flush=True)
        clear_last_connected_node()
        return False

    print(f"[启动恢复] 准备优先重连上次节点: {node_id}", flush=True)
    log_to_json("INFO", "VPN", f"准备优先重连上次节点: {node_id}")

    for attempt in range(1, max_attempts + 1):
        try:
            # main() 初始化时 is_connecting=True；
            # 这里必须先置 False，否则 connect_node() 会直接返回 Already connecting。
            with lock:
                is_connecting = False
                active_openvpn_node_id = ""

            set_state(
                is_connecting=True,
                active_openvpn_node_id=node_id,
                last_check_message=f"正在恢复上次连接节点，第 {attempt}/{max_attempts} 次: {node_id}",
                active_node_latency="正在恢复",
            )


            print(f"[启动恢复] 第 {attempt}/{max_attempts} 次尝试重连: {node_id}", flush=True)
            connect_saved_node_without_quality_check(node_id)

            print(f"[启动恢复] 已成功恢复上次节点: {node_id}", flush=True)
            log_to_json("INFO", "VPN", f"已成功恢复上次节点: {node_id}")
            return True

        except Exception as exc:
            print(f"[启动恢复] 第 {attempt}/{max_attempts} 次重连失败: {exc}", flush=True)
            log_to_json("WARNING", "VPN", f"恢复上次节点失败 {attempt}/{max_attempts}: {exc}")

            with lock:
                is_connecting = False
                active_openvpn_node_id = ""

            set_state(
                is_connecting=False,
                active_openvpn_node_id="",
                last_check_message=f"恢复上次节点失败 {attempt}/{max_attempts}: {exc}",
                active_node_latency="无活动连接",
            )

            if attempt < max_attempts:
                time.sleep(3)

    print("[启动恢复] 上次节点连续重连失败，清除缓存并交给原有逻辑自动选择节点", flush=True)
    log_to_json("WARNING", "VPN", "上次节点连续重连失败，清除缓存并交给原有逻辑自动选择节点")
    clear_last_connected_node()

    return False


def startup_restore_then_collector() -> None:
    """
    启动后先尝试恢复上次节点。
    成功：继续进入原 collector_loop 做后续维护。
    失败：仍然进入原 collector_loop，由旧逻辑拉取节点并自动切换。
    """
    global is_connecting

    try:
        restored = restore_last_connected_node(max_attempts=2)

        if not restored:
            with lock:
                is_connecting = False

            set_state(
                is_connecting=False,
                active_openvpn_node_id="",
                last_check_message="未恢复上次节点，交给维护线程按原逻辑选择节点",
                active_node_latency="等待维护线程",
            )

    except Exception as exc:
        print(f"[启动恢复] 恢复流程异常: {exc}", flush=True)
        log_to_json("ERROR", "VPN", f"启动恢复流程异常: {exc}")

        with lock:
            is_connecting = False

    collector_loop()

def collector_loop() -> None:
    while True:
        success = False
        try:
            res = maintain_valid_nodes(force=False)
            if "没有拉取到新节点" not in res:
                success = True
        except Exception as exc:
            set_state(last_check_at=time.time(), last_check_message=f"check error: {exc}")
            
        if not active_openvpn_running() and not success:
            sleep_time = 30
        else:
            sleep_time = CHECK_INTERVAL_SECONDS
            
        time.sleep(sleep_time)

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AimiliVPN - 安全登录</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #090d16;
      --bg-surface: rgba(15, 23, 42, 0.45);
      --border-color: rgba(255, 255, 255, 0.08);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --primary: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      --primary-hover: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%);
      --success: #10b981;
      --danger: #f43f5e;
    }

    body {
      margin: 0;
      padding: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%);
      height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
    }

    .login-container {
      width: 100%;
      max-width: 400px;
      padding: 24px;
      box-sizing: border-box;
    }

    .login-card {
      background: var(--bg-surface);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      padding: 40px 32px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
      text-align: center;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .brand-logo {
      width: 64px;
      height: 64px;
      background: rgba(99, 102, 241, 0.1);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px auto;
      color: var(--primary);
      position: relative;
    }

    .brand-logo::after {
      content: '';
      position: absolute;
      width: 100%;
      height: 100%;
      border-radius: 16px;
      border: 1px solid var(--success);
      opacity: 0.5;
      animation: ripple 2s infinite ease-out;
    }

    @keyframes ripple {
      0% { transform: scale(1); opacity: 0.5; }
      100% { transform: scale(1.3); opacity: 0; }
    }

    .login-title {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
      margin: 0 0 8px 0;
      letter-spacing: 0.5px;
    }

    .login-subtitle {
      font-size: 14px;
      color: var(--text-secondary);
      margin: 0 0 32px 0;
    }

    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }

    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }

    .input-wrapper {
      position: relative;
    }

    .input-field {
      width: 100%;
      height: 48px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 0 16px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 15px;
      outline: none;
      transition: all 0.2s ease;
    }

    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }

    .error-message {
      color: var(--danger);
      font-size: 13px;
      margin-top: 8px;
      min-height: 18px;
      text-align: left;
      margin-left: 4px;
      display: none;
    }

    .login-btn {
      width: 100%;
      height: 48px;
      background: var(--primary-gradient);
      border: none;
      border-radius: 10px;
      color: white;
      font-family: inherit;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.25);
    }

    .login-btn:hover {
      background: var(--primary-hover);
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .login-btn:active {
      transform: translateY(1px);
    }

    .login-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none !important;
    }

    .login-loader {
      display: none;
      align-items: center;
      gap: 4px;
      height: 14px;
    }

    .login-loader i {
      width: 6px;
      height: 6px;
      border-radius: 999px;
      background: currentColor;
      opacity: 0.65;
      animation: loginBounce 0.8s infinite ease-in-out;
    }

    .login-loader i:nth-child(2) {
      animation-delay: 0.12s;
    }

    .login-loader i:nth-child(3) {
      animation-delay: 0.24s;
    }

    @keyframes loginBounce {
      0%, 80%, 100% {
        transform: translateY(0);
        opacity: 0.45;
      }
      40% {
        transform: translateY(-6px);
        opacity: 1;
      }
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-card">
      <div class="brand-logo">
        <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      </div>
      <h2 class="login-title">AimiliVPN</h2>
      <p class="login-subtitle">请输入您的管理账号和安全密码以继续</p>
      
      <form id="login_form" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label class="form-label" for="username">管理账号</label>
          <div class="input-wrapper">
             <input type="text" id="username" name="username" class="input-field" placeholder="请输入管理账号" required autocomplete="username">
          </div>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label class="form-label" for="password">安全密码</label>
          <div class="input-wrapper">
            <input type="password" id="password" name="password" class="input-field" placeholder="请输入安全密码" required autocomplete="current-password">
          </div>
          <div id="error_text" class="error-message"></div>
        </div>
        
        <button type="submit" id="submit_btn" class="login-btn">
          <span id="login_loader" class="login-loader" aria-hidden="true">
            <i></i><i></i><i></i>
          </span>
          <span id="login_btn_text">登录</span>
        </button>
      </form>
    </div>
  </div>

  <script>
    function setLoginLoading(isLoading) {
      const submitBtn = document.getElementById("submit_btn");
      const btnText = document.getElementById("login_btn_text");
      const loader = document.getElementById("login_loader");

      submitBtn.disabled = isLoading;
      btnText.textContent = isLoading ? "正在验证..." : "登录";
      loader.style.display = isLoading ? "inline-flex" : "none";
    }

    function showLoginError(message) {
      const errorText = document.getElementById("error_text");
      errorText.textContent = message;
      errorText.style.display = "block";
    }

    async function handleLogin(e) {
      e.preventDefault();

      const uname = document.getElementById("username").value.trim();
      const pwd = document.getElementById("password").value.trim();
      const errorText = document.getElementById("error_text");

      errorText.style.display = "none";
      errorText.textContent = "";

      setLoginLoading(true);

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      let shouldRestoreButton = true;

      try {
        const response = await fetch("./api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: uname, password: pwd }),
          signal: controller.signal,
          cache: "no-store"
        });

        clearTimeout(timer);

        let data = {};
        try {
          data = await response.json();
        } catch (_) {
          data = {};
        }

        if (response.ok && data.ok) {
          shouldRestoreButton = false;
          window.location.reload();
          return;
        }

        showLoginError(data.error || "账号或密码不正确，请重新输入");
      } catch (err) {
        clearTimeout(timer);
        showLoginError("网络错误，请刷新页面后重试");
      } finally {
        if (shouldRestoreButton) {
          setLoginLoading(false);
        }
      }
    }
  </script>
</body>
</html>
"""


INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AimiliVPN 节点池管理系统</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    
    :root {
      --bg-dark: #0b0f19;
      --bg-surface: rgba(22, 30, 49, 0.6);
      --bg-surface-hover: rgba(30, 41, 67, 0.85);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-color-hover: rgba(99, 102, 241, 0.35);
      --text-primary: #f3f4f6;
      --text-secondary: #9ca3af;
      --primary: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      --primary-hover: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%);
      --success: #10b981;
      --success-gradient: linear-gradient(135deg, #34d399 0%, #059669 100%);
      --danger: #f43f5e;
      --danger-gradient: linear-gradient(135deg, #fb7185 0%, #e11d48 100%);
      --warning: #f59e0b;
      --warning-gradient: linear-gradient(135deg, #fbbf24 0%, #d97706 100%);
      --active-row-bg: rgba(16, 185, 129, 0.06);
      --active-row-border: rgba(16, 185, 129, 0.25);
    }

    body {
      margin: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%),
        radial-gradient(at 50% 100%, rgba(79, 70, 229, 0.05) 0px, transparent 50%);
      background-attachment: fixed;
      color: var(--text-primary);
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }

    header {
      padding: 16px 32px;
      background: rgba(11, 15, 25, 0.7);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .brand {
      display: flex;
      flex-direction: column;
    }

    h1 {
      font-size: 20px;
      font-weight: 700;
      margin: 0;
      background: linear-gradient(135deg, #a5b4fc 0%, #6366f1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -0.5px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status {
      font-size: 13px;
      color: var(--text-secondary);
      margin-top: 4px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status {
      font-size: 13px;
      color: var(--text-secondary);
      margin-top: 4px;
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      line-height: 1.45;
    }
    
    .proxy-auth-info {
      display: inline-flex;
      flex-direction: column;
      gap: 2px;
      margin-left: 8px;
      min-width: 230px;
      line-height: 1.35;
    }
    
    .proxy-auth-info span {
      white-space: nowrap;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    
    .copy-auth-btn {
      height: 20px;
      padding: 0 7px;
      border-radius: 5px;
      font-size: 11px;
      font-weight: 600;
      border: 1px solid rgba(99, 102, 241, 0.35);
      background: rgba(99, 102, 241, 0.14);
      color: #a5b4fc;
      cursor: pointer;
      box-shadow: none;
    }
    
    .copy-auth-btn:hover {
      background: rgba(99, 102, 241, 0.25);
      border-color: rgba(99, 102, 241, 0.55);
      transform: none;
    }
    
    .proxy-auth-user strong {
      color: #34d399;
    }
    
    .proxy-auth-pass strong {
      color: #fbbf24;
    }

    .btn-group {
      display: flex;
      gap: 12px;
      align-items: center;
      flex-wrap: nowrap;
      flex-shrink: 0;
    }

    button {
      height: 38px;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.04);
      color: var(--text-primary);
    }

    button:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: rgba(255, 255, 255, 0.15);
      transform: translateY(-1px);
    }

    .btn-primary {
      background: var(--primary-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.2);
    }

    .btn-primary:hover {
      background: var(--primary-hover);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .btn-danger {
      background: var(--danger-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(244, 63, 94, 0.2);
    }

    .btn-danger:hover {
      opacity: 0.95;
      box-shadow: 0 6px 16px rgba(244, 63, 94, 0.35);
    }

    button:disabled {
      opacity: 0.4;
      cursor: not-allowed;
      transform: none !important;
      box-shadow: none !important;
    }

    main {
      padding: 24px 32px;
      max-width: 1400px;
      margin: 0 auto;
    }

    .active-card {
      background: linear-gradient(135deg, rgba(99, 102, 241, 0.12) 0%, rgba(79, 70, 229, 0.04) 100%);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      padding: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 24px;
      box-shadow: 0 8px 32px rgba(99, 102, 241, 0.12);
      transition: all 0.3s ease;
      width: 100%;
      box-sizing: border-box;
    }
    
    .active-card-info {
      display: flex;
      align-items: center;
      gap: 20px;
      flex-wrap: wrap;
    }
    
    .active-card-details {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    
    .active-card-title {
      font-size: 14px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #a5b4fc;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .active-card-value {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
    }
    
    .active-card-meta {
      display: flex;
      gap: 20px;
      font-size: 13px;
      color: var(--text-secondary);
      flex-wrap: wrap;
    }

    .active-card-meta span strong {
      color: var(--text-primary);
    }

    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .stat {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 20px;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .stat:hover {
      background: var(--bg-surface-hover);
      border-color: var(--border-color-hover);
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(99, 102, 241, 0.1);
    }

    .stat-info {
      display: flex;
      flex-direction: column;
    }

    .stat strong {
      font-size: 32px;
      font-weight: 700;
      display: block;
      margin-bottom: 4px;
      background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .stat span {
      font-size: 13px;
      color: var(--text-secondary);
      font-weight: 500;
    }

    .stat-icon-wrapper {
      width: 44px;
      height: 44px;
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.04);
      display: flex;
      align-items: center;
      justify-content: center;
      border: 1px solid rgba(255, 255, 255, 0.06);
    }

    .stat-icon {
      width: 22px;
      height: 22px;
      color: var(--primary);
    }

    .stat:nth-child(2) .stat-icon { color: var(--warning); }
    .stat:nth-child(3) .stat-icon { color: var(--success); }

    .ad-section {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 20px;
      margin-bottom: 24px;
    }
    
    .ad-card {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    
    .ad-title {
      font-size: 15px;
      font-weight: 700;
      color: var(--text-primary);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .ad-badge {
      background: var(--primary-gradient);
      color: white;
      font-size: 11px;
      padding: 3px 8px;
      border-radius: 6px;
      font-weight: 700;
      text-transform: uppercase;
      box-shadow: 0 2px 6px rgba(99, 102, 241, 0.3);
    }
    
    .ad-links {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 16px;
    }
    
    .ad-item {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 10px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 12px;
      justify-content: space-between;
      transition: all 0.2s ease;
    }
    
    .ad-item:hover {
      background: rgba(255, 255, 255, 0.04);
      border-color: var(--border-color-hover);
      transform: translateY(-2px);
    }
    
    .ad-tag {
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 6px;
      width: fit-content;
    }
    
    .tag-normal {
      background: rgba(99, 102, 241, 0.15);
      color: #a5b4fc;
      border: 1px solid rgba(99, 102, 241, 0.2);
    }
    
    .tag-opt {
      background: rgba(245, 158, 11, 0.15);
      color: #fde047;
      border: 1px solid rgba(245, 158, 11, 0.2);
    }
    
    .tag-premium {
      background: rgba(16, 185, 129, 0.15);
      color: #6ee7b7;
      border: 1px solid rgba(16, 185, 129, 0.2);
    }
    
    .ad-desc {
      font-size: 13px;
      color: var(--text-secondary);
      line-height: 1.5;
      flex: 1;
    }
    
    .ad-btn {
      align-self: flex-start;
      text-decoration: none;
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.08);
      color: var(--text-primary);
      font-size: 12px;
      font-weight: 600;
      padding: 6px 14px;
      border-radius: 6px;
      transition: all 0.2s ease;
      text-align: center;
    }
    
    .ad-item:hover .ad-btn {
      background: var(--primary-gradient);
      border-color: transparent;
      color: white;
      box-shadow: 0 4px 10px rgba(99, 102, 241, 0.2);
    }
    
    .ad-footer {
      border-top: 1px dashed rgba(255, 255, 255, 0.08);
      padding-top: 12px;
      font-size: 13px;
      color: var(--text-secondary);
      text-align: center;
    }
    
    .forum-link {
      color: #818cf8;
      font-weight: 700;
      text-decoration: none;
      transition: color 0.2s ease;
    }
    
    .forum-link:hover {
      color: #a5b4fc;
      text-decoration: underline;
    }
    
    .switch-chart-section {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 20px;
      margin-bottom: 24px;
    }
    
    .switch-chart-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
      flex-wrap: wrap;
      margin-bottom: 14px;
    }
    
    .switch-chart-title {
      font-size: 15px;
      font-weight: 700;
      color: var(--text-primary);
      margin-bottom: 4px;
    }
    
    .switch-chart-subtitle {
      font-size: 12px;
      color: var(--text-secondary);
      line-height: 1.5;
    }
    
    .switch-chart-total {
      font-size: 13px;
      color: var(--text-secondary);
      background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255,255,255,0.06);
      border-radius: 10px;
      padding: 8px 12px;
      white-space: nowrap;
    }
    
    .switch-chart-total strong {
      color: var(--text-primary);
      font-size: 18px;
      margin: 0 3px;
    }
    
    .switch-chart-wrap {
      position: relative;
      width: 100%;
      height: 220px;
    }
    
    #auto_switch_chart {
      width: 100%;
      height: 220px;
      display: block;
    }
    .switch-chart-divider {
      height: 1px;
      background: rgba(148, 163, 184, 0.12);
      margin: 22px 0 18px;
    }
    
    .switch-chart-head-secondary {
      margin-top: 0;
    }
    
    .switch-duration-chart-wrap {
      height: 390px;
      margin-bottom: 24px;
    }
    
    #switch_duration_chart {
      width: 100%;
      height: 390px;
      display: block;
    }

    .toolbar {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 24px;
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      align-items: center;
    }

    .toolbar select {
      width: 180px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .toolbar select:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      background: #0f172a;
    }

    .toolbar input {
      flex: 1;
      min-width: 250px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      transition: all 0.2s ease;
    }

    .toolbar input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.8);
    }

    .table-wrapper {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
    }

    .table-container {
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      min-width: 1000px;
    }

    th, td {
      padding: 14px 20px;
      border-bottom: 1px solid var(--border-color);
      font-size: 14px;
    }

    th {
      background: rgba(17, 24, 39, 0.4);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-secondary);
    }

    tr {
      transition: background 0.2s ease;
    }

    tr:hover {
      background: rgba(255, 255, 255, 0.015);
    }

    .active-row {
      background: var(--active-row-bg) !important;
      outline: 2px solid var(--success) !important;
      outline-offset: -2px;
      position: relative;
      z-index: 5;
    }

    .active-row td {
      border-bottom: 1px solid var(--active-row-border);
      border-top: 1px solid var(--active-row-border);
    }

    .badge {
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid transparent;
    }

    .badge-pulse {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
      animation: pulse 1.5s infinite;
      display: inline-block;
    }

    @keyframes pulse {
      0% { transform: scale(0.9); opacity: 1; }
      50% { transform: scale(1.6); opacity: 0.4; }
      100% { transform: scale(0.9); opacity: 1; }
    }

    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }

    .available {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
      border-color: rgba(16, 185, 129, 0.2);
    }

    .unavailable {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
      border-color: rgba(244, 63, 94, 0.2);
    }

    .not_checked {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
      border-color: rgba(245, 158, 11, 0.2);
    }

    .current-badge {
      background: rgba(99, 102, 241, 0.15);
      color: #818cf8;
      border-color: rgba(99, 102, 241, 0.3);
    }

    .table-actions {
      display: flex;
      gap: 8px;
    }

    .connect-btn {
      background: transparent;
      color: #818cf8;
      border: 1px solid rgba(99, 102, 241, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .connect-btn:hover:not(:disabled) {
      background: var(--primary-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(99, 102, 241, 0.3);
    }

    .connect-btn:disabled {
      opacity: 0.3;
      cursor: not-allowed;
    }

    .test-btn {
      background: transparent;
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .test-btn:hover:not(:disabled) {
      background: var(--success-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(16, 185, 129, 0.3);
    }

    .test-btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    .mono {
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 13px;
      color: #e2e8f0;
    }

    .latency-val {
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
    }

    .latency-good {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
    }
    
    .latency-medium {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
    }
    
    .latency-poor {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
    }

    @media (max-width: 768px) {
      header {
        flex-direction: column;
        align-items: flex-start;
        padding: 16px 20px;
      }
      .btn-group {
        width: 100%;
        margin-top: 12px;
      }
        .btn-group {
        width: 100%;
        margin-top: 12px;
        flex-wrap: wrap;
      }
    
      .btn-group > button,
      .btn-group > .dropdown,
      .project-auto-update-box {
        flex: 1 1 calc(50% - 8px);
      }
    
      .btn-group > .dropdown > button {
        width: 100%;
      }
  
      main {
        padding: 16px 20px;
      }
      .active-card {
        flex-direction: column;
        align-items: flex-start;
        gap: 16px;
      }
      .active-card button {
        width: 100%;
      }
    }
    
    /* Admin dropdown styles */
    .dropdown {
      position: relative;
      display: inline-block;
    }
    .dropdown-content {
      display: none;
      position: absolute;
      right: 0;
      margin-top: 6px;
      min-width: 140px;
      background: rgba(22, 30, 49, 0.95);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      z-index: 1000;
      overflow: hidden;
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }
    .dropdown-content a {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 16px;
      color: var(--text-primary);
      text-decoration: none;
      font-size: 13px;
      font-weight: 500;
      transition: background 0.2s;
    }
    .dropdown-content a:hover {
      background: rgba(255,255,255,0.08);
    }
    
    /* Modal styles */
    .modal {
      display: none;
      position: fixed;
      z-index: 10000;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      overflow: auto;
      background-color: rgba(9, 13, 22, 0.7);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      align-items: center;
      justify-content: center;
    }
    .modal-content {
      background: rgba(22, 30, 49, 0.9);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      width: 90%;
      max-width: 480px;
      padding: 32px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
      position: relative;
      box-sizing: border-box;
      animation: modalFadeIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    @keyframes modalFadeIn {
      from { transform: scale(0.95); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
    }
    
    /* Inputs in settings */
    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }
    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }
    .input-field {
      width: 100%;
      height: 40px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
    }
    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }
    .project-auto-update-box {
      height: 46px;
      padding: 0 14px;
      border: 1px solid var(--border-color);
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.06);
      display: flex;
      align-items: center;
      gap: 10px;
      color: var(--text-primary);
      font-size: 14px;
      font-weight: 600;
      white-space: nowrap;
    }
    .project-auto-update-box {
      height: 44px;
      padding: 0 12px;
      border: 1px solid var(--border-color);
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.06);
      display: flex;
      align-items: center;
      gap: 10px;
      color: var(--text-primary);
      font-size: 13px;
      font-weight: 600;
      white-space: nowrap;
      line-height: 1;
      flex-shrink: 0;
    }
    
    .btn-group > button,
    .btn-group > .dropdown > button {
      height: 44px;
      padding: 0 14px;
      border-radius: 10px;
      font-size: 13px;
      line-height: 1;
      white-space: nowrap;
      flex-shrink: 0;
      box-sizing: border-box;
    }
    
    .btn-group > button svg,
    .btn-group > .dropdown > button svg {
      flex-shrink: 0;
    }
    
    #refresh {
      min-width: 112px;
    }
    
    #check {
      min-width: 138px;
    }
    
    #admin_btn {
      min-width: 108px;
    }
    
    #project_auto_update_toggle {
      flex-shrink: 0;
    }

    .toggle-switch {
      position: relative;
      display: inline-block;
      width: 46px;
      height: 24px;
      flex-shrink: 0;
    }
    
    .toggle-switch input {
      opacity: 0;
      width: 0;
      height: 0;
    }
    
    .toggle-slider {
      position: absolute;
      cursor: pointer;
      inset: 0;
      background: rgba(255,255,255,0.18);
      border-radius: 999px;
      transition: 0.25s;
    }
    
    .toggle-slider:before {
      content: "";
      position: absolute;
      width: 18px;
      height: 18px;
      left: 3px;
      top: 3px;
      background: #fff;
      border-radius: 50%;
      transition: 0.25s;
    }
    
    .toggle-switch input:checked + .toggle-slider {
      background: #22c55e;
    }
    
    .toggle-switch input:checked + .toggle-slider:before {
      transform: translateX(22px);
    }
    
    .ip-uptime-chart-wrap {
      height: 320px;
      margin-bottom: 28px;
    }
    
    #ip_uptime_chart {
      width: 100%;
      height: 320px;
      display: block;
    }
    
        .ip-uptime-tools {
      display: flex;
      align-items: center;
      gap: 14px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }
    
    .ip-uptime-legend {
      display: flex;
      align-items: center;
      gap: 18px;
      flex-wrap: wrap;
    }
    
    .legend-item {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 13px;
      color: var(--text-secondary);
      white-space: nowrap;
    }
    
    .legend-dot {
      width: 10px;
      height: 10px;
      border-radius: 3px;
      display: inline-block;
    }
    
    .legend-green { background: #26a269; }
    .legend-blue { background: #3b82f6; }
    .legend-orange { background: #f59e0b; }
    .legend-red { background: #ef4444; }
    
    .chart-refresh-btn {
      border: 1px solid rgba(255,255,255,0.14);
      background: rgba(255,255,255,0.04);
      color: var(--text-primary);
      border-radius: 10px;
      padding: 9px 16px;
      font-size: 13px;
      cursor: pointer;
      transition: all .2s ease;
    }
    
    .chart-refresh-btn:hover {
      background: rgba(255,255,255,0.08);
      border-color: rgba(255,255,255,0.22);
    }
    
    .chart-refresh-btn:disabled {
      opacity: .65;
      cursor: not-allowed;
    }
    
    .ip-uptime-chart-wrap {
      height: 390px;
      margin-bottom: 24px;
    }
    
    #ip_uptime_chart {
      width: 100%;
      height: 390px;
      display: block;
    }
    
  </style>
</head>
<body>
<header>
  <div class="brand">
    <h1>
      <svg xmlns="http://www.w3.org/2000/svg" style="width:24px; height:24px; color:#818cf8;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
      AimiliVPN 节点管理系统
    </h1>
    <div id="status" class="status"><span class="status-dot"></span>服务加载中...</div>
  </div>
  <div class="btn-group">
    <button id="refresh" class="btn-primary" style="background: var(--success-gradient);">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>
      更新节点
    </button>
    <button id="check" class="btn-primary">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>
      立即检测补齐
    </button>
    <div class="project-auto-update-box">
      <span>项目自动更新</span>
      <label class="toggle-switch">
        <input type="checkbox" id="project_auto_update_toggle" checked>
        <span class="toggle-slider"></span>
      </label>
    </div>

    <div class="dropdown">
      <button id="admin_btn" class="btn-primary" style="background: rgba(255, 255, 255, 0.08); border: 1px solid var(--border-color); color: var(--text-primary);">
        <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
        管理员
        <svg xmlns="http://www.w3.org/2000/svg" style="width:12px; height:12px; margin-left: 2px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" /></svg>
      </button>
      <div id="admin_dropdown" class="dropdown-content">
        <a href="javascript:void(0)" onclick="openSettingsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          设置
        </a>
        <a href="javascript:void(0)" onclick="openProxySettingsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 11c0-1.105.895-2 2-2h3a2 2 0 012 2v5a2 2 0 01-2 2h-3a2 2 0 01-2-2v-5z" />
            <path stroke-linecap="round" stroke-linejoin="round" d="M7 11V7a5 5 0 0110 0v2" />
            <path stroke-linecap="round" stroke-linejoin="round" d="M6 18H5a2 2 0 01-2-2v-5a2 2 0 012-2h3a2 2 0 012 2" />
          </svg>
          代理设置
        </a>
        <a href="javascript:void(0)" onclick="logoutAdmin()" style="color: var(--danger); border-top: 1px solid rgba(255,255,255,0.05);">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
          退出
        </a>
      </div>
    </div>
  </div>
</header>
<main>
    <section class="switch-chart-section">
      <div class="switch-chart-head">
        <div>
          <div class="switch-chart-title">每日自动更换节点次数</div>
          <div class="switch-chart-subtitle">
            统计范围：每日 00:00 ~ 24:00；仅统计自动切换，不统计手动切换；数据截止昨日，显示最近 15 日。
          </div>
        </div>
        <div class="switch-chart-total">
          15日合计：<strong id="auto_switch_total">0</strong> 次
        </div>
      </div>
    
      <div class="switch-chart-wrap">
        <canvas id="auto_switch_chart"></canvas>
      </div>
    
      <div class="switch-chart-divider"></div>
    
    <div class="switch-chart-head switch-chart-head-secondary">
      <div>
        <div class="switch-chart-title">最近 10 次节点切换耗时</div>
        <div class="switch-chart-subtitle">
          柱子底部为节点切换完成后的系统时间；柱子顶部为本次切换耗时；纵轴使用对数轴，避免秒级、分钟级、小时级、天级混合时显示失真。
        </div>
      </div>
    
      <div class="ip-uptime-tools">
        <div class="ip-uptime-legend">
          <span class="legend-item"><i class="legend-dot legend-green"></i>快速（≤1分钟）</span>
          <span class="legend-item"><i class="legend-dot legend-blue"></i>中等（≤5分钟）</span>
          <span class="legend-item"><i class="legend-dot legend-orange"></i>偏慢（≤10分钟）</span>
          <span class="legend-item"><i class="legend-dot legend-red"></i>异常（>10分钟）</span>
        </div>
    
        <button id="refresh_switch_duration_btn" type="button" class="chart-refresh-btn">
          刷新数据
        </button>
      </div>
    </div>
    
      <div class="switch-chart-wrap switch-duration-chart-wrap">
        <canvas id="switch_duration_chart"></canvas>
      </div>
    
      <div class="switch-chart-divider"></div>
    
      <div class="switch-chart-head switch-chart-head-secondary">
        <div>
          <div class="switch-chart-title">最近 10 个（不含当前连接 IP）IP 持续时长</div>
          <div class="switch-chart-subtitle">
            从 IP 质量与测速通过后开始计时，到节点不可用、切换、断开或出口 IP 变化时结束；
            当前正在连接的 IP 不显示，结束后再进入统计。
          </div>
        </div>
    
        <div class="ip-uptime-tools">
          <div class="ip-uptime-legend">
            <span class="legend-item"><i class="legend-dot legend-green"></i>较长（稳）</span>
            <span class="legend-item"><i class="legend-dot legend-blue"></i>中等</span>
            <span class="legend-item"><i class="legend-dot legend-orange"></i>偏短</span>
            <span class="legend-item"><i class="legend-dot legend-red"></i>较短（不稳）</span>
          </div>
    
          <button id="refresh_ip_uptime_btn" type="button" class="chart-refresh-btn">
            刷新数据
          </button>
    
        </div>
      </div>
    
      <div class="switch-chart-wrap ip-uptime-chart-wrap">
        <canvas id="ip_uptime_chart"></canvas>
      </div>
    </section>

  <!-- 当前连接活动节点卡片 -->
  <section class="active-node-section" id="active_node_card" style="margin-bottom: 24px;">
    <!-- Rendered dynamically by render() -->
  </section>

  <section class="stats">
    <div class="stat">
      <div class="stat-info">
        <strong id="total">0</strong>
        <span>可用节点池</span>
      </div>
      <div class="stat-icon-wrapper">
        <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
      </div>
    </div>
    <div class="stat">
      <div class="stat-info">
        <strong id="target">3</strong>
        <span>目标储备数</span>
      </div>
      <div class="stat-icon-wrapper">
        <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
      </div>
    </div>
    <div class="stat">
      <div class="stat-info">
        <strong id="active">0</strong>
        <span>已激活连接</span>
      </div>
      <div class="stat-icon-wrapper">
        <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
      </div>
    </div>
  </section>

  <section class="proxy-test-section" style="margin-bottom: 24px;">
    <div class="stat" style="display: flex; flex-direction: row; justify-content: space-between; align-items: center; width: 100%; box-sizing: border-box; flex-wrap: wrap; gap: 16px;">
      <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap;">
        <div class="stat-icon-wrapper" style="background: rgba(99, 102, 241, 0.1); border-color: rgba(99, 102, 241, 0.2);">
          <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color: var(--primary);"><path stroke-linecap="round" stroke-linejoin="round" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071a10.5 10.5 0 0114.14 0M1.414 8.05a16 16 0 0121.172 0" /></svg>
        </div>
        <div>
          <h3 style="margin: 0 0 4px 0; font-size: 16px; font-weight: 600; color: var(--text-primary);">本地代理出口检测 (Port 7928)</h3>
          <p style="margin: 0; font-size: 13px; color: var(--text-secondary);">
            测试本地 HTTP/SOCKS5 代理是否成功通过当前 VPN 节点出站，并获取实际出口公网 IP 和延迟。
          </p>
        </div>
      </div>
      <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap; margin-left: auto;">
        <div id="proxy_test_result" style="text-align: right;">
          <div style="font-size: 14px; font-weight: 500; color: var(--text-secondary);">
            测试状态: <span id="proxy_status_badge" class="badge not_checked" style="margin-left: 4px;">未检测</span>
          </div>
          <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">
            出口 IP: <span id="proxy_ip_val" class="mono" style="font-weight: 600; color: var(--text-primary);">-</span> 
            <span id="proxy_latency_val" style="margin-left: 8px;"></span>
          </div>
        </div>
        <button id="btn_test_proxy" class="btn-primary" style="height: 40px; padding: 0 16px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          测试代理
        </button>
      </div>
    </div>
  </section>

  <section class="toolbar">
    <select id="country_filter">
      <option value="">所有国家</option>
    </select>
    <input id="search" placeholder="输入国家、位置、IP、ASN、运营主体等过滤节点..." />
    <button id="btn_batch_test" class="btn-primary" style="height: 42px; padding: 0 20px; font-weight: 600; background: var(--primary-gradient);">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
      批量测试本页
    </button>
  </section>
  <div class="table-wrapper">
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th style="width: 110px;">状态</th>
            <th style="width: 100px;">延迟</th>
            <th style="width: 220px;">IP 地址 : 端口</th>
            <th>物理位置</th>
            <th style="width: 100px;">ASN</th>
            <th>运营主体 / ISP</th>
            <th style="width: 110px;">网络质量</th>
            <th style="width: 110px;">IP 类型</th>
            <th style="width: 160px;">操作</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    
    <!-- 分页控制栏 -->
    <div class="pagination-container" style="padding: 16px; display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-color); flex-wrap: wrap; gap: 12px;">
      <div style="font-size: 13px; color: var(--text-secondary);">
        显示第 <span id="page_start" style="color: var(--text-primary); font-weight:600;">0</span> - <span id="page_end" style="color: var(--text-primary); font-weight:600;">0</span> 条，共 <span id="filtered_count" style="color: var(--text-primary); font-weight:600;">0</span> 条备选节点
      </div>
      <div style="display: flex; gap: 8px; align-items: center;">
        <button id="btn_first_page" class="connect-btn" style="height: 32px; padding: 0 10px;">首页</button>
        <button id="btn_prev_page" class="connect-btn" style="height: 32px; padding: 0 10px;">上一页</button>
        <span style="font-size: 13px; color: var(--text-secondary); margin: 0 8px;">
          页码 <strong id="current_page_val" style="color: var(--primary);">1</strong> / <strong id="total_pages_val">1</strong>
        </span>
        <button id="btn_next_page" class="connect-btn" style="height: 32px; padding: 0 10px;">下一页</button>
        <button id="btn_last_page" class="connect-btn" style="height: 32px; padding: 0 10px;">尾页</button>
      </div>
    </div>
  </div>

  <!-- Settings Modal -->
  <div id="settings_modal" class="modal">
    <div class="modal-content">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          管理员设置
        </h3>
        <button type="button" onclick="closeSettingsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div id="settings_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="settings_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="settings_form" onsubmit="saveSettings(event)">
        <div style="border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 16px; margin-bottom: 16px;">
          <div style="font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary); font-weight: 600; margin-bottom: 12px;">修改网页访问配置</div>
          
          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_port">网页端口</label>
            <input type="number" id="settings_port" class="input-field" required min="1" max="65535" placeholder="8787">
          </div>
          
          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_suffix">登录安全后缀 (仅字母数字)</label>
            <input type="text" id="settings_suffix" class="input-field" required pattern="[A-Za-z0-9]+" placeholder="EJsW2EeBo9lY">
          </div>

          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_new_username">新管理账号 (留空则不修改)</label>
            <input type="text" id="settings_new_username" class="input-field" placeholder="留空则不修改">
          </div>
          
          <div class="form-group">
            <label class="form-label" for="settings_new_password">新安全密码 (留空则不修改)</label>
            <input type="password" id="settings_new_password" class="input-field" placeholder="留空则不修改">
          </div>
        </div>
        
        <div style="margin-bottom: 24px;">
          <div style="font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary); font-weight: 600; margin-bottom: 12px;">安全验证 (必须输入当前账号密码)</div>
          
          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_curr_username">当前管理账号</label>
            <input type="text" id="settings_curr_username" class="input-field" required placeholder="请输入当前管理账号">
          </div>
          
          <div class="form-group">
            <label class="form-label" for="settings_curr_password">当前安全密码</label>
            <input type="password" id="settings_curr_password" class="input-field" required placeholder="请输入当前安全密码">
          </div>
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeSettingsModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="settings_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>
  <!-- Proxy Settings Modal -->
<div id="proxy_settings_modal" class="modal">
  <div class="modal-content">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
      <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
        <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 11c0-1.105.895-2 2-2h3a2 2 0 012 2v5a2 2 0 01-2 2h-3a2 2 0 01-2-2v-5z" />
          <path stroke-linecap="round" stroke-linejoin="round" d="M7 11V7a5 5 0 0110 0v2" />
          <path stroke-linecap="round" stroke-linejoin="round" d="M6 18H5a2 2 0 01-2-2v-5a2 2 0 012-2h3a2 2 0 012 2" />
        </svg>
        代理设置
      </h3>

      <button type="button" onclick="closeProxySettingsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
        <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
          <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>
    </div>

    <div style="border-top: 1px solid rgba(255,255,255,0.05); padding-top: 16px; margin-top: 4px;">
      <div style="font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary); font-weight: 600; margin-bottom: 12px;">
        落地代理认证配置
      </div>

      <div class="form-group">
        <label class="form-label" for="settings_proxy_username">代理用户名</label>
        <input type="text" id="settings_proxy_username" class="input-field" autocomplete="off">
      </div>

      <div class="form-group">
        <label class="form-label" for="settings_proxy_password">代理密码</label>
        <input type="text" id="settings_proxy_password" class="input-field" autocomplete="off">
      </div>
      
      <div style="display:flex; gap:10px; margin-top: 4px; align-items:center;">
      <button type="button"
        id="settings_proxy_random_btn"
        onclick="generateProxyCredentials()"
        style="flex:1; height:40px; min-width:0; border-radius:8px; border:1px solid rgba(99,102,241,0.35); background:rgba(99,102,241,0.12); color:#a5b4fc; font-size:13px; font-weight:600; cursor:pointer; white-space:nowrap;">
        随机生成
      </button>
    
      <button type="button"
        id="settings_proxy_save_btn"
        class="btn-primary"
        onclick="saveProxyAuthSettings()"
        style="flex:2; height:40px; margin-top:0; font-size:13px; white-space:nowrap;">
        保存配置
      </button>
      </div>

      <div id="settings_proxy_msg" style="font-size:13px; margin-top:12px; display:none;"></div>
    </div>
  </div>
</div>
</main>
<script>
let nodes=[], state={}, testingNodeIds = new Set();

let proxyAuthVisible = false;

function maskProxySecret(value){
  const s = String(value || "");

  if (!s) return "未配置";
  if (s === "未配置") return s;

  // 太短的全部脱敏
  if (s.length <= 6) {
    return "•".repeat(s.length);
  }

  // 保留前 4 位和后 4 位，中间脱敏
  return `${s.slice(0, 4)}••••${s.slice(-4)}`;
}

function getProxyAuthDisplay(value){
  const s = String(value || "未配置");
  return proxyAuthVisible ? s : maskProxySecret(s);
}

function toggleProxyAuthVisible(){
  proxyAuthVisible = !proxyAuthVisible;
  render();
}



let currentPage = 1;
const pageSize = 11;
let currentPageNodes = [];

const $=id=>document.getElementById(id);
const esc=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));

async function copyTextToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return true;
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  textarea.style.top = "-9999px";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();

  try {
    document.execCommand("copy");
    return true;
  } finally {
    document.body.removeChild(textarea);
  }
}

async function copyProxyField(field, btn) {
  const value = field === "username"
    ? state.proxy_username
    : state.proxy_password;

  if (!value) {
    return;
  }

  const oldText = btn.textContent;

  try {
    await copyTextToClipboard(value);
    btn.textContent = "已复制";
    btn.style.color = "#6ee7b7";
  } catch (err) {
    btn.textContent = "失败";
    btn.style.color = "#fb7185";
  }

  setTimeout(() => {
    btn.textContent = oldText;
    btn.style.color = "#a5b4fc";
  }, 1200);
}


const base=p=>(p||"").split(/[\\/]/).pop();
function time(ts){return ts?new Date(ts*1000).toLocaleString():"从未"}
function speed(v){return v?`${(v*8/1000/1000).toFixed(1)} Mbps`:"-"}

const translateQuality = q => {
  const dict = {"normal": "普通", "proxy": "代理", "datacenter": "数据中心", "mobile": "移动端"};
  return dict[q] || q || "-";
};

const translateIpType = t => {
  const dict = {"residential": "住宅 IP", "hosting": "机房 IP", "mobile": "移动网", "proxy": "代理 IP"};
  return dict[t] || t || "-";
};

const translateCountry = c => {
  const dict = {
    "Japan": "日本",
    "Korea Republic of": "韩国",
    "Korea": "韩国",
    "Republic of Korea": "韩国",
    "Thailand": "泰国",
    "United States": "美国",
    "United Kingdom": "英国",
    "Russian Federation": "俄罗斯",
    "Russian": "俄罗斯",
    "Viet Nam": "越南",
    "Vietnam": "越南",
    "China": "中国",
    "Taiwan": "台湾",
    "Taiwan Province of China": "台湾",
    "Hong Kong": "香港",
    "Singapore": "新加坡",
    "Malaysia": "马来西亚",
    "Indonesia": "印度尼西亚",
    "India": "印度",
    "Philippines": "菲律宾",
    "Australia": "澳大利亚",
    "New Zealand": "新西兰",
    "Canada": "加拿大",
    "Ukraine": "乌克兰",
    "France": "法国",
    "Germany": "德国",
    "Netherlands": "荷兰",
    "Sweden": "瑞典",
    "Norway": "挪威",
    "Spain": "西班牙",
    "Turkey": "土耳其",
    "South Africa": "南非",
    "Brazil": "巴西",
    "Argentina": "阿根廷",
    "Chile": "智利",
    "Mexico": "墨西哥",
    "Egypt": "埃及",
    "Romania": "罗马尼亚",
    "Poland": "波兰",
    "Kazakhstan": "哈萨克斯坦",
    "Georgia": "格鲁吉亚",
    "Mongolia": "蒙古",
    "Saudi Arabia": "沙特阿拉伯",
    "Iran": "伊朗",
    "Iraq": "伊拉克",
    "Colombia": "哥伦比亚",
    "Cambodia": "柬埔寨",
    "Ireland": "爱尔兰",
    "Italy": "意大利",
    "Switzerland": "瑞士",
    "Belgium": "比利时",
    "Austria": "奥地利",
    "Denmark": "丹麦",
    "Finland": "芬兰",
    "Portugal": "葡萄牙",
    "Greece": "希腊",
    "Czech Republic": "捷克",
    "Hungary": "匈牙利",
    "Israel": "以色列",
    "United Arab Emirates": "阿联酋",
    "UAE": "阿联酋",
    "Macao": "澳门",
    "Macau": "澳门",
    "Iceland": "冰岛",
    "Luxembourg": "卢森堡"
  };
  return dict[c] || c || "-";
};

const translateStatus = s => {
  const dict = {"available": "可用", "unavailable": "不可用", "not_checked": "待检测"};
  return dict[s] || s || "待检测";
};

function getLatencyClass(ms) {
  if (!ms) return '';
  if (ms < 50) return 'latency-good';
  if (ms < 150) return 'latency-medium';
  return 'latency-poor';
}

function updateCountryFilter() {
  const select = $("country_filter");
  const selectedValue = select.value;
  const countries = Array.from(new Set(nodes.map(n => n.country).filter(Boolean))).sort();
  
  const currentOptions = Array.from(select.options).map(o => o.value).filter(Boolean);
  if (JSON.stringify(countries) === JSON.stringify(currentOptions)) {
    return;
  }
  
  select.innerHTML = '<option value="">所有国家</option>' + 
    countries.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  
  if (countries.includes(selectedValue)) {
    select.value = selectedValue;
  } else {
    select.value = "";
  }
}

function getFilteredNodes() {
  const q = $("search").value.toLowerCase();
  const selectedCountry = $("country_filter").value;
  return nodes.filter(n => {
    if (selectedCountry && n.country !== selectedCountry) {
      return false;
    }
    const searchStr = [
      n.country, n.country_short, n.ip, n.remote_host, n.proto,
      translateQuality(n.quality), translateIpType(n.ip_type), n.location, n.owner, n.as_name
    ].join(" ").toLowerCase();
    return searchStr.includes(q);
  });
}

function drawAutoSwitchChart(){
  const canvas = $("auto_switch_chart");
  if (!canvas) return;

  const data = Array.isArray(state.auto_switch_chart) ? state.auto_switch_chart : [];
  const total = data.reduce((sum, item) => sum + (Number(item.count) || 0), 0);

  const totalEl = $("auto_switch_total");
  if (totalEl) totalEl.textContent = total;

  const wrapper = canvas.parentElement;
  const rect = wrapper ? wrapper.getBoundingClientRect() : { width: 900, height: 220 };
  const width = Math.max(640, Math.floor(rect.width || 900));
  const height = Math.max(220, Math.floor(rect.height || 220));
  const dpr = window.devicePixelRatio || 1;

  canvas.width = Math.floor(width * dpr);
  canvas.height = Math.floor(height * dpr);
  canvas.style.width = "100%";
  canvas.style.height = height + "px";

  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);

  const pad = { left: 42, right: 18, top: 16, bottom: 34 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const baseY = pad.top + plotH;

  const counts = data.map(item => Number(item.count) || 0);
  const maxCount = Math.max(0, ...counts);
  const maxY = Math.max(5, Math.ceil((maxCount * 1.15 || 5) / 5) * 5);

  ctx.font = "12px Outfit, sans-serif";
  ctx.textBaseline = "middle";

  for (let i = 0; i <= 4; i++) {
    const value = Math.round(maxY - (maxY / 4) * i);
    const y = pad.top + (plotH / 4) * i;

    ctx.strokeStyle = "rgba(148, 163, 184, 0.16)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(width - pad.right, y);
    ctx.stroke();

    ctx.fillStyle = "rgba(226, 232, 240, 0.75)";
    ctx.textAlign = "right";
    ctx.fillText(String(value), pad.left - 10, y);
  }

  const points = data.map((item, index) => {
    const x = data.length === 1
      ? pad.left + plotW / 2
      : pad.left + (plotW / (data.length - 1)) * index;

    const y = baseY - ((Number(item.count) || 0) / maxY) * plotH;

    return {
      x,
      y,
      count: Number(item.count) || 0,
      label: item.label || item.date || ""
    };
  });

  if (!points.length) {
    ctx.fillStyle = "rgba(148, 163, 184, 0.85)";
    ctx.textAlign = "center";
    ctx.fillText("暂无自动切换统计数据", width / 2, height / 2);
    return;
  }

  const gradient = ctx.createLinearGradient(0, pad.top, 0, baseY);
  gradient.addColorStop(0, "rgba(99, 102, 241, 0.88)");
  gradient.addColorStop(1, "rgba(99, 102, 241, 0.28)");

  ctx.beginPath();
  ctx.moveTo(points[0].x, baseY);
  points.forEach(p => ctx.lineTo(p.x, p.y));
  ctx.lineTo(points[points.length - 1].x, baseY);
  ctx.closePath();
  ctx.fillStyle = gradient;
  ctx.fill();

  ctx.beginPath();
  points.forEach((p, i) => {
    if (i === 0) ctx.moveTo(p.x, p.y);
    else ctx.lineTo(p.x, p.y);
  });
  ctx.strokeStyle = "rgba(129, 140, 248, 1)";
  ctx.lineWidth = 3;
  ctx.stroke();

  points.forEach(p => {
    ctx.beginPath();
    ctx.arc(p.x, p.y, 5, 0, Math.PI * 2);
    ctx.fillStyle = "rgba(99, 102, 241, 1)";
    ctx.fill();

    ctx.lineWidth = 3;
    ctx.strokeStyle = "rgba(248, 250, 252, 0.95)";
    ctx.stroke();

    ctx.fillStyle = "rgba(226, 232, 240, 0.88)";
    ctx.textAlign = "center";
    ctx.fillText(String(p.count), p.x, Math.max(10, p.y - 16));

    ctx.fillStyle = "rgba(226, 232, 240, 0.70)";
    ctx.fillText(p.label, p.x, height - 14);
  });
}


function getSwitchDurationSeconds(item){
  const seconds = Number(item && item.seconds);

  if (Number.isFinite(seconds) && seconds > 0) {
    return seconds;
  }

  const minutes = Number(item && item.minutes);
  if (Number.isFinite(minutes) && minutes > 0) {
    return minutes * 60;
  }

  return 0;
}

function formatSwitchDurationTopLabel(seconds){
  let total = Math.max(0, Math.floor(Number(seconds) || 0));

  const days = Math.floor(total / 86400);
  total %= 86400;

  const hours = Math.floor(total / 3600);
  total %= 3600;

  const minutes = Math.floor(total / 60);
  const secs = total % 60;

  if (days > 0) {
    return minutes > 0
      ? `${days}天${hours}小时${minutes}分`
      : `${days}天${hours}小时`;
  }

  if (hours > 0) {
    return minutes > 0
      ? `${hours}小时${minutes}分`
      : `${hours}小时`;
  }

  if (minutes > 0) {
    return secs > 0
      ? `${minutes}分${secs}秒`
      : `${minutes}分钟`;
  }

  return `${Math.max(1, secs)}秒`;
}

function formatSwitchDurationAxisLabel(seconds){
  const s = Math.max(1, Number(seconds) || 1);

  if (s < 60) {
    return `${Math.round(s)}秒`;
  }

  if (s < 3600) {
    return `${Math.round(s / 60)}分钟`;
  }

  if (s < 86400) {
    const h = s / 3600;
    return `${Number.isInteger(h) ? h : h.toFixed(1).replace(/\.0$/, "")}小时`;
  }

  const d = s / 86400;
  return `${Number.isInteger(d) ? d : d.toFixed(1).replace(/\.0$/, "")}天`;
}

function getSwitchDurationLevel(seconds){
  const s = Math.max(0, Number(seconds) || 0);

  // 绿色：≤ 1 分钟
  if (s <= 60) {
    return {
      colorTop: "rgba(38, 162, 105, 0.96)",
      colorBottom: "rgba(38, 162, 105, 0.48)",
      textColor: "rgba(52, 211, 153, 0.98)"
    };
  }

  // 蓝色：> 1 分钟 且 ≤ 5 分钟
  if (s <= 5 * 60) {
    return {
      colorTop: "rgba(59, 130, 246, 0.96)",
      colorBottom: "rgba(59, 130, 246, 0.48)",
      textColor: "rgba(96, 165, 250, 0.98)"
    };
  }

  // 橙色：> 5 分钟 且 ≤ 10 分钟
  if (s <= 10 * 60) {
    return {
      colorTop: "rgba(245, 158, 11, 0.96)",
      colorBottom: "rgba(245, 158, 11, 0.48)",
      textColor: "rgba(251, 191, 36, 0.98)"
    };
  }

  // 红色：> 10 分钟
  // 30 分钟以上自然也属于红色
  return {
    colorTop: "rgba(239, 68, 68, 0.96)",
    colorBottom: "rgba(239, 68, 68, 0.48)",
    textColor: "rgba(248, 113, 113, 0.98)"
  };
}

/**
 * 切换耗时图表专用视觉缩放。
 *
 * 关键点：
 * - 使用真实 seconds，不使用四舍五入后的 minutes / hours
 * - 使用对数缩放，避免 10秒、10分钟、10小时、10天混在一起时小值看不见
 * - 全是秒级 / 分钟级时，也能体现柱高差异
 */
function buildSwitchDurationVisualScale(secondsList){
  const values = secondsList
    .map(v => Math.max(0, Number(v) || 0))
    .filter(v => v > 0);

  if (!values.length) {
    return {
      minAxis: 1,
      maxAxis: 60,
      minVisual: Math.log10(1),
      maxVisual: Math.log10(60),
      toVisualRatio: () => 0,
      visualToSeconds: () => 1,
    };
  }

  const minData = Math.min(...values);
  const maxData = Math.max(...values);

  let minAxis = Math.max(1, minData * 0.7);
  let maxAxis = Math.max(10, maxData * 1.25);

  // 如果数据跨度很小，给一点额外空间，避免柱子全挤在顶部
  if (maxAxis / minAxis < 2) {
    minAxis = Math.max(1, minData * 0.5);
    maxAxis = Math.max(maxData * 1.8, minAxis * 2);
  }

  const minVisual = Math.log10(minAxis);
  const maxVisual = Math.log10(maxAxis);

  const toVisualRatio = (seconds) => {
    const s = Math.max(minAxis, Number(seconds) || minAxis);
    const v = Math.log10(s);
    return Math.max(0, Math.min(1, (v - minVisual) / Math.max(0.0001, maxVisual - minVisual)));
  };

  const visualToSeconds = (ratio) => {
    const r = Math.max(0, Math.min(1, Number(ratio) || 0));
    const v = minVisual + (maxVisual - minVisual) * r;
    return Math.pow(10, v);
  };

  return {
    minAxis,
    maxAxis,
    minVisual,
    maxVisual,
    toVisualRatio,
    visualToSeconds,
  };
}

async function refreshSwitchDurationChartData(){
  const btn = $("refresh_switch_duration_btn");

  try {
    if (btn) {
      btn.disabled = true;
      btn.textContent = "刷新中...";
    }

    const r = await fetch("./api/nodes");
    const d = await r.json();

    nodes = d.nodes || [];
    state = d.state || {};

    stableSortNodes();
    render();
  } catch (e) {
    console.error("刷新节点切换耗时图失败:", e);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "刷新数据";
    }
  }
}

function drawSwitchDurationChart(){
  const canvas = $("switch_duration_chart");
  if (!canvas) return;

  const data = Array.isArray(state.switch_duration_chart) ? state.switch_duration_chart : [];

  const countEl = $("switch_duration_count");
  if (countEl) countEl.textContent = data.length;

  const wrapper = canvas.parentElement;
  const rect = wrapper ? wrapper.getBoundingClientRect() : { width: 900, height: 390 };
  const width = Math.max(760, Math.floor(rect.width || 900));
  const height = Math.max(390, Math.floor(rect.height || 390));
  const dpr = window.devicePixelRatio || 1;

  canvas.width = Math.floor(width * dpr);
  canvas.height = Math.floor(height * dpr);
  canvas.style.width = "100%";
  canvas.style.height = height + "px";

  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);

  const pad = { left: 82, right: 28, top: 34, bottom: 135 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const baseY = pad.top + plotH;

  if (!data.length) {
    ctx.font = "13px Outfit, sans-serif";
    ctx.fillStyle = "rgba(148, 163, 184, 0.85)";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("暂无切换耗时统计数据", width / 2, height / 2);
    return;
  }

  // 关键：柱高使用真实 seconds，不使用 minutes 的四舍五入值
  const secondValues = data.map(item => getSwitchDurationSeconds(item));
  const scale = buildSwitchDurationVisualScale(secondValues);

  ctx.font = "12px Outfit, sans-serif";
  ctx.textBaseline = "middle";

  // 横向网格线 + 对数轴刻度
  const gridSteps = 4;
  for (let i = 0; i <= gridSteps; i++) {
    const ratio = 1 - (i / gridSteps);
    const axisSeconds = scale.visualToSeconds(ratio);
    const y = pad.top + (plotH / gridSteps) * i;

    ctx.strokeStyle = "rgba(148, 163, 184, 0.16)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(width - pad.right, y);
    ctx.stroke();

    ctx.fillStyle = "rgba(226, 232, 240, 0.72)";
    ctx.textAlign = "right";
    ctx.fillText(formatSwitchDurationAxisLabel(axisSeconds), pad.left - 12, y);
  }

  // 纵轴说明
  ctx.save();
  ctx.translate(24, pad.top + plotH / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.fillStyle = "rgba(148, 163, 184, 0.85)";
  ctx.textAlign = "center";
  ctx.fillText("耗时（对数轴）", 0, 0);
  ctx.restore();

  const slotW = plotW / data.length;
  const barW = Math.max(18, Math.min(54, slotW * 0.50));

  data.forEach((item, index) => {
    const seconds = getSwitchDurationSeconds(item);

    // 关键：柱高根据真实 seconds 的对数比例计算
    const ratio = scale.toVisualRatio(seconds);
    const barH = Math.max(4, ratio * plotH);
    const x = pad.left + index * slotW + (slotW - barW) / 2;
    const y = baseY - barH;

    // 关键：颜色根据真实 seconds 阈值判断
    const level = getSwitchDurationLevel(seconds);

    const gradient = ctx.createLinearGradient(0, y, 0, baseY);
    gradient.addColorStop(0, level.colorTop);
    gradient.addColorStop(1, level.colorBottom);

    ctx.fillStyle = gradient;

    const radius = 7;
    ctx.beginPath();
    ctx.moveTo(x + radius, y);
    ctx.lineTo(x + barW - radius, y);
    ctx.quadraticCurveTo(x + barW, y, x + barW, y + radius);
    ctx.lineTo(x + barW, baseY);
    ctx.lineTo(x, baseY);
    ctx.lineTo(x, y + radius);
    ctx.quadraticCurveTo(x, y, x + radius, y);
    ctx.closePath();
    ctx.fill();

    // 柱顶：切换耗时
    ctx.font = "12px Outfit, sans-serif";
    ctx.fillStyle = level.textColor;
    ctx.textAlign = "center";
    ctx.fillText(
      formatSwitchDurationTopLabel(seconds),
      x + barW / 2,
      Math.max(12, y - 14)
    );

    // 柱底：切换完成后的系统时间
    ctx.save();
    ctx.translate(x + barW / 2 + 30, height - 56);
    ctx.rotate(-Math.PI / 5);
    ctx.fillStyle = "rgba(226, 232, 240, 0.70)";
    ctx.textAlign = "right";
    ctx.fillText(String(item.label || item.finished_label || index + 1), 0, 0);
    ctx.restore();
  });

  // 底部基线
  ctx.strokeStyle = "rgba(148, 163, 184, 0.24)";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(pad.left, baseY);
  ctx.lineTo(width - pad.right, baseY);
  ctx.stroke();
}



function formatChartHour(value){
  const n = Number(value) || 0;

  if (n >= 100) {
    return `${Math.round(n)}h`;
  }

  if (n >= 10) {
    return `${Math.round(n * 10) / 10}h`;
  }

  if (n >= 1) {
    return `${n.toFixed(1).replace(/\.0$/, "")}h`;
  }

  return `${n.toFixed(2).replace(/0+$/, "").replace(/\.$/, "")}h`;
}

function formatAxisSecondsAsHours(seconds){
  const h = Math.max(0, Number(seconds) || 0) / 3600;
  return formatChartHour(h);
}

function getIpUptimeSeconds(item){
  const seconds = Number(item && item.seconds);

  if (Number.isFinite(seconds) && seconds > 0) {
    return seconds;
  }

  const hours = Number(item && item.hours);
  if (Number.isFinite(hours) && hours > 0) {
    return hours * 3600;
  }

  return 0;
}

/**
 * 自适应视觉缩放：
 * - 数据跨度不大：线性缩放
 * - 数据跨度很大：对数缩放
 *
 * 目的：
 * - 全是分钟级时，2分钟、8分钟、26分钟能看出差异
 * - 分钟/小时/天数混合时，分钟级不会被天数级完全压扁
 * - 全是天数时，也能保持差异
 */
function buildIpUptimeVisualScale(secondsList){
  const values = secondsList
    .map(v => Math.max(0, Number(v) || 0))
    .filter(v => v > 0);

  const maxSeconds = values.length ? Math.max(...values) : 1;
  const minSeconds = values.length ? Math.min(...values) : 1;

  const ratio = maxSeconds / Math.max(1, minSeconds);

  // 跨度超过 10 倍时，用对数压缩，避免小值全部贴地
  const useLogScale = ratio >= 10;

  const toVisual = (seconds) => {
    const s = Math.max(0, Number(seconds) || 0);

    if (useLogScale) {
      // 以分钟为单位做 log，分钟级差异会更明显
      return Math.log1p(s / 60);
    }

    return s;
  };

  const fromVisual = (visual) => {
    const v = Math.max(0, Number(visual) || 0);

    if (useLogScale) {
      return Math.expm1(v) * 60;
    }

    return v;
  };

  const maxVisual = Math.max(1, toVisual(maxSeconds) * 1.15);

  return {
    useLogScale,
    maxSeconds,
    minSeconds,
    maxVisual,
    toVisual,
    fromVisual,
  };
}

/**
 * IP 持续时长颜色按当前这批数据的相对排名分级。
 *
 * 最短 -> 红色，不稳定
 * 偏短 -> 橙色
 * 中等 -> 蓝色
 * 最长 -> 绿色，稳定
 */
 
function getIpUptimeLevelByRank(seconds, sortedSeconds){
  const current = Math.max(0, Number(seconds) || 0);
  const list = Array.isArray(sortedSeconds)
    ? sortedSeconds.map(v => Math.max(0, Number(v) || 0)).sort((a, b) => a - b)
    : [];

  if (!list.length) {
    return {
      colorTop: "rgba(59, 130, 246, 0.96)",
      colorBottom: "rgba(59, 130, 246, 0.48)",
      textColor: "rgba(96, 165, 250, 0.98)"
    };
  }

  const min = list[0];
  const max = list[list.length - 1];

  // 所有数据完全一样时，没有长短差异，统一显示中等蓝色
  if (max <= min) {
    return {
      colorTop: "rgba(59, 130, 246, 0.96)",
      colorBottom: "rgba(59, 130, 246, 0.48)",
      textColor: "rgba(96, 165, 250, 0.98)"
    };
  }

  let lessCount = 0;
  let equalCount = 0;

  for (const v of list) {
    if (v < current) lessCount++;
    if (v === current) equalCount++;
  }

  // 相对位置：0 = 最短，1 = 最长
  const rankRatio = (
    lessCount + Math.max(0, equalCount - 1) / 2
  ) / Math.max(1, list.length - 1);

  // 最短 / 较短 -> 红色，不稳定
  if (rankRatio <= 0.25) {
    return {
      colorTop: "rgba(239, 68, 68, 0.96)",
      colorBottom: "rgba(239, 68, 68, 0.48)",
      textColor: "rgba(248, 113, 113, 0.98)"
    };
  }

  // 偏短 -> 橙色
  if (rankRatio <= 0.50) {
    return {
      colorTop: "rgba(245, 158, 11, 0.96)",
      colorBottom: "rgba(245, 158, 11, 0.48)",
      textColor: "rgba(251, 191, 36, 0.98)"
    };
  }

  // 中等 -> 蓝色
  if (rankRatio <= 0.75) {
    return {
      colorTop: "rgba(59, 130, 246, 0.96)",
      colorBottom: "rgba(59, 130, 246, 0.48)",
      textColor: "rgba(96, 165, 250, 0.98)"
    };
  }

  // 最长 / 较长 -> 绿色，稳定
  return {
    colorTop: "rgba(38, 162, 105, 0.96)",
    colorBottom: "rgba(38, 162, 105, 0.48)",
    textColor: "rgba(52, 211, 153, 0.98)"
  };
}

function formatIpUptimeTopLabel(seconds){
  let total = Number(seconds) || 0;
  total = Math.max(0, Math.floor(total));

  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  let minutes = Math.round((total % 3600) / 60);

  // 处理四舍五入后 minutes = 60 的情况
  let finalDays = days;
  let finalHours = hours;
  let finalMinutes = minutes;

  if (finalMinutes >= 60) {
    finalMinutes = 0;
    finalHours += 1;
  }

  if (finalHours >= 24) {
    finalDays += Math.floor(finalHours / 24);
    finalHours = finalHours % 24;
  }

  // 不足 1 小时：显示分钟
  if (finalDays === 0 && finalHours === 0) {
    return `${Math.max(1, finalMinutes)}分钟`;
  }

  // 不足 1 天：显示 xx小时xx分
  if (finalDays === 0) {
    return finalMinutes > 0
      ? `${finalHours}小时${finalMinutes}分`
      : `${finalHours}小时`;
  }

  // 超过 1 天：显示 x天x小时x分
  return finalMinutes > 0
    ? `${finalDays}天${finalHours}小时${finalMinutes}分`
    : `${finalDays}天${finalHours}小时`;
}




async function refreshIpUptimeChartData(){
  const btn = $("refresh_ip_uptime_btn");

  try {
    if (btn) {
      btn.disabled = true;
      btn.textContent = "刷新中...";
    }

    const r = await fetch("./api/nodes");
    const d = await r.json();

    nodes = d.nodes || [];
    state = d.state || {};

    stableSortNodes();
    render();
  } catch (e) {
    console.error("刷新 IP 连接时长图失败:", e);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "刷新数据";
    }
  }
}

function drawIpUptimeChart(){
  const canvas = $("ip_uptime_chart");
  if (!canvas) return;

  const data = Array.isArray(state.ip_uptime_chart) ? state.ip_uptime_chart : [];

  const countEl = $("ip_uptime_count");
  if (countEl) countEl.textContent = data.length;

  const wrapper = canvas.parentElement;
  const rect = wrapper ? wrapper.getBoundingClientRect() : { width: 900, height: 390 };
  const width = Math.max(760, Math.floor(rect.width || 900));
  const height = Math.max(390, Math.floor(rect.height || 390));
  const dpr = window.devicePixelRatio || 1;

  canvas.width = Math.floor(width * dpr);
  canvas.height = Math.floor(height * dpr);
  canvas.style.width = "100%";
  canvas.style.height = height + "px";

  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);

  const pad = { left: 68, right: 24, top: 28, bottom: 110 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const baseY = pad.top + plotH;

  if (!data.length) {
    ctx.font = "13px Outfit, sans-serif";
    ctx.fillStyle = "rgba(148, 163, 184, 0.85)";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("暂无已结束的 IP 连接时长统计数据", width / 2, height / 2);
    return;
  }

  // 关键：柱高和颜色都使用真实 seconds，不使用后端四舍五入后的 item.hours
  const secondValues = data.map(item => getIpUptimeSeconds(item));
  const sortedSeconds = [...secondValues].sort((a, b) => a - b);
  const scale = buildIpUptimeVisualScale(secondValues);

  ctx.font = "12px Outfit, sans-serif";
  ctx.textBaseline = "middle";

  // 横向网格线 + 纵轴刻度
  const gridSteps = 5;
  for (let i = 0; i <= gridSteps; i++) {
    const visualValue = scale.maxVisual - (scale.maxVisual / gridSteps) * i;
    const y = pad.top + (plotH / gridSteps) * i;

    const axisSeconds = scale.fromVisual(visualValue);

    ctx.strokeStyle = "rgba(148, 163, 184, 0.16)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(width - pad.right, y);
    ctx.stroke();

    ctx.fillStyle = "rgba(226, 232, 240, 0.75)";
    ctx.textAlign = "right";
    ctx.fillText(formatAxisSecondsAsHours(axisSeconds), pad.left - 12, y);
  }

  // 纵轴标题
  ctx.fillStyle = "rgba(148, 163, 184, 0.85)";
  ctx.textAlign = "left";
  ctx.fillText("小时", pad.left, 12);

  const slotW = plotW / data.length;
  const barW = Math.max(18, Math.min(58, slotW * 0.52));

  data.forEach((item, index) => {
    const seconds = getIpUptimeSeconds(item);

    const visualValue = scale.toVisual(seconds);
    const x = pad.left + index * slotW + (slotW - barW) / 2;

    // 关键：柱高按真实 seconds 的视觉值计算
    const barH = Math.max(3, (visualValue / scale.maxVisual) * plotH);
    const y = baseY - barH;

    // 关键：颜色按当前 10 条数据里的相对排名计算
    const level = getIpUptimeLevelByRank(seconds, sortedSeconds);

    const gradient = ctx.createLinearGradient(0, y, 0, baseY);
    gradient.addColorStop(0, level.colorTop);
    gradient.addColorStop(1, level.colorBottom);
    ctx.fillStyle = gradient;

    const radius = 7;

    ctx.beginPath();
    ctx.moveTo(x + radius, y);
    ctx.lineTo(x + barW - radius, y);
    ctx.quadraticCurveTo(x + barW, y, x + barW, y + radius);
    ctx.lineTo(x + barW, baseY);
    ctx.lineTo(x, baseY);
    ctx.lineTo(x, y + radius);
    ctx.quadraticCurveTo(x, y, x + radius, y);
    ctx.closePath();
    ctx.fill();

    // 柱顶值：继续显示真实时长，比如 2分钟 / 13小时51分 / 3天16小时48分
    const labelText = formatIpUptimeTopLabel(seconds);

    ctx.font = "12px Outfit, sans-serif";
    ctx.fillStyle = level.textColor;
    ctx.textAlign = "center";
    ctx.fillText(labelText, x + barW / 2, Math.max(12, y - 14));

    // 底部 IP 标签
    ctx.save();
    ctx.translate(x + barW / 2 + 30, height - 42);
    ctx.rotate(-Math.PI / 10);
    ctx.fillStyle = "rgba(226, 232, 240, 0.74)";
    ctx.textAlign = "right";
    ctx.fillText(String(item.label || item.ip || index + 1), 0, 0);
    ctx.restore();
  });

  // 底部基线
  ctx.strokeStyle = "rgba(148, 163, 184, 0.22)";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(pad.left, baseY);
  ctx.lineTo(width - pad.right, baseY);
  ctx.stroke();
}

function stableSortNodes() {
  nodes.sort((a, b) => {
    if ((b.score || 0) !== (a.score || 0)) {
      return (b.score || 0) - (a.score || 0);
    }
    return a.id.localeCompare(b.id);
  });
}

function render(){
  const activeNodeId = state.active_openvpn_node_id;
  const activeNode = nodes.find(n => n.active || n.id === activeNodeId);
  
  // Render separated Active Node Card
  const activeCardContainer = $("active_node_card");
  if (state.is_connecting) {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--warning); box-shadow: 0 0 15px rgba(245, 158, 11, 0.15);">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #f59e0b; width: 24px; height: 24px; animation: spin 2s linear infinite;"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-primary);">
              <span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3);"><span class="badge-pulse" style="background: #f59e0b;"></span>正在连接</span>
              <strong>${esc(state.active_node_latency || '正在连接...')}</strong>
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              ${esc(state.last_check_message || '正在与 VPN 节点建立加密隧道，请稍候...')}
            </div>
          </div>
        </div>
      </div>
    `;
  } else if (activeNode) {
    const latencyClass = getLatencyClass(activeNode.latency_ms);
    const latencyText = activeNode.latency_ms ? `<span class="latency-val ${latencyClass}">${activeNode.latency_ms} ms</span>` : "-";
    const displayLocation = activeNode.location || translateCountry(activeNode.country) || "-";
    activeCardContainer.innerHTML = `
      <div class="active-card">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #34d399; width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title">
              <span class="badge available"><span class="badge-pulse"></span>已连接</span>
              <strong>${esc(translateCountry(activeNode.country))} 节点</strong>
            </div>
            <div class="active-card-value mono" style="font-size: 20px; margin-top: 2px;">
              ${esc(activeNode.ip || activeNode.remote_host)}:${activeNode.remote_port || ""}
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              <span>物理位置: <strong>${esc(displayLocation)}</strong></span>
              <span style="margin-left: 12px;">延时: <strong>${latencyText}</strong></span>
              <span style="margin-left: 12px;">运营主体: <strong>${esc(activeNode.owner || activeNode.as_name || "-")}</strong></span>
              <span style="margin-left: 12px;">IP 类型: <strong>${esc(translateIpType(activeNode.ip_type))}</strong></span>
              ${state.connected_at ? `<span style="margin-left: 12px;">持续时间: <strong id="conn_duration">-</strong></span>` : ''}
              <span style="margin-left: 12px;">连接耗时: <strong>${esc(state.last_node_switch_duration_text || '-')}</strong></span>
            </div>
          </div>
        </div>
        <button class="btn-danger" style="height: 38px; padding: 0 16px; border-radius: 8px;" onclick="disconnectNode()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          断开连接
        </button>
      </div>
    `;
  } else {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--border-color); box-shadow: none;">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(244, 63, 94, 0.1); border-color: rgba(244, 63, 94, 0.2); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: var(--danger); width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-secondary);">
              <span class="badge unavailable" style="padding: 2px 8px;">未连接</span> 当前未连接 VPN 节点
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              在下方列表中选择一个可用备用节点并点击 “切换” 按钮开始连接。
            </div>
          </div>
        </div>
      </div>
    `;
  }
  
  
  if (state.connected_at && activeNode && !state.is_connecting) {
    if (window._durationTimer) clearInterval(window._durationTimer);

    function _fmtDur(s) {
      s = Math.max(0, Math.floor(s || 0));
      const d = Math.floor(s / 86400);
      const h = Math.floor((s % 86400) / 3600);
      const m = Math.floor((s % 3600) / 60);
      const sec = s % 60;
      return d +  '天 ' + h +  '时 ' + m +  '分 ' + sec +  '秒';
    }

    function _updateDur() {
      const el = document.getElementById('conn_duration');
      if (!el) {
        clearInterval(window._durationTimer);
        window._durationTimer = null;
        return;
      }

      el.textContent = _fmtDur(Math.floor(Date.now() / 1000 - Number(state.connected_at)));
    }

    _updateDur();
    window._durationTimer = setInterval(_updateDur, 1000);
  } else {
    if (window._durationTimer) {
      clearInterval(window._durationTimer);
      window._durationTimer = null;
    }
  }

    drawAutoSwitchChart();
    drawSwitchDurationChart();
    drawIpUptimeChart();
  
  const shown = getFilteredNodes();
  
  $("total").textContent=nodes.length; 
  $("target").textContent=state.target_valid_nodes||3;
  $("active").textContent=activeNode?1:0; 
  
  const statusMessage = state.last_check_message || "";
  const maintenanceInfo =
  state.is_maintaining && state.maintenance_message
    ? ` | 后台维护：<span style="color:#f59e0b;">${esc(state.maintenance_message)}</span>`
    : "";
  const activeNodeInfo = activeNode ? `<span class="badge available" style="margin-left:8px; padding:2px 8px;">${esc(translateCountry(activeNode.country))} (${activeNode.id})</span>` : `<span class="badge unavailable" style="margin-left:8px; padding:2px 8px;">无</span>`;
    const proxyAuthInfo = state.proxy_auth_enabled
      ? `<span class="proxy-auth-info">
           <span class="proxy-auth-user">
             ● 代理用户名：
             <strong class="mono" title="${proxyAuthVisible ? "当前显示明文" : "当前已脱敏"}">
               ${esc(getProxyAuthDisplay(state.proxy_username || "未配置"))}
             </strong>
             <button type="button" class="copy-auth-btn" onclick="copyProxyField('username', this)">复制</button>
           </span>
    
           <span class="proxy-auth-pass">
             ● 代理密码：
             <strong class="mono" title="${proxyAuthVisible ? "当前显示明文" : "当前已脱敏"}">
               ${esc(getProxyAuthDisplay(state.proxy_password || "未配置"))}
             </strong>
             <button type="button" class="copy-auth-btn" onclick="copyProxyField('password', this)">复制</button>
           </span>
    
           <button type="button"
             class="copy-auth-btn"
             onclick="toggleProxyAuthVisible()"
             title="${proxyAuthVisible ? "切换为脱敏显示" : "显示代理账号密码明文"}">
             ${proxyAuthVisible ? "隐藏" : "显示"}
           </button>
         </span>`
      : `<span class="proxy-auth-info">
           <span style="color:#fb7185;">● 代理认证：未开启</span>
         </span>`;

const localProxyText = state.local_proxy || "http://0.0.0.0:7928";

$("status").innerHTML=`<span class="status-dot"></span>HTTP 代理接口：${esc(localProxyText)} | 活动节点：${activeNodeInfo} | 状态：${esc(statusMessage)}${maintenanceInfo}${proxyAuthInfo}`;  
  // Update proxy test status card based on background checks
  const pBadge = $("proxy_status_badge");
  const pIpVal = $("proxy_ip_val");
  const pLatVal = $("proxy_latency_val");
  const pBtn = $("btn_test_proxy");
  
  if (state.is_connecting) {
    pBadge.className = "badge";
    pBadge.style.background = "rgba(245, 158, 11, 0.15)";
    pBadge.style.color = "#f59e0b";
    pBadge.style.borderColor = "rgba(245, 158, 11, 0.3)";
    pBadge.innerHTML = `<span class="badge-pulse" style="background: #f59e0b;"></span>正在连接`;
    pIpVal.textContent = state.active_node_latency || "正在连接...";
    pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message || "正在与 VPN 节点建立加密隧道，请稍候...")}</span>`;
    pBtn.disabled = true;
    pBtn.style.opacity = "0.5";
    pBtn.style.cursor = "not-allowed";
  } else {
    pBtn.disabled = false;
    pBtn.style.opacity = "";
    pBtn.style.cursor = "";
    pBadge.style.background = "";
    pBadge.style.color = "";
    pBadge.style.borderColor = "";
    if (state.proxy_ok !== undefined) {
      if (state.proxy_ok) {
        pBadge.className = "badge available";
        pBadge.textContent = "可用";
        pIpVal.textContent = state.proxy_ip || "-";
        const latencyClass = getLatencyClass(state.proxy_latency_ms);
        pLatVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${state.proxy_latency_ms} ms</span>`;
      } else {
        pBadge.className = "badge unavailable";
        pBadge.textContent = "不可用";
        pIpVal.textContent = "-";
        if (state.last_check_message) {
          pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message)}</span>`;
        } else {
          pLatVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(state.proxy_error)}">${esc(state.proxy_error || "连接失败")}</span>`;
        }
      }
    } else {
      pBadge.className = "badge not_checked";
      pBadge.textContent = "未检测";
      pIpVal.textContent = "-";
      if (state.last_check_message) {
        pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message)}</span>`;
      } else {
        pLatVal.innerHTML = "";
      }
    }
  }

  // Pagination calculation
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;
  
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, shown.length);
  currentPageNodes = shown.slice(startIndex, endIndex);

  // Render table rows
  if (currentPageNodes.length === 0) {
    $("rows").innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-secondary); padding: 40px 0;">未找到符合过滤条件的备选节点。</td></tr>`;
  } else {
    $("rows").innerHTML=currentPageNodes.map(n=>{
      const isCurrentlyActive = activeNode && n.id === activeNode.id;
      const rowClass = isCurrentlyActive ? 'class="active-row"' : '';
      
      const badgeClass = isCurrentlyActive ? 'available' : (n.probe_status || 'not_checked');
      const badgeText = isCurrentlyActive ? '<span class="badge-pulse"></span>已连接' : translateStatus(n.probe_status);
      const latencyClass = getLatencyClass(n.latency_ms);
      const latencyText = n.latency_ms ? `<span class="latency-val ${latencyClass}">${n.latency_ms} ms</span>` : "-";
      const displayLocation = n.location || translateCountry(n.country) || "-";
      
      const isTesting = testingNodeIds.has(n.id);
      const testSpinner = `<svg style="animation: spin 1s linear infinite; width: 12px; height: 12px; display: inline-block; margin-right: 4px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>`;
      const testBtnText = isTesting ? `${testSpinner}检测中` : '检测';
      const testBtn = `<button class="test-btn" data-node-id="${esc(n.id)}" ${isTesting ? 'disabled' : ''} onclick="testNode(this, '${esc(n.id)}', event)">${testBtnText}</button>`;
      
      // Connect button is disabled if probe status is "unavailable" and not already active, or if we are already connecting
      const isUnavailable = n.probe_status === "unavailable";
      const connectBtn = isCurrentlyActive 
        ? `<button class="connect-btn" disabled style="background: var(--success-gradient); color: white; cursor: default; opacity: 1;">已连接</button>`
        : `<button class="connect-btn" ${(isUnavailable || state.is_connecting) ? 'disabled style="opacity:0.3; cursor:not-allowed;"' : ''} onclick="connectNode('${esc(n.id)}')">切换</button>`;
      
      return `<tr ${rowClass}>
        <td><span class="badge ${badgeClass}">${badgeText}</span></td>
        <td>${latencyText}</td>
        <td class="mono">${esc(n.ip||n.remote_host)}:${n.remote_port||""}</td>
        <td>${esc(displayLocation)}</td>
        <td class="mono" style="font-size:12px; color:var(--text-secondary);">${esc(n.asn||"-")}</td>
        <td>${esc(n.owner||n.as_name||"-")}</td>
        <td>${esc(translateQuality(n.quality))}</td>
        <td>${esc(translateIpType(n.ip_type))}</td>
        <td>
          <div class="table-actions">
            ${testBtn}
            ${connectBtn}
          </div>
        </td>
      </tr>`;
    }).join("");
  }

  // Render pagination controls
  $("page_start").textContent = shown.length > 0 ? startIndex + 1 : 0;
  $("page_end").textContent = endIndex;
  $("filtered_count").textContent = shown.length;
  $("current_page_val").textContent = currentPage;
  $("total_pages_val").textContent = totalPages;
  
  $("btn_first_page").disabled = currentPage === 1;
  $("btn_prev_page").disabled = currentPage === 1;
  $("btn_next_page").disabled = currentPage === totalPages;
  $("btn_last_page").disabled = currentPage === totalPages;
}

// Hook up page buttons events
$("btn_first_page").onclick = () => { currentPage = 1; render(); };
$("btn_prev_page").onclick = () => { if (currentPage > 1) { currentPage--; render(); } };
$("btn_next_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage < totalPages) { currentPage++; render(); }
};
$("btn_last_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  currentPage = totalPages;
  render();
};

async function testNode(btn, id, event){
  if (event) event.stopPropagation();
  testingNodeIds.add(id);
  render();
  
  try {
    const response = await fetch("./api/test_node", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = await response.json();
    if (result.ok && result.node) {
      const idx = nodes.findIndex(n => n.id === id);
      if (idx !== -1) {
        nodes[idx] = result.node;
      }
    }
  } catch (e) {
  } finally {
    testingNodeIds.delete(id);
    render();
  }
}

let pollInterval = null;

function startConnectionPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(async () => {
    try {
      const resp = await fetch("./api/nodes");
      const data = await resp.json();
      nodes = data.nodes || [];
      state = data.state || {};
      stableSortNodes();
      render();
      
      if (!state.is_connecting) {
        clearInterval(pollInterval);
        pollInterval = null;
        try {
          await fetch("./api/test_proxy", { method: "POST" });
        } catch(pe){}
        load();
      }
    } catch(pe) {
      clearInterval(pollInterval);
      pollInterval = null;
      load();
    }
  }, 1000);
}

async function initProjectAutoUpdateSetting() {
  try {
    const r = await fetch("./api/project_auto_update");
    const d = await r.json();

    const toggle = document.getElementById("project_auto_update_toggle");
    if (toggle) {
      toggle.checked = d.enabled !== false;
    }
  } catch (e) {}
}

async function setProjectAutoUpdateEnabled(enabled) {
  try {
    await fetch("./api/project_auto_update", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled })
    });
  } catch (e) {}
}

const projectAutoUpdateToggle = document.getElementById("project_auto_update_toggle");
if (projectAutoUpdateToggle) {
  projectAutoUpdateToggle.addEventListener("change", function () {
    setProjectAutoUpdateEnabled(this.checked);
  });
}

initProjectAutoUpdateSetting();

async function connectNode(id){
  state.is_connecting = true;
  state.active_openvpn_node_id = id;
  state.active_node_latency = "正在连接";
  state.last_check_message = "正在发送连接请求...";
  render();
  
  startConnectionPolling();
  
  try {
    const r = await fetch("./api/connect",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({id})
    });
    const result = await r.json();
    if (!result.ok) {
      alert("连接失败: " + (result.error || "未知错误"));
      if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
      }
      state.is_connecting = false;
      render();
      return;
    }
  } catch(e) {
    alert("连接请求错误");
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
    state.is_connecting = false;
    render();
  }
}

async function disconnectNode(){
  if (!confirm("确定要断开当前的 VPN 连接吗？")) return;
  try {
    const response = await fetch("./api/disconnect", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      try {
        await fetch("./api/test_proxy", { method: "POST" });
      } catch(pe){}
      load();
    } else {
      alert("断开连接失败: " + (result.error || "未知错误"));
    }
  } catch (e) {
    alert("请求断开连接失败");
  }
}

// Batch test button implementation
$("btn_batch_test").onclick = async () => {
  const pageNodes = currentPageNodes || [];
  if (pageNodes.length === 0) {
    alert("当前页面没有可供测试的备选节点");
    return;
  }
  
  const btn = $("btn_batch_test");
  btn.disabled = true;
  btn.innerHTML = `<svg style="animation: spin 1s linear infinite; width: 14px; height: 14px; display: inline-block; margin-right: 6px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>测试中...`;
  
  pageNodes.forEach(n => testingNodeIds.add(n.id));
  render();
  
  const testPromises = pageNodes.map(async (n) => {
    const id = n.id;
    try {
      const response = await fetch("./api/test_node", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id })
      });
      const result = await response.json();
      if (result.ok && result.node) {
        const idx = nodes.findIndex(item => item.id === id);
        if (idx !== -1) {
          nodes[idx] = result.node;
        }
      }
    } catch (e) {
    } finally {
      testingNodeIds.delete(id);
      render();
    }
  });
  
  try {
    await Promise.all(testPromises);
  } catch (e) {
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 批量测试本页`;
  }
};

async function load(){
  const r=await fetch("./api/nodes"); 
  const d=await r.json(); 
  nodes=d.nodes||[]; 
  state=d.state||{}; 
  
  stableSortNodes();
  updateCountryFilter();
  render();

  if (state.is_connecting) {
    startConnectionPolling();
  }
}

$("search").oninput=()=>{ currentPage = 1; render(); };
$("country_filter").onchange=()=>{ currentPage = 1; render(); };

$("refresh").onclick=async()=>{ 
  $("refresh").disabled=true; 
  $("refresh").textContent="正在后台更新..."; 
  try{await fetch("./api/refresh_nodes",{method:"POST"}); await load();} 
  catch(e){}
  setTimeout(()=>{
    $("refresh").disabled=false; 
    $("refresh").textContent="更新节点";
  }, 3000);
};
$("check").onclick=async()=>{ 
  $("check").disabled=true; 
  $("check").textContent="检测中..."; 
  try{await fetch("./api/check",{method:"POST"}); await load();} 
  finally{$("check").disabled=false; $("check").textContent="立即检测补齐";}
};
$("btn_test_proxy").onclick = async () => {
  const btn = $("btn_test_proxy");
  const badge = $("proxy_status_badge");
  const ipVal = $("proxy_ip_val");
  const latVal = $("proxy_latency_val");
  
  btn.disabled = true;
  btn.innerHTML = `<span class="badge-pulse"></span>测试中...`;
  badge.className = "badge not_checked";
  badge.textContent = "检测中...";
  ipVal.textContent = "-";
  latVal.textContent = "";
  
  try {
    const response = await fetch("./api/test_proxy", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      badge.className = "badge available";
      badge.textContent = "可用";
      ipVal.textContent = result.ip || "-";
      
      const latencyClass = getLatencyClass(result.latency_ms);
      latVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${result.latency_ms} ms</span>`;
    } else {
      badge.className = "badge unavailable";
      badge.textContent = "不可用";
      ipVal.textContent = "-";
      latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(result.error)}">连接失败</span>`;
    }
  } catch (e) {
    badge.className = "badge unavailable";
    badge.textContent = "网络错误";
    ipVal.textContent = "-";
    latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;">请求出错</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 测试代理`;
  }
};

// Admin dropdown toggle
const adminBtn = $("admin_btn");
const adminDropdown = $("admin_dropdown");
if (adminBtn && adminDropdown) {
  adminBtn.onclick = (e) => {
    e.stopPropagation();
    const isShow = adminDropdown.style.display === "block";
    adminDropdown.style.display = isShow ? "none" : "block";
  };
  document.addEventListener("click", () => {
    adminDropdown.style.display = "none";
  });
}

function openSettingsModal() {
  $("settings_error").style.display = "none";
  $("settings_success").style.display = "none";
  $("settings_form").reset();

  const proxyMsg = $("settings_proxy_msg");
  if (proxyMsg) {
    proxyMsg.style.display = "none";
    proxyMsg.textContent = "";
  }
  
  if (state) {
    $("settings_port").value = state.port || 8787;
    $("settings_suffix").value = state.secret_path || "EJsW2EeBo9lY";


    if ($("settings_proxy_username")) {
      $("settings_proxy_username").value = state.proxy_username || "";
    }
    if ($("settings_proxy_password")) {
      $("settings_proxy_password").value = state.proxy_password || "";
    }
  }
  
  $("settings_modal").style.display = "flex";
  $("admin_dropdown").style.display = "none";
}
function openProxySettingsModal() {
  const proxyMsg = $("settings_proxy_msg");
  if (proxyMsg) {
    proxyMsg.style.display = "none";
    proxyMsg.textContent = "";
  }



  $("proxy_settings_modal").style.display = "flex";
  $("admin_dropdown").style.display = "none";
}

function closeProxySettingsModal() {
  $("proxy_settings_modal").style.display = "none";
}

function closeSettingsModal() {
  $("settings_modal").style.display = "none";
}

async function saveSettings(e) {
  e.preventDefault();
  const errorDivEl = $("settings_error");
  const successDiv = $("settings_success");
  const submitBtn = $("settings_submit_btn");
  
  errorDivEl.style.display = "none";
  successDiv.style.display = "none";
  
  const port = parseInt($("settings_port").value);
  const suffix = $("settings_suffix").value.trim();
  const newUsername = $("settings_new_username").value.trim();
  const newPassword = $("settings_new_password").value.trim();
  const currUsername = $("settings_curr_username").value.trim();
  const currPassword = $("settings_curr_password").value.trim();
  
  if (isNaN(port) || port < 1 || port > 65535) {
    errorDivEl.textContent = "端口范围必须在 1 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (!/^[A-Za-z0-9]+$/.test(suffix)) {
    errorDivEl.textContent = "登录安全后缀仅能由英文字母和数字组成";
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";
  
  try {
    const res = await fetch("./api/update_settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        port: port,
        secret_path: suffix,
        new_username: newUsername,
        new_password: newPassword,
        curr_username: currUsername,
        curr_password: currPassword
      })
    });
    
    const data = await res.json();
    if (res.ok && data.ok) {
      successDiv.textContent = "保存成功！页面将在 4 秒内自动跳转至新地址...";
      successDiv.style.display = "block";
      
      const inputs = $("settings_form").querySelectorAll("input, button");
      inputs.forEach(el => el.disabled = true);
      
      setTimeout(() => {
        const protocol = window.location.protocol;
        const host = window.location.hostname;
        window.location.href = `${protocol}//${host}:${port}/${suffix}/`;
      }, 4000);
    } else {
      errorDivEl.textContent = data.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}
function randomChars(length, chars) {
  const result = [];
  const cryptoObj = window.crypto || window.msCrypto;

  if (cryptoObj && cryptoObj.getRandomValues) {
    const values = new Uint32Array(length);
    cryptoObj.getRandomValues(values);

    for (let i = 0; i < length; i++) {
      result.push(chars[values[i] % chars.length]);
    }
  } else {
    for (let i = 0; i < length; i++) {
      result.push(chars[Math.floor(Math.random() * chars.length)]);
    }
  }

  return result.join("");
}

function generateStrongProxyPassword(length = 24) {
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const digits = "0123456789";
  const all = lower + upper + digits;

  while (true) {
    const password = randomChars(length, all);

    if (
      /[a-z]/.test(password) &&
      /[A-Z]/.test(password) &&
      /[0-9]/.test(password)
    ) {
      return password;
    }
  }
}

function generateProxyCredentials() {
  const username = "aimili_" + randomChars(
    12,
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
  );

  const password = generateStrongProxyPassword(24);

  $("settings_proxy_username").value = username;
  $("settings_proxy_password").value = password;

  const msg = $("settings_proxy_msg");
  if (msg) {
    msg.textContent = "已随机生成代理账号密码，点击“保存配置”后实时生效";
    msg.style.color = "var(--success)";
    msg.style.display = "block";
  }
}

async function saveProxyAuthSettings() {
  const btn = $("settings_proxy_save_btn");
  const msg = $("settings_proxy_msg");

  const enabled = true;
  const username = $("settings_proxy_username").value.trim();
  const password = $("settings_proxy_password").value.trim();

  msg.style.display = "none";
  msg.textContent = "";

  if (!/^[A-Za-z0-9_.@-]{3,64}$/.test(username)) {
    msg.textContent = "代理用户名长度必须为 3-64 位，只能包含字母、数字、下划线、点、@ 和短横线";
    msg.style.color = "var(--danger)";
    msg.style.display = "block";
    return;
  }

  if (!/^[A-Za-z0-9_.@-]{6,128}$/.test(password)) {
    msg.textContent = "代理密码长度必须为 6-128 位，只能包含字母、数字、下划线、点、@ 和短横线";
    msg.style.color = "var(--danger)";
    msg.style.display = "block";
    return;
  }

  btn.disabled = true;
  btn.textContent = "正在保存...";

  try {
    const res = await fetch("./api/update_proxy_auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        enabled,
        username,
        password,
      }),
    });

    const data = await res.json();

    if (res.ok && data.ok) {
      state.proxy_auth_enabled = data.proxy_auth_enabled;
      state.proxy_username = data.proxy_username;
      state.proxy_password = data.proxy_password;

      msg.textContent = "代理认证已更新，并已实时生效";
      msg.style.color = "var(--success)";
      msg.style.display = "block";

      render();
    } else {
      msg.textContent = data.error || "代理认证保存失败";
      msg.style.color = "var(--danger)";
      msg.style.display = "block";
    }
  } catch (err) {
    msg.textContent = "连接服务器失败，请稍后重试";
    msg.style.color = "var(--danger)";
    msg.style.display = "block";
  } finally {
    btn.disabled = false;
    btn.textContent = "保存配置";
  }
}

async function logoutAdmin() {
  try {
    const res = await fetch("./api/logout", { method: "POST" });
    if (res.ok) {
      window.location.reload();
    }
  } catch (err) {
    console.error("退出登录失败", err);
    window.location.reload();
  }
}

document.addEventListener("click", (e) => {
  const target = e.target;

  if (target && target.id === "refresh_switch_duration_btn") {
    refreshSwitchDurationChartData();
    return;
  }

  if (target && target.id === "refresh_ip_uptime_btn") {
    refreshIpUptimeChartData();
    return;
  }
});

window.addEventListener("resize", () => {
  if (window._switchChartResizeTimer) {
    clearTimeout(window._switchChartResizeTimer);
  }

  window._switchChartResizeTimer = setTimeout(() => {
    if (typeof state !== "undefined") {
      if (typeof drawAutoSwitchChart === "function") {
        drawAutoSwitchChart();
      }

      if (typeof drawSwitchDurationChart === "function") {
        drawSwitchDurationChart();
      }

      if (typeof drawIpUptimeChart === "function") {
        drawIpUptimeChart();
      }
    }
  }, 150);
});

// 页面加载时自动初始化数据
load();

// 每 10 秒在前台空闲时自动更新节点与状态，无需手动刷新页面
setInterval(async () => {
  if (typeof state !== "undefined" && !state.is_connecting && (!testingNodeIds || !testingNodeIds.size) && document.visibilityState === "visible") {
    try {
      const r = await fetch("./api/nodes");
      const d = await r.json();
      nodes = d.nodes || [];
      state = d.state || {};
      stableSortNodes();
      render();
    } catch(e) {}
  }
}, 10000);
</script>
</body></html>"""

def check_proxy_health() -> dict[str, Any]:
    # 1. 检测代理服务端口是否在监听
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.5)
    try:
        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
        s.close()
    except Exception as e:
        return {
            "ok": False,
            "error": f"代理服务未运行 (端口 {LOCAL_PROXY_PORT} 连接失败，原因: {e})"
        }

    # 2. 检测虚拟网卡 tun0 是否存在 (Linux 下)
    tun_path = Path("/sys/class/net/tun0")
    if sys.platform.startswith("linux") and not tun_path.exists():
        return {
            "ok": False,
            "error": "VPN 虚拟网卡 (tun0) 未启用，请确保当前已成功连接 VPN 节点"
        }

    # 3. 使用 curl 通过本地 SOCKS5 代理接口测试 IP 与实际延迟
    def run_proxy_ip_check(url: str, timeout_seconds: int = 6) -> dict[str, Any] | None:
        cmd = [
            "curl", "-4", "-sS",
            "-w", "\n%{time_total} %{http_code}",
            *get_internal_curl_proxy_args("socks5h", "127.0.0.1"),
            url,
            "--max-time", str(timeout_seconds),
        ]

        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds + 2)

        if res.returncode != 0:
            return None

        lines = res.stdout.strip().splitlines()
        if len(lines) < 2:
            return None

        ip = lines[0].strip()
        time_info = lines[-1].strip().split()

        if len(time_info) != 2:
            return None

        total_time_str, http_code = time_info

        if http_code != "200" or not ip:
            return None

        latency_ms = int(float(total_time_str) * 1000)
        return {
            "ok": True,
            "ip": ip,
            "latency_ms": latency_ms,
        }

    try:
        for url in (
                "http://ip.sb",
                "http://api.ipify.org",
                "https://ifconfig.me/ip",
        ):
            result = run_proxy_ip_check(url, 6)
            if result:
                return result

        return {
            "ok": False,
            "error": "出口连接测试失败：所有 IP 检测接口均不可用"
        }
    except Exception as e:
        return {
            "ok": False,
            "error": f"出口连接测试异常: {e}"
        }

def confirm_proxy_health_failure() -> tuple[bool, dict[str, Any]]:
    """
    连续检测代理健康状态。
    返回:
      True  = 确认故障，需要切换
      False = 未确认故障，不切换
    """
    last_result: dict[str, Any] = {
        "ok": False,
        "error": "未知错误",
    }

    for index in range(PROXY_HEALTH_CONFIRM_TIMES):
        result = check_proxy_health()
        last_result = result

        if result.get("ok"):
            return False, result

        print(
            f"[代理检测] 第 {index + 1}/{PROXY_HEALTH_CONFIRM_TIMES} 次检测失败: {result.get('error', '未知错误')}",
            flush=True,
        )

        if index < PROXY_HEALTH_CONFIRM_TIMES - 1 and PROXY_HEALTH_CONFIRM_DELAY_SECONDS > 0:
            time.sleep(PROXY_HEALTH_CONFIRM_DELAY_SECONDS)

    return True, last_result

def background_proxy_checker() -> None:
    time.sleep(2)

    while True:
        try:
            if is_connecting:
                time.sleep(5)
                continue

            if not active_openvpn_node_id and not active_openvpn_running():
                set_state(
                    proxy_ok=False,
                    proxy_ip="-",
                    proxy_latency_ms=0,
                    proxy_error="当前没有活动 VPN 节点，等待维护线程连接节点",
                    proxy_fail_count=0,
                    proxy_fail_threshold=PROXY_HEALTH_CONFIRM_TIMES,
                )
                time.sleep(30)
                continue

            res = check_proxy_health()



            if res["ok"]:
                set_state(
                    proxy_ok=True,
                    proxy_ip=res["ip"],
                    proxy_latency_ms=res["latency_ms"],
                    proxy_error="",
                    proxy_fail_count=0,
                    proxy_fail_threshold=PROXY_HEALTH_CONFIRM_TIMES,
                )

                touch_ip_uptime_seen_ip(
                    res.get("ip", ""),
                    node_id=active_openvpn_node_id,
                    reason="后台健康检测确认出口 IP",
                )

                log_to_json(
                    "INFO",
                    "Proxy",
                    f"代理可用，IP: {res['ip']}, 延迟: {res['latency_ms']} ms",
                )

            else:
                first_error = res.get("error", "未知错误")

                print(
                    f"[警告] 7928 端口本地代理首次检测不可用，开始连续确认检测: {first_error}",
                    flush=True,
                )

                log_to_json(
                    "WARNING",
                    "Proxy",
                    f"代理首次检测不可用，开始连续确认检测: {first_error}",
                )

                confirmed_failed, final_res = confirm_proxy_health_failure()
                final_error = final_res.get("error", first_error)

                if not confirmed_failed:
                    set_state(
                        proxy_ok=True,
                        proxy_ip=final_res.get("ip", "-"),
                        proxy_latency_ms=final_res.get("latency_ms", 0),
                        proxy_error="",
                        proxy_fail_count=0,
                        proxy_fail_threshold=PROXY_HEALTH_CONFIRM_TIMES,
                    )

                    touch_ip_uptime_seen_ip(
                        final_res.get("ip", ""),
                        node_id=active_openvpn_node_id,
                        reason="追加检测恢复正常，确认出口 IP",
                    )

                    print(
                        "[代理检测] 追加检测已恢复正常，判定为临时抖动，不切换节点",
                        flush=True,
                    )

                    log_to_json(
                        "INFO",
                        "Proxy",
                        "追加检测已恢复正常，判定为临时抖动，不切换节点",
                    )

                    time.sleep(30)
                    continue

                set_state(
                    proxy_ok=False,
                    proxy_ip="-",
                    proxy_latency_ms=0,
                    proxy_error=final_error,
                    proxy_fail_count=PROXY_HEALTH_CONFIRM_TIMES,
                    proxy_fail_threshold=PROXY_HEALTH_CONFIRM_TIMES,
                )



                if active_openvpn_node_id:
                    mark_node_switch_start(
                        f"代理连续 {PROXY_HEALTH_CONFIRM_TIMES} 次检测失败: {final_error}"
                    )

                    mark_current_ip_uptime_pending_end(
                        f"代理连续 {PROXY_HEALTH_CONFIRM_TIMES} 次检测失败: {final_error}"
                    )

                if not active_openvpn_node_id:
                    time.sleep(30)
                    continue

                print(
                    f"[代理检测] 连续 {PROXY_HEALTH_CONFIRM_TIMES} 次检测失败，确认故障，开始自动切换节点",
                    flush=True,
                )

                log_to_json(
                    "WARNING",
                    "Proxy",
                    f"代理连续 {PROXY_HEALTH_CONFIRM_TIMES} 次检测失败，确认故障，开始自动切换节点，最后错误: {final_error}",
                )

                with lock:
                    nodes = read_json(NODES_FILE, [])
                    active_node = next(
                        (n for n in nodes if n.get("id") == active_openvpn_node_id),
                        None,
                    )

                    if active_node:
                        mark_blacklisted(
                            active_node,
                            f"代理连续 {PROXY_HEALTH_CONFIRM_TIMES} 次检测失败: {final_error}",
                        )
                        active_node["probe_status"] = "unavailable"
                        active_node["probe_message"] = (
                            f"代理连续 {PROXY_HEALTH_CONFIRM_TIMES} 次检测失败: {final_error}"
                        )
                        active_node["probed_at"] = time.time()
                        write_json(NODES_FILE, nodes)

                auto_switch_node(record_switch=True)

        except Exception as e:
            print(f"[错误] 代理后台检测发生异常: {e}", flush=True)
            log_to_json("ERROR", "Proxy", f"检测守护线程发生异常: {e}")

        time.sleep(30)

def active_node_pinger() -> None:
    global active_openvpn_node_id, is_connecting
    while True:
        try:
            if active_openvpn_running() and active_openvpn_node_id:
                nodes = read_json(NODES_FILE, [])
                node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                if node:
                    ip = node.get("ip") or node.get("remote_host")
                    port = parse_int(node.get("remote_port"))
                    fallback = parse_int(node.get("ping"))
                    if ip:
                        latency = vpn_utils.ping_latency_ms(ip, port, fallback)
                        if latency > 0:
                            set_state(active_node_latency=f"{latency} ms")
                        else:
                            set_state(active_node_latency="检测超时")
                    else:
                        set_state(active_node_latency="检测超时")
                else:
                    set_state(active_node_latency="检测超时")
            elif is_connecting:
                set_state(active_node_latency="测试中...")
            else:
                set_state(active_node_latency="无活动连接")
        except Exception as e:
            print(f"[ERROR] active_node_pinger error: {e}", flush=True)
        time.sleep(10)


class Handler(BaseHTTPRequestHandler):
    def get_secret_path(self) -> str:
        auth_file = DATA_DIR / "ui_auth.json"
        if not auth_file.exists():
            try:
                DATA_DIR.mkdir(exist_ok=True)
                auth_file.write_text(json.dumps({"secret_path": "EJsW2EeBo9lY"}), encoding="utf-8")
            except Exception:
                pass
            return "EJsW2EeBo9lY"
        try:
            creds = json.loads(auth_file.read_text(encoding="utf-8"))
            if "secret_path" in creds:
                return creds["secret_path"]
            elif "password" in creds:
                secret_path = creds["password"]
                try:
                    auth_file.write_text(json.dumps({"secret_path": secret_path}), encoding="utf-8")
                except Exception:
                    pass
                return secret_path
            return "EJsW2EeBo9lY"
        except Exception:
            return "EJsW2EeBo9lY"

    def is_authorized(self) -> bool:
        ui_cfg = load_ui_config()
        pwd = ui_cfg.get("password")
        if not pwd:
            return True
        
        cookie_header = self.headers.get("Cookie", "")
        cookies = {}
        if cookie_header:
            for item in cookie_header.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()
        
        session_token = cookies.get("session")
        if not session_token:
            return False
            
        with lock:
            exp_time = active_sessions.get(session_token)
            if exp_time is not None and exp_time > time.time():
                return True
        return False

    def validate_path(self) -> str:
        secret_path = self.get_secret_path()
        if not secret_path:
            return self.path
        if self.path == f"/{secret_path}":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", f"/{secret_path}/")
            self.end_headers()
            return ""
        prefix = f"/{secret_path}/"
        if self.path.startswith(prefix):
            return "/" + self.path[len(prefix):]
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()
        return ""

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}", flush=True)

    def send_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def do_GET(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if not self.is_authorized():
            if effective_path in ("/", "/index.html"):
                self.send_bytes(LOGIN_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            else:
                self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
                
        if effective_path in ("/", "/index.html"):
            self.send_bytes(INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")

        elif effective_path == "/api/project_auto_update":
            self.send_json(load_project_update_config())

        elif effective_path == "/api/nodes":
            global last_active_ping_time, last_active_latency, active_openvpn_node_id
            nodes = read_json(NODES_FILE, [])
            resolved_active_id = resolve_active_openvpn_node_id()

            active_node = next(
                (n for n in nodes if resolved_active_id and n.get("id") == resolved_active_id),
                None,
            )

            for n in nodes:
                n["active"] = bool(resolved_active_id and n.get("id") == resolved_active_id)

            if active_node:
                ip = active_node.get("ip") or active_node.get("remote_host")
                if ip:
                    now = time.time()
                    if now - last_active_ping_time > 15.0:
                        last_active_ping_time = now
                        def bg_ping(ip_addr: str, port: int, fallback: int) -> None:
                            global last_active_latency
                            try:
                                latency = vpn_utils.ping_latency_ms(ip_addr, port, fallback)
                                if latency > 0:
                                    last_active_latency = latency
                            except Exception:
                                pass
                        threading.Thread(
                            target=bg_ping, 
                            args=(ip, parse_int(active_node.get("remote_port")), parse_int(active_node.get("ping"))),
                            daemon=True
                        ).start()
                    if last_active_latency > 0:
                        active_node["latency_ms"] = last_active_latency
            stripped_nodes = []
            for n in nodes:
                stripped = n.copy()
                if "config_text" in stripped:
                    del stripped["config_text"]
                stripped_nodes.append(stripped)
            self.send_json({"nodes": stripped_nodes, "state": get_state()})
        elif effective_path.startswith("/configs/"):
            filename = urllib.parse.unquote(effective_path.removeprefix("/configs/"))
            with lock:
                nodes = read_json(NODES_FILE, [])
                node = next((n for n in nodes if Path(n.get("config_file", "")).name == filename), None)
            if node and node.get("config_text"):
                self.send_bytes(node["config_text"].encode("utf-8"), "application/x-openvpn-profile")
            else:
                self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return

        if effective_path == "/api/login":
            try:
                client_ip = get_request_ip(self)

                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                input_pwd = str(payload.get("password") or "")
                input_uname = str(payload.get("username") or "")

                locked, remaining_seconds = get_login_lock_status(client_ip)
                if locked:
                    self.send_json(
                        {
                            "ok": False,
                            "error": f"登录失败次数过多，请 {format_seconds_zh(remaining_seconds)} 后再试",
                            "locked": True,
                            "remaining_seconds": remaining_seconds,
                        },
                        HTTPStatus.TOO_MANY_REQUESTS,
                    )
                    return

                ui_cfg = load_ui_config()
                expected_pwd = ui_cfg.get("password", "")
                expected_uname = ui_cfg.get("username", "admin")

                if expected_pwd and input_pwd == expected_pwd and input_uname == expected_uname:
                    clear_login_failure(client_ip)

                    token = uuid.uuid4().hex
                    with lock:
                        active_sessions[token] = time.time() + 30 * 24 * 3600
                    body = json.dumps({"ok": True}).encode("utf-8")

                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")

                    secret_path = self.get_secret_path()
                    cookie_path = f"/{secret_path}/" if secret_path else "/"
                    self.send_header(
                        "Set-Cookie",
                        f"session={token}; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=2592000"
                    )

                    self.end_headers()
                    self.wfile.write(body)
                    self.wfile.flush()
                    self.close_connection = True
                else:
                    fail_info = register_login_failure(client_ip)

                    if fail_info["locked"]:
                        self.send_json(
                            {
                                "ok": False,
                                "error": f"登录失败次数过多，已锁定 {format_seconds_zh(LOGIN_LOCK_SECONDS)}",
                                "locked": True,
                                "remaining_seconds": LOGIN_LOCK_SECONDS,
                            },
                            HTTPStatus.TOO_MANY_REQUESTS,
                        )
                    else:
                        remaining_attempts = max(
                            0,
                            LOGIN_FAIL_MAX_ATTEMPTS - int(fail_info["count"]),
                            )

                        self.send_json(
                            {
                                "ok": False,
                                "error": f"用户名或密码不正确，还可尝试 {remaining_attempts} 次",
                                "locked": False,
                                "remaining_attempts": remaining_attempts,
                            },
                            HTTPStatus.FORBIDDEN,
                        )
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/logout":
            try:
                cookie_header = self.headers.get("Cookie", "")
                cookies = {}
                if cookie_header:
                    for item in cookie_header.split(";"):
                        item = item.strip()
                        if "=" in item:
                            k, v = item.split("=", 1)
                            cookies[k.strip()] = v.strip()
                session_token = cookies.get("session")
                if session_token:
                    with lock:
                        active_sessions.pop(session_token, None)
                secret_path = self.get_secret_path()
                cookie_path = f"/{secret_path}/" if secret_path else "/"
                body = json.dumps({"ok": True}).encode("utf-8")

                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.send_header(
                    "Set-Cookie",
                    f"session=; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
                )

                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()
                self.close_connection = True

            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if not self.is_authorized():
            self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return
        if effective_path == "/api/update_proxy_auth":

            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")

                enabled = True
                username = validate_proxy_credential(
                    "代理用户名",
                    str(payload.get("username") or ""),
                    3,
                    64,
                )
                password = validate_proxy_credential(
                    "代理密码",
                    str(payload.get("password") or ""),
                    6,
                    128,
                )

                write_proxy_auth_env(enabled, username, password)
                apply_proxy_auth_runtime(enabled, username, password)

                set_state(proxy_auth_enabled=enabled)

                self.send_json({
                    "ok": True,
                    "message": "代理认证配置已更新，并已实时生效",
                    "proxy_auth_enabled": enabled,
                    "proxy_username": username,
                    "proxy_password": password,
                })
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/update_settings":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                
                curr_username = str(payload.get("curr_username") or "")
                curr_password = str(payload.get("curr_password") or "")
                
                new_port = payload.get("port")
                new_suffix = str(payload.get("secret_path") or "").strip()
                new_username = str(payload.get("new_username") or "").strip()
                new_password = str(payload.get("new_password") or "").strip()
                
                if not curr_username or not curr_password:
                    self.send_json({"ok": False, "error": "请输入当前账号和密码进行安全验证"}, HTTPStatus.FORBIDDEN)
                    return
                
                ui_cfg = load_ui_config()
                expected_uname = ui_cfg.get("username", "admin")
                expected_pwd = ui_cfg.get("password", "")
                
                if curr_username != expected_uname or curr_password != expected_pwd:
                    self.send_json({"ok": False, "error": "当前账号或密码不正确"}, HTTPStatus.FORBIDDEN)
                    return
                
                try:
                    new_port_int = int(new_port)
                    if not (1 <= new_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "端口范围必须是 1 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return
                
                if not new_suffix or not re.match(r"^[A-Za-z0-9]+$", new_suffix):
                    self.send_json({"ok": False, "error": "安全后缀仅能由英文字母和数字组成"}, HTTPStatus.BAD_REQUEST)
                    return
                old_port = parse_int(ui_cfg.get("port")) or UI_PORT
                old_host = str(ui_cfg.get("host") or UI_HOST or "0.0.0.0")

                # 如果端口发生变化，先检测新端口是否可绑定。
                # 注意：当前端口本来就被当前进程占用，所以端口没变时不能检测。
                if new_port_int != old_port:
                    ok, reason = check_ui_port_available(old_host, new_port_int)
                    if not ok:
                        self.send_json({"ok": False, "error": reason}, HTTPStatus.BAD_REQUEST)
                        return
                ui_cfg["port"] = new_port_int
                ui_cfg["secret_path"] = new_suffix
                if new_username:
                    ui_cfg["username"] = new_username
                if new_password:
                    ui_cfg["password"] = new_password
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                self.send_json({"ok": True, "message": "配置更新成功，系统将在 2 秒内重启..."})
                
                def restart_server():
                    time.sleep(2)
                    print("[系统] 管理后台配置更新，进程即将退出以触发自动重启...", flush=True)
                    os._exit(0)
                
                threading.Thread(target=restart_server, daemon=True).start()
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/check":
            try:
                self.send_json({"ok": True, "message": maintain_valid_nodes(force=True)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        if effective_path == "/api/project_auto_update":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                enabled = payload.get("enabled", True) is not False

                cfg = save_project_update_config(
                    enabled=enabled,
                    last_message="项目自动更新已开启" if enabled else "项目自动更新已关闭",
                )

                self.send_json({"ok": True, **cfg})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/refresh_nodes":
            try:
                threading.Thread(target=maintain_valid_nodes, args=(False,), daemon=True).start()
                self.send_json({"ok": True, "message": "已在后台启动节点更新流程"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_nodes":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                node_ids = payload.get("ids", [])
                tested_nodes = test_multiple_nodes(node_ids)
                self.send_json({"ok": True, "nodes": tested_nodes})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/disconnect":
            try:
                finish_current_ip_uptime("手动断开连接")
                stop_active_openvpn()
                clear_last_connected_node()

                with lock:
                    nodes = read_json(NODES_FILE, [])
                    for item in nodes:
                        item["active"] = False
                    write_json(NODES_FILE, nodes)

                global last_active_ping_time, last_active_latency
                last_active_ping_time = 0.0
                last_active_latency = 0

                set_state(
                    active_openvpn_node_id="",
                    last_check_message="手动断开连接",
                    active_node_latency="无活动连接",
                )

                self.send_json({"ok": True})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

        elif effective_path == "/api/connect":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")

                node_id = str(payload.get("id") or "")

                # 手动点击“切换”也统计：
                # 从点击切换开始，到新节点 IP 质量 / 测速达标结束。
                if node_id:
                    mark_node_switch_start(f"手动切换到 {node_id}")

                self.send_json({
                    "ok": True,
                    "message": connect_node_with_quality_check(node_id)
                })
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

        elif effective_path == "/api/test_node":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                node_id = str(payload.get("id") or "")
                updated_node = test_node_by_id(node_id)
                self.send_json({"ok": True, "node": updated_node})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_proxy":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                if length > 0:
                    self.rfile.read(length)
                result = check_proxy_health()
                if result["ok"]:
                    set_state(
                        proxy_ok=True,
                        proxy_ip=result["ip"],
                        proxy_latency_ms=result["latency_ms"],
                        proxy_error=""
                    )
                else:
                    set_state(
                        proxy_ok=False,
                        proxy_ip="-",
                        proxy_latency_ms=0,
                        proxy_error=result.get("error", "未知错误")
                    )
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

class Tee:
    def __init__(self, file_path: str):
        Path(file_path).parent.mkdir(exist_ok=True, parents=True)
        self.file = open(file_path, "a", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, data: str) -> None:
        self.stdout.write(data)
        self.file.write(data)
        self.file.flush()

    def flush(self) -> None:
        self.stdout.flush()
        self.file.flush()

def main() -> None:
    ensure_dirs()
    kill_existing_openvpn_processes()
    
    log_file = DATA_DIR / "vpngate.log"
    tee = Tee(str(log_file))
    sys.stdout = tee
    sys.stderr = tee

    init_state_on_start()
    threading.Thread(target=proxy_server.start_proxy_server, args=(LOCAL_PROXY_HOST, LOCAL_PROXY_PORT), daemon=True).start()
    
    # Wait for the gateway to officially start
    print("[网关] 正在启动代理网关...", flush=True)
    gateway_ready = False
    for _ in range(30):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(0.5)
            s.connect((LOCAL_PROXY_HOST, LOCAL_PROXY_PORT))
            gateway_ready = True
            break
        except Exception:
            time.sleep(0.5)
        finally:
            try:
                s.close()
            except Exception:
                pass
            
    if gateway_ready:
        print("[网关] 代理网关已成功启动监听，启动同步与检测脚本...", flush=True)
    else:
        print("[警告] 代理网关启动超时，继续执行脚本...", flush=True)



    threading.Thread(target=startup_restore_then_collector, daemon=True).start()
    threading.Thread(target=background_proxy_checker, daemon=True).start()
    threading.Thread(target=active_node_pinger, daemon=True).start()
    threading.Thread(target=project_auto_update_loop, daemon=True).start()

    ui_cfg = load_ui_config()
    ui_host = ui_cfg.get("host", UI_HOST)
    ui_port = int(ui_cfg.get("port", UI_PORT))
    
    print(f"UI: http://{ui_host}:{ui_port}/", flush=True)
    print(f"Proxy: http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}", flush=True)
    ThreadingHTTPServer((ui_host, ui_port), Handler).serve_forever()

if __name__ == "__main__":
    main()