import json
import socketserver
import time
from typing import Optional

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

def load_aimilivpn_proxy_config(env_file: str = "/etc/default/aimilivpn"):
    """
    自动读取 /etc/default/aimilivpn 里的代理配置。
    """
    cfg = {
        "host": "127.0.0.1",
        "port": 7928,
        "auth_enabled": False,
        "username": "",
        "password": "",
    }

    if not os.path.exists(env_file):
        return cfg

    with open(env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            value = value.strip().strip('"').strip("'")

            if key == "LOCAL_PROXY_PORT":
                try:
                    cfg["port"] = int(value)
                except ValueError:
                    pass

            elif key == "PROXY_AUTH_ENABLED":
                cfg["auth_enabled"] = value.lower() in ("1", "true", "yes", "on")

            elif key == "PROXY_USERNAME":
                cfg["username"] = value

            elif key == "PROXY_PASSWORD":
                cfg["password"] = value

    return cfg
class AuthProxyBridgeHandler(socketserver.BaseRequestHandler):
    """
    本地临时 HTTP 代理桥接器。

    Chrome 连接本地无认证代理：
        http://127.0.0.1:随机端口

    该桥接器再连接真实代理：
        http://127.0.0.1:7928

    并自动添加：
        Proxy-Authorization: Basic xxx
    """

    def handle(self):
        client = self.request
        client.settimeout(15)

        upstream_host = self.server.upstream_host
        upstream_port = self.server.upstream_port
        auth_header = self.server.auth_header

        upstream = None

        try:
            first_data = self._recv_header(client)
            if not first_data:
                return

            upstream = socket.create_connection(
                (upstream_host, upstream_port),
                timeout=15
            )

            first_data = self._add_proxy_auth(first_data, auth_header)

            upstream.sendall(first_data)

            self._relay(client, upstream)

        except Exception:
            return

        finally:
            try:
                client.close()
            except Exception:
                pass

            if upstream is not None:
                try:
                    upstream.close()
                except Exception:
                    pass

    @staticmethod
    def _recv_header(sock):
        data = b""

        while b"\r\n\r\n" not in data:
            chunk = sock.recv(8192)

            if not chunk:
                break

            data += chunk

            if len(data) > 1024 * 1024:
                break

        return data

    @staticmethod
    def _add_proxy_auth(data: bytes, auth_header: bytes) -> bytes:
        if b"\r\n\r\n" not in data:
            return data

        header, body = data.split(b"\r\n\r\n", 1)
        lines = header.split(b"\r\n")

        if not lines:
            return data

        request_line = lines[0]

        new_headers = []

        for line in lines[1:]:
            lower = line.lower()

            # 删除旧的代理认证头，避免重复
            if lower.startswith(b"proxy-authorization:"):
                continue

            new_headers.append(line)

        rebuilt = b"\r\n".join(
            [request_line, auth_header] + new_headers
        ) + b"\r\n\r\n" + body

        return rebuilt

    @staticmethod
    def _relay(sock1, sock2):
        sockets = [sock1, sock2]

        while True:
            readable, _, error = select.select(sockets, [], sockets, 60)

            if error:
                break

            if not readable:
                break

            for s in readable:
                try:
                    data = s.recv(8192)

                    if not data:
                        return

                    if s is sock1:
                        sock2.sendall(data)
                    else:
                        sock1.sendall(data)

                except Exception:
                    return


class ThreadingProxyBridgeServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_auth_proxy_bridge(
        upstream_host: str,
        upstream_port: int,
        username: str,
        password: str,
):
    """
    启动本地临时代理桥接器。
    返回：
        server 对象
        Chrome 可使用的 proxy_server 地址
    """
    token = base64.b64encode(
        f"{username}:{password}".encode("utf-8")
    ).decode("ascii")

    auth_header = f"Proxy-Authorization: Basic {token}".encode("ascii")

    server = ThreadingProxyBridgeServer(
        ("127.0.0.1", 0),
        AuthProxyBridgeHandler
    )

    server.upstream_host = upstream_host
    server.upstream_port = upstream_port
    server.auth_header = auth_header

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True
    )
    thread.start()

    local_port = server.server_address[1]
    proxy_server = f"http://127.0.0.1:{local_port}"

    return server, proxy_server

def create_driver(
        headless: bool = True,
        proxy_server: Optional[str] = None,
):
    options = Options()

    if headless:
        options.add_argument("--headless=new")
        options.add_argument("--window-size=1920,1080")
    else:
        options.add_argument("--start-maximized")

    options.add_argument("--disable-gpu")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--no-sandbox")

    # 让 Chrome 走指定代理
    if proxy_server:
        options.add_argument(f"--proxy-server={proxy_server}")

    return webdriver.Chrome(options=options)

def query_ip(driver, ip: str, timeout: int = 30):
    wait = WebDriverWait(driver, timeout)

    # 1. 等输入框可点击
    ip_input = wait.until(
        EC.element_to_be_clickable(
            (By.CSS_SELECTOR, "input[placeholder='请输入查询IP']")
        )
    )

    # 2. 清空原来的 IP
    ip_input.click()
    ip_input.send_keys(Keys.CONTROL, "a")
    ip_input.send_keys(Keys.BACKSPACE)

    # 3. 输入新的 IP
    ip_input.send_keys(ip)

    # 4. 等待输入框 value 真的变成目标 IP
    wait.until(
        lambda d: d.execute_script(
            "return arguments[0].value;", ip_input
        ) == ip
    )

    # 5. 找输入框后面的查询按钮
    search_btn = wait.until(
        lambda d: d.execute_script("""
            const input = document.querySelector("input[placeholder='请输入查询IP']");
            if (!input) return null;

            const all = Array.from(
                document.querySelectorAll("input[placeholder='请输入查询IP'], button")
            );

            const inputIndex = all.indexOf(input);
            if (inputIndex === -1) return null;

            const buttons = all.slice(inputIndex + 1).filter(el => {
                return el.tagName === "BUTTON"
                    && el.offsetWidth > 0
                    && el.offsetHeight > 0
                    && !el.disabled;
            });

            for (const btn of buttons) {
                if ((btn.innerText || "").includes("查询")) {
                    return btn;
                }
            }

            return buttons[0] || null;
        """)
    )

    # 6. 点击查询按钮
    driver.execute_script("arguments[0].click();", search_btn)


def wait_result_ip(driver, ip: str, timeout: int = 60) -> bool:
    """
    等待页面结果区域出现当前查询的 IP。
    目的：避免第二次查询时直接读到上一次的 vpn 结果。
    """
    wait = WebDriverWait(driver, timeout)

    js = r"""
    const targetIp = arguments[0];

    const elements = Array.from(document.querySelectorAll("span, div, p"));

    for (const el of elements) {
        const rect = el.getBoundingClientRect();
        const text = (el.innerText || el.textContent || "").trim();

        if (
            text &&
            text.includes(targetIp) &&
            rect.width > 0 &&
            rect.height > 0
        ) {
            return true;
        }
    }

    return false;
    """

    try:
        return wait.until(
            lambda d: d.execute_script(js, ip)
        )
    except TimeoutException:
        return False


def get_field_value(driver, key: str, timeout: int = 60) -> Optional[str]:
    """
    根据左侧字段名，例如 vpn，获取同一行右侧的值，例如 true。
    找不到返回 None。
    """
    wait = WebDriverWait(driver, timeout)

    js = r"""
    const targetKey = arguments[0];

    const clean = (s) => {
        return (s || "")
            .replace(/[“”]/g, '"')
            .replace(/\s+/g, "")
            .replace(/[":：,，]/g, "")
            .toLowerCase();
    };

    const key = clean(targetKey);
    const spans = Array.from(document.querySelectorAll("span"));

    let keySpan = null;

    for (const span of spans) {
        const text = clean(span.innerText || span.textContent);

        if (text === key) {
            keySpan = span;
            break;
        }
    }

    if (!keySpan) {
        return null;
    }

    const keyRect = keySpan.getBoundingClientRect();

    const candidates = spans
        .filter(span => span !== keySpan)
        .map(span => {
            const rect = span.getBoundingClientRect();
            const text = (span.innerText || span.textContent || "").trim();

            return {
                span,
                text,
                rect,
                topDiff: Math.abs(rect.top - keyRect.top),
                leftDiff: rect.left - keyRect.right
            };
        })
        .filter(item => {
            return item.text
                && item.rect.width > 0
                && item.rect.height > 0
                && item.leftDiff > 0
                && item.topDiff < 12;
        })
        .sort((a, b) => a.leftDiff - b.leftDiff);

    if (candidates.length > 0) {
        return candidates[0].text;
    }

    return null;
    """

    try:
        return wait.until(
            lambda d: d.execute_script(js, key)
        )
    except TimeoutException:
        return None


def parse_bool(value: Optional[str]) -> Optional[bool]:
    """
    把页面里的 true / false 字符串转成 Python 布尔值。
    其他情况返回 None。
    """
    if value is None:
        return None

    value = value.strip().lower()

    if value == "true":
        return True

    if value == "false":
        return False

    return None


def query_single_ip_vpn(
        driver,
        ip: str,
        query_timeout: int = 30,
        result_timeout: int = 60,
) -> Optional[bool]:
    """
    查询单个 IP 的 vpn 字段。
    返回：
        True
        False
        None
    """
    try:
        query_ip(driver, ip, timeout=query_timeout)

        # 先等当前 IP 的结果出来，避免读到旧结果
        if not wait_result_ip(driver, ip, timeout=result_timeout):
            return None

        vpn_value = get_field_value(driver, "vpn", timeout=result_timeout)

        return parse_bool(vpn_value)

    except TimeoutException:
        return None

    except WebDriverException:
        return None

    except Exception:
        return None


def get_ip_vpn_status(
        *ips: str,
        headless: bool = True,
        page_load_timeout: int = 30,
        query_timeout: int = 30,
        result_timeout: int = 60,
) -> str:
    """
    批量查询 ipipseek 的 vpn 字段。

    访问 ipipseek.com 的浏览器流量会自动走：
        127.0.0.1:7928

    并自动读取：
        /etc/default/aimilivpn

    返回 JSON 字符串：
        {
            "60.113.181.155": true,
            "138.64.65.244": false,
            "1.1.1.1": null
        }
    """

    results = {}
    driver = None
    bridge_server = None

    try:
        proxy_cfg = load_aimilivpn_proxy_config()

        upstream_host = "127.0.0.1"
        upstream_port = int(proxy_cfg["port"])

        # 如果开启了代理认证，则启动本地临时桥接代理
        if proxy_cfg["auth_enabled"]:
            username = proxy_cfg["username"]
            password = proxy_cfg["password"]

            if not username or not password:
                for ip in ips:
                    results[ip] = None
                return json.dumps(results, ensure_ascii=False)

            bridge_server, chrome_proxy_server = start_auth_proxy_bridge(
                upstream_host=upstream_host,
                upstream_port=upstream_port,
                username=username,
                password=password,
            )

        else:
            # 没有认证，Chrome 直接走 127.0.0.1:7928
            chrome_proxy_server = f"http://{upstream_host}:{upstream_port}"

        driver = create_driver(
            headless=headless,
            proxy_server=chrome_proxy_server,
        )

        driver.set_page_load_timeout(page_load_timeout)

        try:
            driver.get("https://www.ipipseek.com/")
            driver.refresh()
        except TimeoutException:
            pass

        for ip in ips:
            results[ip] = query_single_ip_vpn(
                driver,
                ip,
                query_timeout=query_timeout,
                result_timeout=result_timeout,
            )

            time.sleep(5)

        return json.dumps(results, ensure_ascii=False)

    except Exception:
        for ip in ips:
            results[ip] = None

        return json.dumps(results, ensure_ascii=False)

    finally:
        if driver is not None:
            driver.quit()

        if bridge_server is not None:
            try:
                bridge_server.shutdown()
                bridge_server.server_close()
            except Exception:
                pass

if __name__ == "__main__":
    result = get_ip_vpn_status(
        "60.113.181.155",
        "138.64.65.244"
    )

    print(result)