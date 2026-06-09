import json
import subprocess
import time
from typing import Optional
import os
from urllib.parse import quote
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

def get_aimilivpn_proxy_server(
        env_file: str = "/etc/default/aimilivpn",
        scheme: str = "http",
) -> str:
    """
    从 /etc/default/aimilivpn 自动读取代理端口、用户名、密码。
    返回：
        socks5://user:pass@127.0.0.1:7928
    """

    port = "7928"
    auth_enabled = False
    username = ""
    password = ""

    if os.path.exists(env_file):
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()

                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                value = value.strip().strip('"').strip("'")

                if key == "LOCAL_PROXY_PORT":
                    port = value

                elif key == "PROXY_AUTH_ENABLED":
                    auth_enabled = value.lower() in ("1", "true", "yes", "on")

                elif key == "PROXY_USERNAME":
                    username = value

                elif key == "PROXY_PASSWORD":
                    password = value

    if auth_enabled and username and password:
        username = quote(username, safe="")
        password = quote(password, safe="")
        return f"{scheme}://{username}:{password}@127.0.0.1:{port}"

    return f"{scheme}://127.0.0.1:{port}"

def create_driver(
        headless: bool = True,
        proxy_server: Optional[str] = None,
        debug: bool = False,
        debug_port: int = 9222,
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

    if proxy_server:
        options.add_argument(f"--proxy-server={proxy_server}")

    # 开启无头 Chrome 远程调试
    if debug:
        options.add_argument(f"--remote-debugging-port={debug_port}")

        # 推荐只监听本机，避免 9222 暴露到公网
        options.add_argument("--remote-debugging-address=127.0.0.1")

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
def test_proxy_alive(
        proxy_server: Optional[str] = None,
        test_url: str = "https://www.ipipseek.com/",
        timeout: int = 20,
) -> dict:
    """
    测试代理是否可用，并返回耗时。

    返回示例：
        {
            "ok": True,
            "http_code": "200",
            "time_total": 1.234,
            "proxy": "socks5://xxx:xxx@127.0.0.1:7928",
            "error": ""
        }
    """

    if proxy_server is None:
        proxy_server = get_aimilivpn_proxy_server()

    cmd = [
        "curl",
        "-x", proxy_server,
        "-L",
        "-s",
        "-o", "/dev/null",
        "-w", "%{http_code} %{time_total}",
        "--connect-timeout", str(timeout),
        "--max-time", str(timeout),
        test_url,
    ]

    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )

        output = res.stdout.strip()

        if res.returncode != 0:
            return {
                "ok": False,
                "http_code": "",
                "time_total": None,
                "proxy": proxy_server,
                "error": res.stderr.strip() or output,
            }

        parts = output.split()

        http_code = parts[0] if len(parts) >= 1 else ""
        time_total = float(parts[1]) if len(parts) >= 2 else None

        return {
            "ok": http_code.startswith("2") or http_code.startswith("3"),
            "http_code": http_code,
            "time_total": time_total,
            "proxy": proxy_server,
            "error": "",
        }

    except Exception as e:
        return {
            "ok": False,
            "http_code": "",
            "time_total": None,
            "proxy": proxy_server,
            "error": repr(e),
        }


def get_ip_vpn_status(
        *ips: str,
        headless: bool = True,
        page_load_timeout: int = 30,
        query_timeout: int = 30,
        result_timeout: int = 60,
) -> str:
    """
    批量查询 ipipseek 的 vpn 字段。

    调用示例：
        result = get_ip_vpn_status("60.113.181.155", "138.64.65.244")

    返回 JSON 字符串：
        {
            "60.113.181.155": true,
            "138.64.65.244": false,
            "1.1.1.1": null
        }

    注意：
        Python 内部是 True / False / None
        JSON 输出后是 true / false / null
    """

    results = {}
    driver = None

    try:
        proxy_server = get_aimilivpn_proxy_server()

        driver = create_driver(
            headless=headless,
            proxy_server=proxy_server,
            debug=True,
            debug_port=9222,
        )
        driver.set_page_load_timeout(page_load_timeout)

        try:
            driver.get("https://www.ipipseek.com/")
            driver.refresh()
            driver.refresh()
        except TimeoutException:
            # 页面加载超时，但 DOM 可能已经可用，所以继续执行
            pass

        for ip in ips:

            results[ip] = query_single_ip_vpn(
                driver,
                ip,
                query_timeout=query_timeout,
                result_timeout=result_timeout,
            )
            time.sleep(10)

        return json.dumps(results, ensure_ascii=False)

    except Exception:
        return json.dumps(results, ensure_ascii=False)

    finally:
        if driver is not None:
            driver.quit()


if __name__ == "__main__":
    proxy_server = get_aimilivpn_proxy_server()

    proxy_test = test_proxy_alive(
        proxy_server=proxy_server,
        test_url="https://www.ipipseek.com/",
        timeout=20,
    )

    print("代理测试结果：", json.dumps(proxy_test, ensure_ascii=False))

    if not proxy_test["ok"]:
        print("代理不可用，停止查询")
        exit(1)

    print(f"代理可用，耗时：{proxy_test['time_total']} 秒")

    result = get_ip_vpn_status(
        "60.113.181.155",
        "138.64.65.244"
    )

    print(result)