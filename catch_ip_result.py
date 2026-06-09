
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import json
import sys
import time
from typing import Optional

def create_driver(headless: bool = True):
    options = Options()

    if headless:
        # Chrome 新版无头模式
        options.add_argument("--headless=new")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--proxy-server=http://127.0.0.1:7928")
    else:
        options.add_argument("--start-maximized")

    # 提高无头模式稳定性
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--no-sandbox")

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
        driver = create_driver(headless=headless)
        driver.set_page_load_timeout(page_load_timeout)

        try:
            driver.get("https://www.ipipseek.com/")
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
            time.sleep(5)

        return json.dumps(results, ensure_ascii=False)

    except Exception:
        # 如果浏览器初始化或打开页面失败，所有 IP 返回 None
        for ip in ips:
            results[ip] = None

        return json.dumps(results, ensure_ascii=False)

    finally:
        if driver is not None:
            driver.quit()



if __name__ == "__main__":
    ips = [
        arg.strip()
        for arg in sys.argv[1:]
        if arg.strip()
    ]

    # 不传参数时保留原来的测试 IP，方便你手动调试
    if not ips:
        ips = [
            "60.113.181.155",
            "138.64.65.244",
        ]

    result = get_ip_vpn_status(*ips)
    print(result)