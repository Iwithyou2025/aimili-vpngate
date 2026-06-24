import os
import time

from playwright.sync_api import (
    sync_playwright,
    TimeoutError as PlaywrightTimeoutError,
    Error as PlaywrightError,
    expect,
)
import json
import sys
from typing import Optional


def create_page(
        playwright,
        headless: bool = True,
        proxy_server: Optional[str] = None,
):
    """
    创建 Chromium 浏览器、上下文和页面。

    参数说明：
        headless:
            True  = 无头模式
            False = 有头模式

        proxy_server:
            代理地址。
            只要传入代理地址，无头和有头模式都会走代理。
            如果不想走代理，传 None。
    """

    # 1. Chromium 启动参数
    launch_args = [
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--no-sandbox",
    ]

    # 2. 有头模式下最大化窗口
    if not headless:
        launch_args.append("--start-maximized")

    # 3. 设置代理
    #    这里不再判断 headless，所以无头/有头都会走代理


    proxy_server = resolve_proxy_server(proxy_server)
    proxy = None
    if proxy_server:
        proxy = {
            "server": proxy_server,
        }

    # 4. 启动浏览器
    browser = playwright.chromium.launch(
        headless=headless,
        args=launch_args,
        proxy=proxy,
    )

    # 5. 创建浏览器上下文
    #    无头模式指定窗口尺寸
    #    有头模式使用真实窗口尺寸
    if headless:
        context = browser.new_context(
            viewport={
                "width": 1920,
                "height": 1080,
            }
        )
    else:
        context = browser.new_context(
            no_viewport=True,
        )

    # 6. 创建页面
    page = context.new_page()

    return browser, context, page


def query_ip(page, ip: str):
    """
    在 ipipseek 页面输入 IP，并点击查询按钮。

    注意：
        这里不使用 time.sleep。
        输入框 fill、按钮 click 都使用 Playwright 自带自动等待。
    """

    # 1. 找到 IP 输入框
    #    Playwright 会自动等待元素可用。
    ip_input = page.get_by_placeholder("请输入查询IP").first

    # 2. 清空并输入 IP
    #    fill() 本身会自动等待输入框可见、可编辑。
    ip_input.fill(ip)

    # 3. 确认输入框的值已经变成目标 IP
    #    expect 会自动等待，不需要手动 sleep。
    expect(ip_input).to_have_value(ip)

    # 4. 找到页面中第一个 text=查询 的元素
    #    按你的要求，直接使用 text=查询。
    search_btn = page.locator("text=查询").first

    # 5. 点击查询
    #    click() 本身会自动等待元素可见、稳定、可点击。
    search_btn.click()


def wait_result_ip(page, ip: str) -> bool:
    """
    等待页面中出现当前查询的 IP。

    这个等待不是人工 sleep，而是 Playwright 的自动等待。
    如果页面一直没有出现当前 IP，说明查询结果没有正常出来。
    """

    try:
        # 等待页面上出现当前 IP 文本
        # 如果结果区更新成功，页面应该能看到这个 IP。
        expect(
            page.get_by_text(ip).first
        ).to_be_visible()

        return True

    except Exception:
        return False


def resolve_proxy_server(proxy_server: Optional[str] = None) -> Optional[str]:
    """
    解析 Playwright 浏览器代理地址。

    优先级：
        1. 函数显式传入 proxy_server
        2. 环境变量 IPIPSEEK_PROXY_SERVER
        3. 默认 http://127.0.0.1:7777

    如果传入空字符串或环境变量为空，则视为不使用代理。
    """

    if proxy_server is not None:
        proxy_server = proxy_server.strip()
        return proxy_server or None

    proxy_server = os.environ.get(
        "IPIPSEEK_PROXY_SERVER",
        "http://127.0.0.1:7777",
    ).strip()

    return proxy_server or None


def parse_bool(value: Optional[str]) -> Optional[bool]:
    """
    把页面里的 true / false 字符串转成 Python 布尔值。

    返回：
        "true"  -> True
        "false" -> False
        其他    -> None
    """

    # 1. 没有读取到字段值
    if value is None:
        return None

    # 2. 统一转成小写
    value = value.strip().lower()

    # 3. 转换 true
    if value == "true":
        return True

    # 4. 转换 false
    if value == "false":
        return False

    # 5. 其他内容都视为未知
    return None

def query_single_ip_vpn(page, ip: str) -> Optional[bool]:
    """
    查询单个 IP 的 vpn 字段。

    成功时返回：
        True
        False

    失败时返回：
        None

    规则：
        1. 查询前，先等待输入框自动出现一个 IP，最多等 15 秒
        2. 如果 15 秒内出现了，就清空，再输入自己的 IP
        3. 如果超过 15 秒还没出现，也直接输入自己的 IP
        4. 查询后，15 秒内找到 true / false，立即 return
        5. 查询后超过 15 秒没有明确结果，return None
    """

    try:
        ip = ip.strip()
        if not ip:
            return None

        # 1. 找到 IP 输入框
        ip_input = page.get_by_placeholder("请输入查询IP").first

        # 2. 查询前：等待输入框里自动出现一个 IP
        wait_input_deadline = time.monotonic() + 15

        while time.monotonic() < wait_input_deadline:
            try:
                old_value = ip_input.input_value(timeout=500).strip()

                # 输入框里已经出现了一个 IP
                # 这个 IP 不是我们要查的，所以后面会清掉
                if old_value:
                    break

            except Exception:
                pass

            page.wait_for_timeout(200)

        # 3. 无论上面是否等到旧 IP，这里都清空并输入自己的 IP
        ip_input.fill("")
        ip_input.fill(ip)

        # 4. 确认输入框的值已经变成目标 IP
        expect(ip_input).to_have_value(ip)

        # 5. 点击查询按钮
        search_btn = page.locator("text=查询").first
        search_btn.click()

        # 6. 查询后：等待结果，最多 15 秒
        result_deadline = time.monotonic() + 30

        while time.monotonic() < result_deadline:

            # 6.1 先确认页面中是否已经出现当前 IP
            #     避免读取到上一次查询的旧结果
            try:
                if not page.get_by_text(ip).first.is_visible():
                    page.wait_for_timeout(200)
                    continue
            except Exception:
                page.wait_for_timeout(200)
                continue

            # 6.2 当前 IP 已出现，再读取 vpn 字段
            vpn_values = page.evaluate(
                r"""
                (targetKey) => {
                    const clean = (s) => {
                        return (s || "")
                            .replace(/[“”]/g, '"')
                            .replace(/\s+/g, "")
                            .replace(/[":：,，]/g, "")
                            .toLowerCase();
                    };
            
                    const key = clean(targetKey);
                    const spans = Array.from(document.querySelectorAll("span"));
            
                    // 1. 找到页面上所有可见的 vpn 字段
                    const keySpans = spans.filter(span => {
                        const rect = span.getBoundingClientRect();
                        const text = clean(span.innerText || span.textContent);
            
                        return text === key
                            && rect.width > 0
                            && rect.height > 0;
                    });
            
                    const values = [];
            
                    // 2. 对每一个 vpn 字段，读取同一行右侧最近的值
                    for (const keySpan of keySpans) {
                        const keyRect = keySpan.getBoundingClientRect();
            
                        const candidates = spans
                            .filter(span => span !== keySpan)
                            .map(span => {
                                const rect = span.getBoundingClientRect();
                                const text = (span.innerText || span.textContent || "").trim();
            
                                return {
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
                            values.push(candidates[0].text);
                        }
                    }
            
                    return values;
                }
                """,
                "vpn",
            )

            # 把所有 vpn 值转成 Python 布尔值
            parsed_values = [
                parse_bool(value)
                for value in vpn_values
            ]

            # 去掉没有明确解析出来的值
            known_values = [
                value
                for value in parsed_values
                if value is True or value is False
            ]

            # 规则：
            # 1. 只要任意一个 vpn=true，立即返回 True
            if any(value is True for value in known_values):
                return True

            # 2. 只有读取到至少一个明确值，并且全部都是 false，才返回 False
            if known_values and all(value is False for value in known_values):
                return False

            # 6.5 还没有结果，继续等一小段时间
            page.wait_for_timeout(200)

        # 7. 超过 15 秒仍然没有 true / false
        return None

    except PlaywrightTimeoutError:
        return None

    except PlaywrightError:
        return PlaywrightError

    except Exception:
        return None


def get_ip_vpn_status(
        *ips: str,
        headless: bool = True,
        proxy_server: Optional[str] = None,
) -> str:
    """
    批量查询多个 IP 的 vpn 状态。

    返回格式固定为：
        {
            "60.113.181.155": true,
            "39.111.179.36": null
        }

    注意：
        不再返回 error/message/failed_ip。
        任意异常都只会让对应 IP 返回 null。
    """


    # 3. 设置代理
    #    这里不再判断 headless，所以无头/有头都会走代理
    proxy_server = resolve_proxy_server(proxy_server)

    # 2. 初始化结果字典
    results = {}

    try:
        with sync_playwright() as playwright:
            browser = None
            context = None

            try:
                # 2. 创建浏览器页面
                browser, context, page = create_page(
                    playwright,
                    headless=headless,
                    proxy_server=proxy_server,
                )

                # 3. 打开 ipipseek 页面
                #    goto 会使用 Playwright 默认导航超时时间。
                #    这里不手动 sleep。
                page.goto(
                    "https://www.ipipseek.com/",
                    wait_until="domcontentloaded"
                )



                # 4.逐个查询 IP
                #    改成 while 循环：
                #    - 每个 IP 查询到 True / False 后就结束该 IP
                #    - 每个 IP 超过 30 秒仍然不是 True / False，则返回 None
                #    - 所有 IP 都结束后，退出 while

                pending_ips = []

                # 4.1 先整理 IP，并初始化结果
                for ip in ips:
                    ip = ip.strip()

                    if not ip:
                        continue

                    results[ip] = None
                    pending_ips.append(ip)

                # 4.2 给每个 IP 设置独立 30 秒超时时间
                deadlines = {
                    ip: time.monotonic() + 60
                    for ip in pending_ips
                }

                # 4.3 while 循环查询
                while pending_ips:
                    for ip in pending_ips[:]:
                        # 当前 IP 已超过 30 秒，还没得到 True / False
                        if time.monotonic() >= deadlines[ip]:
                            results[ip] = None
                            pending_ips.remove(ip)
                            continue

                        # 查询当前 IP
                        value = query_single_ip_vpn(
                            page,
                            ip,
                        )

                        # 只有明确返回 True / False，才认为该 IP 查询结束
                        if value is True or value is False:
                            results[ip] = value
                            pending_ips.remove(ip)
                            continue

                    # 如果所有 IP 都已经返回 True / False，或者超时结束，就退出 while
                    if not pending_ips:
                        break


                # 5. 返回 JSON 字符串
                return json.dumps(
                    results,
                    ensure_ascii=False,
                )

            finally:
                # 6. 关闭上下文
                if context is not None:
                    context.close()

                # 7. 关闭浏览器
                if browser is not None:
                    browser.close()

    except Exception as exc:
        # 8. 如果浏览器启动、页面打开等全局流程失败
        #    所有 IP 统一返回 None，但把真实错误打印到 stderr，方便服务端排查。
        print(f"[PlaywrightError] {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)

        for ip in ips:
            ip = ip.strip()
            if ip:
                results[ip] = None

        return json.dumps(
            results,
            ensure_ascii=False,
        )


if __name__ == "__main__":
    proxy_server = None
    ips = []

    args = sys.argv[1:]
    i = 0

    while i < len(args):
        arg = args[i].strip()

        if not arg:
            i += 1
            continue

        if arg == "--proxy" and i + 1 < len(args):
            proxy_server = args[i + 1].strip()
            i += 2
            continue

        if arg.startswith("--proxy="):
            proxy_server = arg.split("=", 1)[1].strip()
            i += 1
            continue

        ips.append(arg)
        i += 1

    # 如果命令行没有传 IP，就使用默认测试 IP
    if not ips:
        ips = [
            "60.113.181.155"
        ]

    result = get_ip_vpn_status(
        *ips,
        proxy_server=proxy_server,
    )

    print(result)