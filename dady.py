#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import logging
import threading
import queue
import re
import requests
import json
import os
import tempfile
import zipfile

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.chrome.service import Service

# ===================== НАСТРОЙКИ =====================
EMAILS_FILE = "emails.txt"
OUTPUT_FILE = "accounts.txt"
PROXIES_FILE = "proxy.txt"
API_TOKEN = "kv3wxML6Ibxo2ok1SPJCVonQIM09TWDgqjf0_S3BcVWIfvZVx9XlqcioEKn6qiXt"
API_URL = "https://firstmail.ltd/api/v1/email/messages"
THREADS = 1
DELAY = 5
HEADLESS = False
# =====================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("AutoRegister")


def create_proxy_extension(proxy_string):
    """Создаёт расширение для SOCKS5 с авторизацией. Возвращает путь к каталогу или None."""
    if not proxy_string.startswith('socks5://'):
        return None

    rest = proxy_string[8:]
    if '@' not in rest:
        # Нет авторизации, можно использовать --proxy-server напрямую
        return None

    try:
        auth, host_port = rest.split('@', 1)
        user, pwd = auth.split(':', 1)
        if ':' in host_port:
            host, port = host_port.split(':', 1)
        else:
            host = host_port
            port = '1080'

        extension_dir = tempfile.mkdtemp()

        manifest = {
            "version": "1.0.0",
            "manifest_version": 2,
            "name": "Chrome Proxy",
            "permissions": [
                "proxy", "tabs", "unlimitedStorage", "storage",
                "<all_urls>", "webRequest", "webRequestBlocking"
            ],
            "background": {"scripts": ["background.js"]},
            "minimum_chrome_version": "22.0.0"
        }
        with open(os.path.join(extension_dir, "manifest.json"), "w") as f:
            json.dump(manifest, f)

        bg_js = f"""
        var config = {{
            mode: "fixed_servers",
            rules: {{
                singleProxy: {{
                    scheme: "socks5",
                    host: "{host}",
                    port: parseInt({port})
                }},
                bypassList: ["localhost"]
            }}
        }};
        chrome.proxy.settings.set({{value: config, scope: "regular"}}, function() {{}});
        chrome.webRequest.onAuthRequired.addListener(
            function(details) {{
                return {{
                    authCredentials: {{
                        username: "{user}",
                        password: "{pwd}"
                    }}
                }};
            }},
            {{urls: ["<all_urls>"]}},
            ['blocking']
        );
        """
        with open(os.path.join(extension_dir, "background.js"), "w") as f:
            f.write(bg_js)

        return extension_dir
    except Exception as e:
        logger.warning(f"Не удалось создать расширение для прокси {proxy_string}: {e}")
        return None


def get_verification_code_api(email_address, email_password, sender_domain="tm.openai.com", timeout=120):
    headers = {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "email": email_address,
        "password": email_password,
        "limit": 10,
        "folder": "INBOX"
    }
    start_time = time.time()
    while time.time() - start_time < timeout:
        logger.info(f"Проверка писем для {email_address}...")
        try:
            response = requests.post(API_URL, headers=headers, json=payload)
            if response.status_code != 200:
                logger.error(f"Ошибка API: {response.status_code}")
                time.sleep(10)
                continue
            data = response.json()
            if not data.get("success"):
                logger.info(f"Нет писем для {email_address}, ожидаем...")
                time.sleep(10)
                continue
            messages = data.get("data", {}).get("messages")
            if not messages:
                logger.info(f"Нет писем для {email_address}, ожидаем...")
                time.sleep(10)
                continue
            for msg in messages:
                from_addr = msg.get("from", [])
                if isinstance(from_addr, list) and from_addr:
                    from_str = str(from_addr[0])
                else:
                    from_str = str(from_addr)
                if sender_domain in from_str:
                    subject = msg.get("subject", "")
                    body = msg.get("body", "")
                    full_text = subject + " " + body
                    match = re.search(r"\b(\d{6})\b", full_text)
                    if not match:
                        match = re.search(r"\b(\d{4,6})\b", full_text)
                    if match:
                        code = match.group(1)
                        logger.info(f"Найден код {code} для {email_address}")
                        return code
            time.sleep(10)
        except Exception as e:
            logger.error(f"Ошибка API для {email_address}: {e}")
            time.sleep(10)
    logger.error(f"Письмо с кодом не пришло за {timeout} секунд для {email_address}")
    return None


def save_debug_info(driver, prefix):
    try:
        driver.save_screenshot(f"{prefix}_screenshot.png")
        with open(f"{prefix}_page.html", "w", encoding="utf-8") as f:
            f.write(driver.page_source)
        logger.info(f"Отладочные файлы сохранены: {prefix}_screenshot.png и {prefix}_page.html")
    except Exception as e:
        logger.warning(f"Не удалось сохранить отладочные файлы: {e}")


def register_account(email, password, proxy):
    driver = None
    proxy_extension_dir = None
    try:
        options = webdriver.ChromeOptions()
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option("useAutomationExtension", False)
        if HEADLESS:
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")

        # Обработка прокси
        if proxy:
            # Попробуем создать расширение для SOCKS5 с авторизацией
            proxy_extension_dir = create_proxy_extension(proxy)
            if proxy_extension_dir:
                options.add_argument(f"--load-extension={proxy_extension_dir}")
                logger.info(f"Используется SOCKS5 прокси с авторизацией (расширение)")
            elif proxy.startswith('socks5://') and '@' in proxy:
                # SOCKS5 с авторизацией, но расширение не создалось — пропускаем
                logger.error(f"Не удалось настроить SOCKS5 прокси с авторизацией: {proxy}. Прокси не используется.")
            else:
                # HTTP/HTTPS/SOCKS5 без авторизации
                options.add_argument(f"--proxy-server={proxy}")
                logger.info(f"Используется прокси (стандартный метод): {proxy}")

        service = Service("/usr/bin/chromedriver")
        driver = webdriver.Chrome(service=service, options=options)

        driver.execute_script(
            "Object.defineProperty(navigator, 'webdriver', "
            "{get: () => undefined})"
        )

        driver.get("https://chatgpt.com")
        logger.info("Открыта страница chatgpt.com")
        wait = WebDriverWait(driver, 20)

        # Нажать "Log in"
        login_clicked = False
        login_xpaths = [
            "//button[contains(text(), 'Log in')]",
            "//button[contains(text(), 'Войти')]",
            "//a[contains(text(), 'Log in')]",
            "//a[contains(text(), 'Войти')]",
            "//button[@data-testid='login-button']"
        ]
        for xp in login_xpaths:
            try:
                btn = driver.find_element(By.XPATH, xp)
                if btn.is_displayed() and btn.is_enabled():
                    btn.click()
                    logger.info("Нажата кнопка Log in")
                    login_clicked = True
                    break
            except:
                continue
        if not login_clicked:
            logger.warning("Не найдена кнопка Log in")

        time.sleep(2)

        # Поле email
        try:
            email_field = wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='email']"))
            )
        except TimeoutException:
            logger.error("Поле email не появилось")
            save_debug_info(driver, "debug_no_email_field")
            return False

        email_field.clear()
        email_field.send_keys(email)
        logger.info(f"Email {email} введён")

        continue_btn = wait.until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']"))
        )
        continue_btn.click()
        logger.info("Нажата кнопка Continue (email)")

        # Проверка на уже зарегистрированный email
        try:
            error_msg = driver.find_element(By.XPATH, "//div[contains(text(), 'already registered')]")
            if error_msg.is_displayed():
                logger.info(f"Email {email} уже зарегистрирован, выполняем вход")
                password_field = wait.until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='password']"))
                )
                password_field.clear()
                password_field.send_keys(password)
                continue_btn2 = wait.until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']"))
                )
                continue_btn2.click()
                logger.info("Вход выполнен")
                time.sleep(3)
                with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                    f.write(f"{email}:{password}\n")
                return True
        except:
            pass

        # Регистрация нового аккаунта
        password_field = wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='password']"))
        )
        password_field.clear()
        password_field.send_keys(password)
        logger.info("Пароль введён")

        continue_btn2 = wait.until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']"))
        )
        continue_btn2.click()
        logger.info("Нажата кнопка Continue (пароль)")

        code_field = wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='code']"))
        )
        logger.info("Поле для кода появилось")

        code = get_verification_code_api(email, password, sender_domain="tm.openai.com", timeout=120)
        if not code:
            logger.error(f"Не удалось получить код для {email}")
            return False

        code_field.clear()
        code_field.send_keys(code)
        logger.info(f"Код {code} введён")

        continue_btn3 = wait.until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']"))
        )
        continue_btn3.click()
        logger.info("Нажата кнопка Continue (код)")

        time.sleep(3)

        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(f"{email}:{password}\n")
        logger.info(f"Аккаунт {email} успешно зарегистрирован и сохранён")
        return True

    except TimeoutException as e:
        logger.error(f"Таймаут при обработке {email}: {e}")
        if driver:
            save_debug_info(driver, f"debug_timeout_{email.replace('@', '_')}")
        return False
    except Exception as e:
        logger.error(f"Ошибка при регистрации {email}: {e}")
        if driver:
            save_debug_info(driver, f"debug_error_{email.replace('@', '_')}")
        return False
    finally:
        if driver:
            driver.quit()
        if proxy_extension_dir and os.path.exists(proxy_extension_dir):
            try:
                import shutil
                shutil.rmtree(proxy_extension_dir)
            except:
                pass


def read_accounts():
    accounts = []
    try:
        with open(EMAILS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and ":" in line:
                    email, pwd = line.split(":", 1)
                    accounts.append((email, pwd))
    except FileNotFoundError:
        logger.error(f"Файл {EMAILS_FILE} не найден!")
        sys.exit(1)
    return accounts


def read_proxies():
    proxies = []
    if PROXIES_FILE:
        try:
            with open(PROXIES_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        proxies.append(line)
        except FileNotFoundError:
            logger.error(f"Файл {PROXIES_FILE} не найден!")
            sys.exit(1)
    return proxies


def main():
    try:
        import requests
    except ImportError:
        logger.error("Установите requests: pip install requests")
        sys.exit(1)

    accounts = read_accounts()
    if not accounts:
        logger.error("Файл с аккаунтами пуст или имеет неверный формат.")
        sys.exit(1)

    proxies = read_proxies()

    tasks = queue.Queue()
    for i, (email, pwd) in enumerate(accounts):
        proxy = proxies[i % len(proxies)] if proxies else None
        tasks.put((email, pwd, proxy))

    def worker():
        while True:
            try:
                email, pwd, proxy = tasks.get_nowait()
            except queue.Empty:
                break
            logger.info(f"Обработка {email} с прокси {proxy}")
            success = register_account(email, pwd, proxy)
            if success:
                logger.info(f"Успешно обработан {email}")
            else:
                logger.error(f"Не удалось обработать {email}")
            if DELAY > 0:
                time.sleep(DELAY)
            tasks.task_done()

    threads = []
    for _ in range(min(THREADS, len(accounts))):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    logger.info("Все задачи выполнены.")


if __name__ == "__main__":
    main()
