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

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.chrome.service import Service

# ===== НАСТРОЙКИ =====
TARGET_DOMAIN = "auth.openai.com"
REGISTER_PATH = "/create-account"
SENDER_DOMAIN = "tm.openai.com"
EMAILS_FILE = "emails.txt"
OUTPUT_FILE = "accounts.txt"
PROXIES_FILE = "proxy.txt"
API_TOKEN = "kv3wxML6Ibxo2ok1SPJCVonQIM09TWDgqjf0_S3BcVWIfvZVx9XlqcioEKn6qiXt"
API_URL = "https://firstmail.ltd/api/v1/email/messages"
THREADS = 1
DELAY = 5
HEADLESS = False
# ====================

# Настройка логирования
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("AutoRegister")

# Селекторы элементов
SELECTORS = {
    "email": "input[name='email']",
    "password": "input[name='password']",
    "submit": "button[type='submit']",
    "code": "input[name='code']"
}


def get_verification_code_api(email_address, email_password,
                              sender_domain, timeout=120):
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
            response = requests.post(
                API_URL, headers=headers, json=payload
            )
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
                if sender_domain not in from_str:
                    continue
                subject = msg.get("subject", "")
                body = msg.get("body", "")
                full_text = subject + " " + body
                match = re.search(r"\b(\d{6})\b", full_text)
                if not match:
                    match = re.search(r"\b(\d{4,6})\b", full_text)
                if match:
                    code = match.group(1)
                    logger.info(
                        f"Найден код {code} для {email_address}"
                    )
                    return code
            time.sleep(10)
        except Exception as e:
            logger.error(f"Ошибка API для {email_address}: {e}")
            time.sleep(10)
    logger.error(
        f"Письмо с кодом не пришло за {timeout} секунд для {email_address}"
    )
    return None


def register_account(email, password, proxy):
    driver = None
    try:
        options = webdriver.ChromeOptions()
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option(
            "excludeSwitches", ["enable-automation"]
        )
        options.add_experimental_option(
            "useAutomationExtension", False
        )
        if HEADLESS:
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
        if proxy:
            options.add_argument(f"--proxy-server={proxy}")
            logger.info(f"Используется прокси: {proxy}")

        # Используем системный chromedriver
        try:
            service = Service("/usr/bin/chromedriver")
            driver = webdriver.Chrome(
                service=service,
                options=options
            )
        except Exception as e:
            logger.error(f"Ошибка запуска chromedriver: {e}")
            return False

        driver.execute_script(
            "Object.defineProperty(navigator, 'webdriver', "
            "{get: () => undefined})"
        )

        target_url = f"https://{TARGET_DOMAIN}{REGISTER_PATH}"
        driver.get(target_url)
        logger.info(f"Открыта страница {target_url} для {email}")

        wait = WebDriverWait(driver, 10)

        email_field = wait.until(
            EC.presence_of_element_located(
                (By.CSS_SELECTOR, SELECTORS["email"])
            )
        )
        email_field.clear()
        email_field.send_keys(email)

        password_field = driver.find_element(
            By.CSS_SELECTOR, SELECTORS["password"]
        )
        password_field.clear()
        password_field.send_keys(password)

        submit_button = driver.find_element(
            By.CSS_SELECTOR, SELECTORS["submit"]
        )
        submit_button.click()
        logger.info(f"Форма регистрации отправлена для {email}")

        code_field_locator = (By.CSS_SELECTOR, SELECTORS["code"])
        wait.until(EC.presence_of_element_located(code_field_locator))

        code = get_verification_code_api(
            email, password, SENDER_DOMAIN, timeout=120
        )
        if not code:
            logger.error(f"Не удалось получить код для {email}")
            return False

        code_field = driver.find_element(*code_field_locator)
        code_field.clear()
        code_field.send_keys(code)

        try:
            code_submit = driver.find_element(
                By.CSS_SELECTOR, SELECTORS["submit"]
            )
            code_submit.click()
        except NoSuchElementException:
            code_field.send_keys("\n")

        logger.info(f"Код подтверждения введён для {email}")

        time.sleep(3)

        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(f"{email}:{password}\n")
        logger.info(
            f"Аккаунт {email} успешно сохранён в {OUTPUT_FILE}"
        )
        return True

    except Exception as e:
        logger.error(f"Ошибка при регистрации {email}: {e}")
        return False
    finally:
        if driver:
            driver.quit()


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
        logger.error(
            "Файл с аккаунтами пуст или имеет неверный формат."
        )
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
                logger.info(f"Успешно зарегистрирован {email}")
            else:
                logger.error(f"Не удалось зарегистрировать {email}")
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
