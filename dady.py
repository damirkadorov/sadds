#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Авторегистрация аккаунтов на chatgpt.com через Chromium.
Использует API Firstmail для получения кода подтверждения.
"""

import sys
import time
import logging
import threading
import queue
import re
import requests
import json

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.chrome.service import Service

# ===================== НАСТРОЙКИ (измените здесь) =====================
EMAILS_FILE = "emails.txt"          # Файл с email:пароль
OUTPUT_FILE = "accounts.txt"        # Куда сохранять успешные аккаунты
PROXIES_FILE = "proxy.txt"          # Файл с прокси (по одному на строку)
API_TOKEN = "kv3wxML6Ibxo2ok1SPJCVonQIM09TWDgqjf0_S3BcVWIfvZVx9XlqcioEKn6qiXt"
API_URL = "https://firstmail.ltd/api/v1/email/messages"
THREADS = 1                         # Количество потоков (1 = последовательно)
DELAY = 5                           # Задержка между регистрациями (сек)
HEADLESS = False                    # Запускать браузер без окна (True/False)
# ======================================================================

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("AutoRegister")


def get_verification_code_api(email_address, email_password, sender_domain="tm.openai.com", timeout=120):
    """Получает код подтверждения через API Firstmail."""
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


def register_account(email, password, proxy):
    """Регистрирует один аккаунт на chatgpt.com."""
    driver = None
    try:
        options = webdriver.ChromeOptions()
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option("useAutomationExtension", False)
        if HEADLESS:
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
        if proxy:
            options.add_argument(f"--proxy-server={proxy}")
            logger.info(f"Используется прокси: {proxy}")

        # Используем системный chromedriver (установленный через apt)
        service = Service("/usr/bin/chromedriver")
        driver = webdriver.Chrome(service=service, options=options)

        driver.execute_script(
            "Object.defineProperty(navigator, 'webdriver', "
            "{get: () => undefined})"
        )

        # Шаг 1: открыть chatgpt.com
        driver.get("https://chatgpt.com")
        logger.info("Открыта страница chatgpt.com")
        wait = WebDriverWait(driver, 15)

        # Шаг 2: нажать кнопку "Зарегистрироваться бесплатно" (Sign up)
        # Пробуем разные варианты
        signup_buttons = [
            "//button[contains(text(), 'Sign up')]",
            "//button[contains(text(), 'Зарегистрироваться')]",
            "//a[contains(text(), 'Sign up')]",
            "//a[contains(text(), 'Зарегистрироваться')]",
            "//button[@data-testid='signup-button']",
            "//button[contains(@class, 'btn-primary') and contains(text(), 'Sign up')]"
        ]
        clicked = False
        for xp in signup_buttons:
            try:
                btn = driver.find_element(By.XPATH, xp)
                if btn.is_displayed() and btn.is_enabled():
                    btn.click()
                    logger.info("Нажата кнопка регистрации")
                    clicked = True
                    break
            except:
                pass
        if not clicked:
            # Если не нашли кнопку, возможно, она уже на странице входа
            logger.warning("Кнопка регистрации не найдена, возможно, уже на странице ввода email")
            pass

        time.sleep(2)

        # Шаг 3: ввод email
        email_field = wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='email']"))
        )
        email_field.clear()
        email_field.send_keys(email)
        logger.info(f"Email {email} введён")

        # Шаг 4: нажать "Continue" (первая кнопка)
        continue_btn = wait.until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']"))
        )
        continue_btn.click()
        logger.info("Нажата кнопка Continue (email)")

        # Шаг 5: ожидание поля пароля
        password_field = wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='password']"))
        )
        password_field.clear()
        password_field.send_keys(password)
        logger.info("Пароль введён")

        # Шаг 6: нажать "Continue" (пароль)
        continue_btn2 = wait.until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']"))
        )
        continue_btn2.click()
        logger.info("Нажата кнопка Continue (пароль)")

        # Шаг 7: ожидание поля для кода
        code_field = wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='code']"))
        )
        logger.info("Поле для кода появилось")

        # Шаг 8: получить код через API
        code = get_verification_code_api(email, password, sender_domain="tm.openai.com", timeout=120)
        if not code:
            logger.error(f"Не удалось получить код для {email}")
            return False

        # Шаг 9: ввести код
        code_field.clear()
        code_field.send_keys(code)
        logger.info(f"Код {code} введён")

        # Шаг 10: нажать "Continue" (код)
        continue_btn3 = wait.until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']"))
        )
        continue_btn3.click()
        logger.info("Нажата кнопка Continue (код)")

        # Небольшая пауза для завершения регистрации
        time.sleep(3)

        # Сохраняем успешный аккаунт
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(f"{email}:{password}\n")
        logger.info(f"Аккаунт {email} успешно сохранён в {OUTPUT_FILE}")
        return True

    except TimeoutException as e:
        logger.error(f"Таймаут при регистрации {email}: {e}")
        return False
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
