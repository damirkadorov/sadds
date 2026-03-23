#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Авторегистрация/автовход на chatgpt.com через Chromium с поддержкой HTTP/HTTPS прокси.
При появлении капчи (включая Cloudflare) останавливается и ждёт ручного решения.
Использует API Firstmail для получения кода.
"""

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
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.chrome.service import Service

# ===================== НАСТРОЙКИ =====================
EMAILS_FILE = "emails.txt"          # email:пароль (каждая строка)
OUTPUT_FILE = "accounts.txt"        # успешные аккаунты
PROXIES_FILE = "proxy.txt"          # HTTP/HTTPS прокси, формат: http://user:pass@host:port
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


def wait_for_captcha(driver):
    """
    Обнаруживает капчу (включая Cloudflare) и ждёт ручного решения.
    Возвращает True, если капча была и решена, иначе False.
    """
    # Проверяем URL на наличие индикаторов капчи
    url = driver.current_url.lower()
    captcha_url_indicators = ["captcha", "challenge", "error", "security"]
    if any(ind in url for ind in captcha_url_indicators):
        logger.warning(f"Обнаружена капча по URL: {url}")
        captcha_present = True
    else:
        captcha_present = False

    # Дополнительно ищем элементы на странице
    xpath_list = [
        "//iframe[contains(@src, 'recaptcha')]",
        "//iframe[contains(@src, 'challenges.cloudflare.com')]",
        "//div[@class='g-recaptcha']",
        "//div[contains(@class, 'captcha')]",
        "//div[contains(text(), 'captcha')]",
        "//div[contains(text(), 'проверка')]",
        "//div[contains(text(), 'Checking your browser')]",
        "//div[contains(text(), 'Please wait')]",
        "//div[contains(text(), 'Cloudflare')]",
        "//div[contains(text(), 'Ray ID')]",
        "//button[contains(text(), 'Verify you are human')]",
        "//div[@id='cf-challenge']",
        "//div[@class='cf-browser-verification']"
    ]

    for xp in xpath_list:
        try:
            elem = driver.find_element(By.XPATH, xp)
            if elem.is_displayed():
                captcha_present = True
                break
        except:
            continue

    if captcha_present:
        logger.warning("Обнаружена капча! Пожалуйста, решите её вручную в открытом браузере.")
        # Ждём, пока капча исчезнет
        while True:
            time.sleep(3)
            # Проверяем URL
            new_url = driver.current_url.lower()
            if not any(ind in new_url for ind in captcha_url_indicators):
                # Дополнительно проверяем, что капча-элементы пропали
                captcha_still_there = False
                for xp in xpath_list:
                    try:
                        elem = driver.find_element(By.XPATH, xp)
                        if elem.is_displayed():
                            captcha_still_there = True
                            break
                    except:
                        continue
                if not captcha_still_there:
                    logger.info("Капча решена, продолжаем...")
                    break
            # Небольшая пауза после исчезновения, чтобы страница стабилизировалась
        time.sleep(2)
        return True
    return False


def register_account(email, password, proxy):
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

        service = Service("/usr/bin/chromedriver")
        driver = webdriver.Chrome(service=service, options=options)

        driver.execute_script(
            "Object.defineProperty(navigator, 'webdriver', "
            "{get: () => undefined})"
        )

        driver.get("https://chatgpt.com")
        logger.info("Открыта страница chatgpt.com")
        # Проверка капчи после загрузки
        wait_for_captcha(driver)

        # Ждём появления кнопки Log in (с запасом времени)
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
        wait_for_captcha(driver)

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

        wait_for_captcha(driver)

        continue_btn = wait.until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']"))
        )
        continue_btn.click()
        logger.info("Нажата кнопка Continue (email)")

        wait_for_captcha(driver)

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
                wait_for_captcha(driver)
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

        wait_for_captcha(driver)

        continue_btn2 = wait.until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']"))
        )
        continue_btn2.click()
        logger.info("Нажата кнопка Continue (пароль)")

        wait_for_captcha(driver)

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

        wait_for_captcha(driver)

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
    if not os.path.exists(PROXIES_FILE):
        return proxies
    with open(PROXIES_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                proxies.append(line)
    return proxies


def main():
    try:
        import requests
    except ImportError:
        logger.error("Установите requests: pip install requests")
        sys.exit(1)

    use_proxy = input("Использовать прокси? (y/n): ").strip().lower()
    proxies = []
    if use_proxy == 'y':
        proxies = read_proxies()
        if not proxies:
            logger.warning("Файл с прокси пуст или не найден. Работаем без прокси.")
        else:
            logger.info(f"Загружено {len(proxies)} прокси")
    else:
        logger.info("Работаем без прокси")

    accounts = read_accounts()
    if not accounts:
        logger.error("Файл с аккаунтами пуст или имеет неверный формат.")
        sys.exit(1)

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
