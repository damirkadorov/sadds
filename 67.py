import requests
import json
import base64
import uuid
import time
import hashlib
import re
from nacl import utils, public
from nacl.public import PrivateKey, PublicKey, Box


def encrypt_data(data):
    SERVER_PUBLIC_KEY_B64 = "8OX4IxjbfDRCJ28fxng2NMEtnc2Sw0HG5+LCjjF//Q0="
    server_public_key = PublicKey(base64.b64decode(SERVER_PUBLIC_KEY_B64))

    nonce = utils.random(Box.NONCE_SIZE)
    client_private_key = PrivateKey.generate()
    client_public_key = client_private_key.public_key
    box = Box(client_private_key, server_public_key)

    if isinstance(data, dict):
        data = json.dumps(data)
    encrypted = box.encrypt(data.encode('utf-8'), nonce)
    encrypted_data = encrypted[len(nonce):]

    out = bytearray()
    out.extend(nonce)
    out.extend(bytes(client_public_key))
    out.extend(encrypted_data)

    return base64.b64encode(bytes(out)).decode('utf-8')


def initiate_card_session(session_id, card_number, csrf_token=None, request_id=None):
    url = f"https://checkout.monime.io/api/v1/{session_id}/card-scheme-instances/-/initiate-session"

    headers = {
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json; charset=utf-8',
        'origin': 'https://checkout.monime.io',
        'referer': f'https://checkout.monime.io/{session_id}',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'x-idempotency-key': str(uuid.uuid4()),
    }

    if csrf_token:
        headers['x-csrf-token'] = csrf_token
    if request_id:
        headers['x-request-id'] = request_id

    encrypted_card = encrypt_data(card_number)

    payload = {
        "cardNumber": encrypted_card
    }

    print(f"\n{'─' * 50}")
    print(f"ЭТАП 1/3")
    print(f"{'─' * 50}")

    response = requests.post(url, headers=headers, json=payload)

    if response.status_code == 200:
        result = response.json()
        print(f"✓ Статус: {response.status_code}")

        if 'result' in result and 'htmlRender' in result['result']:
            html_render = result['result']['htmlRender']
            if html_render.get('content'):
                print("\n→ Дополнительная проверка")
                print("→ Продолжаем...")

        return response
    else:
        print(f"✗ Ошибка: {response.status_code}")
        print(f"Ответ: {response.text}")
        return None


def authenticate_card_session(session_id, email, card_details, csrf_token=None, request_id=None):

    url = f"https://checkout.monime.io/api/v1/{session_id}/card-scheme-instances/-/authenticate-session"

    headers = {
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json; charset=utf-8',
        'origin': 'https://checkout.monime.io',
        'referer': f'https://checkout.monime.io/{session_id}',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'x-idempotency-key': str(uuid.uuid4()),
    }

    if csrf_token:
        headers['x-csrf-token'] = csrf_token
    if request_id:
        headers['x-request-id'] = request_id

    encrypted_card_info = encrypt_data({
        "expiry": card_details["expiry"],
        "securityCode": card_details["cvv"],
        "holderName": card_details["holder_name"]
    })

    payload = {
        "customer": {
            "email": email
        },
        "cardInfo": encrypted_card_info,
        "deviceInfo": {
            "screenWidth": 1920,
            "screenHeight": 1080,
            "colorDepth": 32,
            "fingerprint": hashlib.md5(f"{email}{time.time()}".encode()).hexdigest(),
            "timezoneOffset": -time.timezone // 60 if time.timezone else -120
        }
    }

    print(f"\n{'─' * 50}")
    print(f"ЭТАП 2/3")
    print(f"{'─' * 50}")

    response = requests.post(url, headers=headers, json=payload)

    if response.status_code == 200:
        print(f"✓ Статус: {response.status_code}")
        return response
    else:
        print(f"✗ Ошибка: {response.status_code}")
        print(f"Ответ: {response.text}")
        return None


def charge_card_session(session_id, csrf_token=None, request_id=None):

    url = f"https://checkout.monime.io/api/v1/{session_id}/card-scheme-instances/-/charge-session"

    headers = {
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json; charset=utf-8',
        'origin': 'https://checkout.monime.io',
        'referer': f'https://checkout.monime.io/{session_id}',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'x-idempotency-key': str(uuid.uuid4()),
    }

    if csrf_token:
        headers['x-csrf-token'] = csrf_token
    if request_id:
        headers['x-request-id'] = request_id

    payload = {}

    print(f"\n{'─' * 50}")
    print(f"ЭТАП 3/3")
    print(f"{'─' * 50}")

    response = requests.post(url, headers=headers, json=payload)

    if response.status_code == 200:
        print(f"✓ Статус: {response.status_code}")
        try:
            print(f"📄 Ответ: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
        except:
            print(f"Ответ: {response.text}")
    else:
        print(f"✗ Ошибка: {response.status_code}")
        print(f"Ответ: {response.text}")

    return response


def complete_payment_flow(session_id, email, card_number, card_details, csrf_token=None):

    print(f"\n{'═' * 50}")
    print(f"НАЧАЛО ПРОВЕРКИ")
    print(f"{'═' * 50}")
    print(f"ID: {session_id}")
    print(f"Email: {email}")
    print(f"Account: {card_number[:6]}...{card_number[-4:]}")

    # Генерируем request-id для всей сессии
    request_id = str(uuid.uuid4())

    response1 = initiate_card_session(session_id, card_number, csrf_token, request_id)
    if not response1 or response1.status_code != 200:
        print("✗ Остановка: ошибка на этапе 1")
        return False

    time.sleep(2)

    print("\n→ Переход к этапу 2")
    response2 = authenticate_card_session(session_id, email, card_details, csrf_token, request_id)
    if not response2 or response2.status_code != 200:
        print("✗ Остановка: ошибка на этапе 2")
        return False

    time.sleep(1)

    response3 = charge_card_session(session_id, csrf_token, request_id)

    if response3 and response3.status_code == 200:
        print(f"\n{'═' * 50}")
        print(f"ПРОВЕРКА ЗАВЕРШЕНА")
        print(f"{'═' * 50}")
        return True
    else:
        print(f"\n{'═' * 50}")
        print(f"ОШИБКА ПРИ ПРОВЕРКЕ")
        print(f"{'═' * 50}")
        return False



if __name__ == "__main__":
    session_id = "scs-k6N6bs7buJQe9ST395PT25Ni3bW"
    email = "Simon43@gmail.com"
    csrf_token = "e613d2a6-b1c1-4af0-bf5d-1369789e1a3d"

    card_number = "4569330006256925"
    card_details = {
        "expiry": "12/26",
        "cvv": "123",
        "holder_name": "Test User"
    }

    success = complete_payment_flow(
        session_id=session_id,
        email=email,
        card_number=card_number,
        card_details=card_details,
        csrf_token=csrf_token
    )

    if success:
        print("\n✓ Проверка успешна")
    else:
        print("\n✗ В процессе проверки возникла ошибка")