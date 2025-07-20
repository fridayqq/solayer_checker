import os
import uuid
import struct
import base64
import base58
import requests
import csv
import datetime
import time
import random
from typing import Optional
from solders.keypair import Keypair
from dotenv import load_dotenv

"""~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Solayer claim / vesting checker (Python 3.11+)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Usage:
  1.  pip install -r requirements.txt     # requests solders python-dotenv base58
  2.  Put PRIVATE_KEY=<base58 secret key> in a .env file (or export env‑var)
  3.  python solayer_client_full.py

The script reproduces exactly the sequence that the Solayer front‑end sends:
  • GetSignatureMessage           – receive challenge (field1 string)
  • VerifySignature               – send signature + nonce, receive JWT (field1)
  • GetAccountInfo                – eligibility / balance
  • GetVestingBaseInfo            – overall vesting stats
  • GetVestingClaimInfo           – next claim tranche

All protobuf is built manually; the only protobuf feature we need is
varint‑length‑prefixed strings/bytes.
"""

# Добавим в начало файла после импортов:

CONFIG = {
    'delay_between_wallets': 2.0,  # Базовая задержка между кошельками в секундах
    'delay_random_range': 1.0,     # Случайное добавление к задержке (±)
    'max_retries': 3,              # Максимальное количество попыток
    'retry_delay_base': 5.0,       # Базовая задержка для ретрая
    'retry_delay_multiplier': 2.0, # Множитель для экспоненциального backoff
    'request_timeout': 30.0,       # Таймаут для HTTP запросов
}

def load_config(filename: str = 'config.json') -> dict:
    """Загружаем конфигурацию из файла"""
    try:
        import json
        with open(filename, 'r') as f:
            custom_config = json.load(f)
        CONFIG.update(custom_config)
        print(f"📋 Конфигурация загружена из {filename}")
    except FileNotFoundError:
        print(f"⚠️  Файл {filename} не найден, используем стандартную конфигурацию")
    except Exception as e:
        print(f"⚠️  Ошибка загрузки конфига: {e}, используем стандартную конфигурацию")
    return CONFIG

def wait_between_requests():
    """Задержка между запросами"""
    base_delay = CONFIG['delay_between_wallets']
    random_delay = random.uniform(-CONFIG['delay_random_range'], CONFIG['delay_random_range'])
    total_delay = max(0.1, base_delay + random_delay)
    
    print(f"⏱️  Ожидание {total_delay:.1f}с перед следующим кошельком...")
    time.sleep(total_delay)


def retry_on_error(func, *args, **kwargs):
    """Выполняет функцию с ретраями при ошибках"""
    last_exception = None
    
    for attempt in range(CONFIG['max_retries'] + 1):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.RequestException as e:
            last_exception = e
            if attempt < CONFIG['max_retries']:
                delay = CONFIG['retry_delay_base'] * (CONFIG['retry_delay_multiplier'] ** attempt)
                print(f"⚠️  Ошибка сети (попытка {attempt + 1}/{CONFIG['max_retries'] + 1}): {e}")
                print(f"⏱️  Ретрай через {delay:.1f}с...")
                time.sleep(delay)
            else:
                print(f"❌ Превышено максимальное количество попыток")
                raise last_exception
        except Exception as e:
            # Для других ошибок не делаем ретрай
            print(f"❌ Критическая ошибка: {e}")
            raise e
    
    raise last_exception


def process_wallet(private_key_b58: str) -> dict:
    """Обрабатываем один кошелек и возвращаем результат"""
    try:
        kp = Keypair.from_bytes(base58.b58decode(private_key_b58))
        client = SolayerGRPCClient(kp)
        
        wallet_address = str(kp.pubkey())
        print(f"\n🔑 Обрабатываем кошелек: {wallet_address}")
        
        # 1) Получаем challenge с ретраями
        challenge = retry_on_error(client.get_signature_message)
        full_msg = challenge["field_1"]
        
        # 2) Подписываем и верифицируем с ретраями
        nonce = str(uuid.uuid4())
        signature = client.sign_message(full_msg)
        retry_on_error(client.verify_signature, full_msg, signature, nonce)
        
        # 3) Проверяем eligibility с ретраями
        acc_info = retry_on_error(client.get_account_info)
        eligible = "field_1" in acc_info and len(acc_info["field_1"]) > 10
        
        # 4) Получаем vesting info если eligible
        total_allocation = "0"
        vested_amount = "0"
        
        if eligible:
            try:
                v_claim = retry_on_error(client.get_vesting_claim_info)
                vesting_data = parse_vesting_claim_data(v_claim.get("field_1", ""))
                
                if vesting_data:
                    total_allocation = vesting_data["total_allocation"]
                    vested_amount = vesting_data["vested_amount"]
            except Exception as e:
                print(f"⚠️  Ошибка получения vesting info: {e}")
        
        result = {
            'private_key': private_key_b58,
            'wallet_address': wallet_address,
            'eligible': eligible,
            'total_allocation': total_allocation,
            'vested_amount': vested_amount,
            'total_allocation_formatted': format_layer_amount(total_allocation),
            'status': 'SUCCESS'
        }
        
        # Выводим результат
        status = "✅ ELIGIBLE" if eligible else "❌ NOT ELIGIBLE"
        allocation_text = result['total_allocation_formatted'] if eligible and total_allocation != "0" else "0.000"
        print(f"   Статус: {status}")
        print(f"   Allocation: {allocation_text} LAYER")
        
        return result
        
    except Exception as e:
        print(f"❌ Ошибка обработки кошелька {private_key_b58[:10]}...: {e}")
        return {
            'private_key': private_key_b58,
            'wallet_address': 'ERROR',
            'eligible': False,
            'total_allocation': '0',
            'vested_amount': '0',
            'total_allocation_formatted': '0.000',
            'status': f'ERROR: {str(e)}'
        }

def load_private_keys(filename: str = 'keys.txt') -> list:
    """Загружаем приватные ключи из файла"""
    try:
        with open(filename, 'r') as f:
            keys = [line.strip() for line in f if line.strip()]
        print(f"📁 Загружено {len(keys)} приватных ключей из {filename}")
        return keys
    except FileNotFoundError:
        print(f"❌ Файл {filename} не найден!")
        return []

def save_to_csv(results: list, filename: str = None):
    """Сохраняем результаты в CSV файл"""
    if not filename:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"solayer_results_{timestamp}.csv"
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['private_key', 'wallet_address', 'eligible', 'total_allocation', 
                     'vested_amount', 'total_allocation_formatted', 'status']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for result in results:
            writer.writerow(result)
    
    print(f"💾 Результаты сохранены в {filename}")

def main_batch():
    """Основная функция для обработки множества кошельков"""
    print("🚀 SOLAYER BATCH CHECKER")
    print("=" * 60)
    
    # Загружаем конфигурацию
    config = load_config()
    print(f"⚙️  Настройки:")
    print(f"   Задержка между кошельками: {config['delay_between_wallets']}±{config['delay_random_range']}с")
    print(f"   Максимум попыток: {config['max_retries']}")
    print(f"   Таймаут запросов: {config['request_timeout']}с")
    
    # Загружаем приватные ключи
    private_keys = load_private_keys('keys.txt')
    if not private_keys:
        print("❌ Нет приватных ключей для обработки")
        return
    
    results = []
    successful = 0
    eligible_count = 0
    total_allocation_sum = 0
    start_time = time.time()
    
    # Обрабатываем каждый кошелек
    for i, private_key in enumerate(private_keys, 1):
        print(f"\n{'='*60}")
        print(f"📊 Обрабатываем кошелек {i}/{len(private_keys)}")
        
        wallet_start_time = time.time()
        result = process_wallet(private_key)
        wallet_end_time = time.time()
        
        results.append(result)
        
        if result['status'] == 'SUCCESS':
            successful += 1
            if result['eligible']:
                eligible_count += 1
                try:
                    total_allocation_sum += float(result['total_allocation'])
                except (ValueError, TypeError):
                    pass
        
        # Показываем прогресс
        elapsed = wallet_end_time - wallet_start_time
        print(f"⏱️  Обработан за {elapsed:.1f}с")
        
        # Ждем перед следующим кошельком (кроме последнего)
        if i < len(private_keys):
            wait_between_requests()
    
    # Выводим сводку
    total_time = time.time() - start_time
    print(f"\n{'='*60}")
    print("📈 ИТОГОВАЯ СВОДКА:")
    print(f"   Всего кошельков: {len(private_keys)}")
    print(f"   Успешно обработано: {successful}")
    print(f"   Eligible кошельков: {eligible_count}")
    print(f"   Общее время: {total_time/60:.1f} минут")
    if total_allocation_sum > 0:
        print(f"   Общий allocation: {format_layer_amount(str(int(total_allocation_sum)))}")
    
    # Сохраняем в CSV
    save_to_csv(results)
    
    # Показываем eligible кошельки
    if eligible_count > 0:
        print(f"\n🎉 ELIGIBLE КОШЕЛЬКИ:")
        print("-" * 100)
        print(f"{'Адрес':<45} {'Allocation':<20} {'Статус'}")
        print("-" * 100)
        for result in results:
            if result['eligible']:
                addr = result['wallet_address']
                allocation = result['total_allocation_formatted']
                print(f"{addr:<45} {allocation:<20} ✅")

def main():
    """Основная функция - выбираем режим работы"""
    # Проверяем, есть ли файл keys.txt
    if os.path.exists('keys.txt'):
        print("📁 Найден файл keys.txt")
        choice = input("Выберите режим:\n1 - Один кошелек из .env\n2 - Batch обработка из keys.txt\nВвод (1/2): ").strip()
        
        if choice == '2':
            main_batch()
            return
    
    # Режим одного кошелька (оригинальный код)
    pk_b58 = os.getenv("PRIVATE_KEY")
    if not pk_b58:
        raise SystemExit("PRIVATE_KEY not found in .env")
    
    result = process_wallet(pk_b58)
    print(f"\n🎯 РЕЗУЛЬТАТ:")
    print(f"   Кошелек: {result['wallet_address']}")
    print(f"   Статус: {'✅ ELIGIBLE' if result['eligible'] else '❌ NOT ELIGIBLE'}")
    if result['eligible']:
        print(f"   Total Allocation: {result['total_allocation_formatted']}")
    
    # Сохраняем результат одного кошелька в CSV
    save_to_csv([result])

def format_layer_amount(raw_amount: str | float) -> str:
    """Convert raw token amount to LAYER tokens (assuming 9 decimals like SOL)"""
    try:
        amount = float(raw_amount)
        # Всегда делим на 10^9, так как числа приходят в raw формате
        layer_amount = amount / 1_000_000_000
        return f"{layer_amount:.3f}"
    except (ValueError, TypeError):
        return f"{raw_amount} (raw)"

def parse_vesting_claim_data(field_data: str | dict) -> dict:
    """Более точный парсинг vesting данных"""
    try:
        print(f"🔍 Парсим vesting данные: {field_data}")
        
        # Если это словарь с nested полями
        if isinstance(field_data, dict):
            allocation_fields = []
            for key, value in field_data.items():
                if isinstance(value, int) and value > 1000000:  # Большие числа
                    allocation_fields.append(value)
                    print(f"   📊 Найдено большое число в {key}: {value}")
            
            if allocation_fields:
                return {
                    'total_allocation': str(max(allocation_fields)),
                    'vested_amount': str(min(allocation_fields)) if len(allocation_fields) > 1 else str(allocation_fields[0])
                }
        
        # Если это строка, ищем числа
        if isinstance(field_data, str):
            import re
            
            # Ищем float числа (с точкой)
            float_numbers = re.findall(r'\d+\.\d+', field_data)
            print(f"   📊 Найденные float числа: {float_numbers}")
            
            if float_numbers:
                # Берем первое число (они одинаковые, но повторяются)
                first_number = float_numbers[0]
                
                # НЕ умножаем на 10^9, так как числа уже в правильном формате
                try:
                    float_value = float(first_number)
                    # Сохраняем как есть
                    amount_str = str(float_value)
                    
                    print(f"   📊 Найденное число: {first_number} -> {amount_str}")
                    
                    return {
                        'total_allocation': amount_str,
                        'vested_amount': amount_str
                    }
                except ValueError:
                    print(f"   ❌ Ошибка конвертации: {first_number}")
            
            # Fallback: ищем большие целые числа
            numbers = re.findall(r'\d{9,}', field_data)
            print(f"   📊 Найденные целые числа: {numbers}")
            
            if numbers:
                return {
                    'total_allocation': numbers[0],
                    'vested_amount': numbers[1] if len(numbers) > 1 else numbers[0]
                }
                
    except Exception as e:
        print(f"❌ Ошибка парсинга vesting данных: {e}")
    
    return {}

load_dotenv()

class SolayerGRPCClient:
    BASE_URL = (
        "https://claim.solayer.foundation/"
        "api/solayerservice.v1.SolayerService"
    )

    def __init__(self, keypair: Keypair) -> None:
        self.keypair = keypair
        self.wallet_address = str(keypair.pubkey())
        self.browser_id = base64.b64encode(os.urandom(16)).decode()
        self.token: str | None = None  # filled after VerifySignature
        self.session = requests.Session()
        self.session.timeout = CONFIG['request_timeout']

    # ------------------------------------------------------------------
    # gRPC‑Web helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _grpc_wrap(payload: bytes) -> bytes:
        """Adds the 5‑byte gRPC‑Web prefix: 0x00 + big‑endian length."""
        return b"\x00" + struct.pack(">I", len(payload)) + payload

    @staticmethod
    def _build_simple_request(request_type: int = 1) -> bytes:
        """Message with only field1 = request_type (varint)."""
        return SolayerGRPCClient._grpc_wrap(b"\x08" + bytes([request_type]))

    def _build_login_request(self) -> bytes:
        """field1=request_type=1, field2=wallet_address (string)."""
        addr = self.wallet_address.encode()
        msg = b"\x08\x01" + b"\x12" + bytes([len(addr)]) + addr
        return self._grpc_wrap(msg)

    # ------------------------------------------------------------------
    # tiny protobuf parser (varint + length‑delimited)
    # ------------------------------------------------------------------
    def _parse_protobuf_response(self, response_data):
        """Парсим protobuf ответ с детальным логированием"""
        try:
            if len(response_data) < 5:
                print(f"⚠️  Слишком короткий ответ: {len(response_data)} байт")
                return None
                
            # Пропускаем gRPC заголовок (5 байт)
            proto_data = response_data[5:]
            print(f"🔍 Данные protobuf: {len(proto_data)} байт")
            print(f"🔍 Hex данные: {proto_data.hex()}")
            
            if len(proto_data) == 0:
                print("⚠️  Пустые данные protobuf")
                return {}
            
            # Детальный парсинг protobuf
            result = {}
            i = 0
            while i < len(proto_data):
                if i >= len(proto_data):
                    break
                    
                # Читаем field header
                field_header = proto_data[i]
                field_number = field_header >> 3
                wire_type = field_header & 0x07
                i += 1
                
                print(f"📋 Field {field_number}, wire_type {wire_type}")
                
                if wire_type == 0:  # varint
                    value, i = self._read_varint(proto_data, i)
                    result[f'field_{field_number}'] = value
                    print(f"   📊 Varint value: {value}")
                elif wire_type == 2:  # length-delimited (string/bytes)
                    if i >= len(proto_data):
                        break
                    length, i = self._read_varint(proto_data, i)
                    if i + length > len(proto_data):
                        break
                    value = proto_data[i:i+length]
                    i += length
                    
                    print(f"   📊 Length: {length}, Raw bytes: {value.hex()}")
                    
                    try:
                        # Пробуем декодировать как строку
                        decoded = value.decode('utf-8')
                        result[f'field_{field_number}'] = decoded
                        print(f"   📊 String value: {decoded}")
                    except:
                        # Если не получается, сохраняем как base64
                        b64 = base64.b64encode(value).decode('utf-8')
                        result[f'field_{field_number}'] = b64
                        print(f"   📊 Base64 value: {b64}")
                        
                        # Пробуем парсить как вложенный protobuf
                        try:
                            nested = self._parse_nested_protobuf(value)
                            if nested:
                                print(f"   🔍 Nested protobuf: {nested}")
                                result[f'field_{field_number}_nested'] = nested
                        except:
                            pass
                else:
                    # Пропускаем неизвестные типы
                    print(f"⚠️  Неизвестный wire_type: {wire_type}")
                    i += 1
                    
            print(f"📋 Полный результат парсинга: {result}")
            return result
        except Exception as e:
            print(f"❌ Ошибка парсинга protobuf: {e}")
            return None

    def _parse_nested_protobuf(self, data: bytes) -> dict:
        """Парсим вложенные protobuf данные"""
        result = {}
        i = 0
        while i < len(data):
            try:
                field_header = data[i]
                field_number = field_header >> 3
                wire_type = field_header & 0x07
                i += 1
                
                if wire_type == 0:  # varint
                    value, i = self._read_varint(data, i)
                    result[f'nested_field_{field_number}'] = value
                    print(f"      🔹 Nested varint {field_number}: {value}")
                elif wire_type == 2:  # length-delimited
                    length, i = self._read_varint(data, i)
                    if i + length > len(data):
                        break
                    value = data[i:i+length]
                    i += length
                    try:
                        decoded = value.decode('utf-8')
                        result[f'nested_field_{field_number}'] = decoded
                        print(f"      🔹 Nested string {field_number}: {decoded}")
                    except:
                        result[f'nested_field_{field_number}'] = value.hex()
                        print(f"      🔹 Nested bytes {field_number}: {value.hex()}")
                else:
                    break
            except:
                break
        return result

    @staticmethod
    def _read_varint(buf: bytes, i: int) -> tuple[int, int]:
        """Читаем varint из буфера"""
        shift = 0
        val = 0
        while i < len(buf):
            b = buf[i]
            val |= (b & 0x7F) << shift
            i += 1
            if b & 0x80 == 0:
                break
            shift += 7
        return val, i

    @classmethod
    def _parse_message(cls, data: bytes) -> dict:
        if len(data) < 5:
            return {}
        buf = data[5:]  # strip 5‑byte gRPC header
        i, out = 0, {}
        while i < len(buf):
            key = buf[i]
            field_no, wire = key >> 3, key & 0x07
            i += 1
            if wire == 0:  # varint
                val, i = cls._read_varint(buf, i)
                out[f"field_{field_no}"] = val
            elif wire == 2:  # length‑delimited
                ln, i = cls._read_varint(buf, i)
                val = buf[i : i + ln]
                i += ln
                try:
                    out[f"field_{field_no}"] = val.decode()
                except UnicodeDecodeError:
                    out[f"field_{field_no}"] = base64.b64encode(val).decode()
            else:
                raise NotImplementedError(f"wire type {wire} not handled")
        return out

    # ------------------------------------------------------------------
    # HTTP headers
    # ------------------------------------------------------------------
    def _headers(self, use_auth: bool = False) -> dict:
        h = {
            "accept": "*/*",
            "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "browser-id": self.browser_id,
            "content-type": "application/grpc-web+proto",
            "origin": "https://claim.solayer.foundation",
            "platform": "WEB",
            "referer": "https://claim.solayer.foundation/",
            "user-agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/138.0.0.0 Safari/537.36"
            ),
            "x-grpc-web": "1",
            "x-request-id": str(uuid.uuid4()),
        }
        if use_auth and self.token:
            h["authorization"] = self.token  # exactly as server gave, no Bearer
        return h

    # ------------------------------------------------------------------
    # API methods
    # ------------------------------------------------------------------
    def get_signature_message(self) -> dict:
        resp = self.session.post(
            f"{self.BASE_URL}/GetSignatureMessage",
            headers=self._headers(),
            data=self._build_login_request(),
            timeout=CONFIG['request_timeout']
        )
        resp.raise_for_status()
        return self._parse_message(resp.content)

    def verify_signature(self, message: str, signature_b58: str, nonce: str) -> dict:
        sig_raw = base58.b58decode(signature_b58)
        addr_bytes = self.wallet_address.encode()
        nonce_bytes = nonce.encode()
        wallet_type = b"Phantom"

        parts = [
            b"\x08\x01",  # field1 request_type=1
            b"\x12" + bytes([len(addr_bytes)]) + addr_bytes,  # field2 address
            b"\x1a" + bytes([len(sig_raw)]) + sig_raw,  # field3 signature
            b"\x22" + bytes([len(nonce_bytes)]) + nonce_bytes,  # field4 nonce
            b"\x2a" + bytes([len(wallet_type)]) + wallet_type,  # field5 wallet_type
        ]
        payload = b"".join(parts)
        resp = self.session.post(
            f"{self.BASE_URL}/VerifySignature",
            headers=self._headers(),
            data=self._grpc_wrap(payload),
            timeout=CONFIG['request_timeout']
        )
        resp.raise_for_status()
        parsed = self._parse_message(resp.content)
        self.token = parsed.get("field_1")  # save JWT for later calls
        return parsed

    def get_account_info(self) -> dict:
        resp = self.session.post(
            f"{self.BASE_URL}/GetAccountInfo",
            headers=self._headers(use_auth=True),
            data=b"\x00\x00\x00\x00\x00",  # empty message
            timeout=CONFIG['request_timeout']
        )
        resp.raise_for_status()
        return self._parse_message(resp.content)

    # ---------- Vesting ----------
    def get_vesting_base_info(self) -> dict:
        resp = self.session.post(
            f"{self.BASE_URL}/GetVestingBaseInfo",
            headers=self._headers(use_auth=True),
            data=self._build_simple_request(),
        )
        resp.raise_for_status()
        return self._parse_message(resp.content)

    def get_vesting_claim_info(self) -> dict:
        resp = self.session.post(
            f"{self.BASE_URL}/GetVestingClaimInfo",
            headers=self._headers(use_auth=True),
            data=self._build_simple_request(),
            timeout=CONFIG['request_timeout']
        )
        resp.raise_for_status()
        return self._parse_message(resp.content)

    # ------------------------------------------------------------------
    # Sign helper
    # ------------------------------------------------------------------
    def sign_message(self, msg: str | bytes) -> str:
        msg_bytes = msg.encode() if isinstance(msg, str) else msg
        sig = self.keypair.sign_message(msg_bytes)
        return base58.b58encode(bytes(sig)).decode()

# ----------------------------------------------------------------------
# ------------------------------  CLI  ---------------------------------
# ----------------------------------------------------------------------
def main():
    """Основная функция - выбираем режим работы"""
    # Проверяем, есть ли файл keys.txt
    if os.path.exists('keys.txt'):
        print("📁 Найден файл keys.txt")
        choice = input("Выберите режим:\n1 - Один кошелек из .env\n2 - Batch обработка из keys.txt\nВвод (1/2): ").strip()
        
        if choice == '2':
            main_batch()
            return
    
    # Режим одного кошелька (оригинальный код)
    pk_b58 = os.getenv("PRIVATE_KEY")
    if not pk_b58:
        raise SystemExit("PRIVATE_KEY not found in .env")
    
    result = process_wallet(pk_b58)
    print(f"\n🎯 РЕЗУЛЬТАТ:")
    print(f"   Кошелек: {result['wallet_address']}")
    print(f"   Статус: {'✅ ELIGIBLE' if result['eligible'] else '❌ NOT ELIGIBLE'}")
    if result['eligible']:
        print(f"   Total Allocation: {result['total_allocation_formatted']}")
    
    # Сохраняем результат одного кошелька в CSV
    save_to_csv([result])

if __name__ == "__main__":
    main()

