#!/usr/bin/env python3
"""
netspeed: замер скорости скачивания с заданного адреса.

Скрипт делает несколько запросов подряд (по умолчанию 10) и каждый раз
ждёт, пока ответ придёт целиком. Для каждого запроса он отдельно засекает,
сколько времени ушло на каждый этап:

    DNS        узнать IP-адрес сервера по его имени
    TCP        подключиться к серверу
    TLS        договориться о шифровании (только для https)
    ожидание   отправить запрос и дождаться начала ответа
    скачивание получить сам файл

В конце печатает общий объём, среднее время запроса и скорость.

Нужен только Python 3.8+, сторонние библиотеки не используются.
"""

import argparse
import http.client
import json
import secrets
import socket
import ssl
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

CHUNK_SIZE = 64 * 1024        # читаем ответ кусками по 64 КБ
MAX_REDIRECTS = 5             # больше пяти переадресаций подряд считаем ошибкой
REDIRECT_CODES = {301, 302, 303, 307, 308}
USER_AGENT = "netspeed/1.0 (+https://github.com/getrismine/netspeed)"


class FetchError(Exception):
    """Запрос не удался: нет сети, сервер вернул ошибку или ответ оборвался."""


@dataclass
class Timing:
    """Итог одного запроса. Все времена в секундах, размер в байтах."""

    status: int = 0          # код ответа сервера, например 200
    bytes: int = 0           # сколько байт пришло в теле ответа
    dns: float = 0.0
    tcp: float = 0.0
    tls: float = 0.0
    wait: float = 0.0
    download: float = 0.0
    total: float = 0.0       # всё время запроса от начала до последнего байта
    redirects: int = 0       # сколько раз сервер отправил нас по другому адресу
    final_url: str = ""      # адрес, с которого в итоге скачали


# ---------- единицы измерения ----------

def to_mbit_per_s(n_bytes, seconds):
    """Байты за время -> мегабиты в секунду. 1 байт = 8 бит, 1 Мбит = 1 000 000 бит."""
    if seconds <= 0:
        return 0.0
    return n_bytes * 8 / seconds / 1_000_000


def to_mbyte_per_s(n_bytes, seconds):
    """Байты за время -> мегабайты в секунду. 1 МБ = 1 000 000 байт."""
    if seconds <= 0:
        return 0.0
    return n_bytes / seconds / 1_000_000


def format_size(n_bytes):
    """Размер для людей: 800 Б, 512.0 КБ, 10.00 МБ (КБ и МБ считаем по 1000)."""
    if n_bytes < 1000:
        return f"{n_bytes} Б"
    if n_bytes < 1_000_000:
        return f"{n_bytes / 1000:.1f} КБ"
    return f"{n_bytes / 1_000_000:.2f} МБ"


def format_time(seconds):
    """Время для людей: до секунды в миллисекундах, дальше в секундах."""
    if seconds < 0.01:
        return f"{seconds * 1000:.1f} мс"     # совсем короткие этапы с десятыми долями
    if seconds < 1:
        return f"{seconds * 1000:.0f} мс"
    return f"{seconds:.2f} с"


# ---------- один запрос ----------

def add_cache_buster(url):
    """Дописывает к адресу случайный параметр.

    Для сервера и CDN это каждый раз новый адрес, поэтому они не могут отдать
    готовую копию из кэша, и мы меряем настоящую передачу данных.
    Часть после # браузер серверу не отправляет, поэтому её убираем.
    """
    parts = urlsplit(url)
    extra = "_nocache=" + secrets.token_hex(8)
    query = parts.query + "&" + extra if parts.query else extra
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def open_connection(host, port, use_tls, timeout, timing):
    """Подключается к серверу вручную, чтобы засечь DNS, TCP и TLS по отдельности."""

    # 1. DNS: узнаём IP-адреса сервера по имени
    started = time.perf_counter()
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise FetchError(f"не удалось найти адрес {host}: {error}") from error
    timing.dns += time.perf_counter() - started

    # 2. TCP: у сервера может быть несколько адресов (IPv4 и IPv6),
    #    пробуем по очереди, пока какой-нибудь не ответит
    started = time.perf_counter()
    sock = None
    last_error = None
    for family, kind, proto, _, address in addresses:
        try:
            sock = socket.socket(family, kind, proto)
            sock.settimeout(timeout)
            sock.connect(address)
            break
        except OSError as error:
            last_error = error
            sock.close()
            sock = None
    if sock is None:
        raise FetchError(f"не удалось подключиться к {host}:{port}: {last_error}")
    timing.tcp += time.perf_counter() - started

    # 3. TLS: для https договариваемся о шифровании и проверяем сертификат
    if use_tls:
        started = time.perf_counter()
        context = ssl.create_default_context()
        try:
            sock = context.wrap_socket(sock, server_hostname=host)
        except OSError as error:
            sock.close()
            raise FetchError(f"не удалось установить защищённое соединение: {error}") from error
        timing.tls += time.perf_counter() - started

    return sock


def fetch_once(url, timeout=30.0, on_progress=None):
    """Скачивает адрес один раз через новое соединение и возвращает Timing.

    on_progress(получено, всего) вызывается после каждого куска данных,
    всего = None, если сервер не сообщил размер.
    """
    timing = Timing()
    started_total = time.perf_counter()

    for _ in range(MAX_REDIRECTS + 1):
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise FetchError(f"поддерживаются только http и https: {url}")
        if not parts.hostname:
            raise FetchError(f"в адресе нет имени сервера: {url}")
        use_tls = parts.scheme == "https"
        try:
            port = parts.port or (443 if use_tls else 80)
        except ValueError as error:
            raise FetchError(f"неправильный порт в адресе: {url}") from error

        sock = open_connection(parts.hostname, port, use_tls, timeout, timing)

        # Подключение уже готово, отдаём его http.client: он сам подключаться
        # не будет и только отправит запрос и разберёт ответ
        connection_class = http.client.HTTPSConnection if use_tls else http.client.HTTPConnection
        conn = connection_class(parts.hostname, port, timeout=timeout)
        conn.sock = sock

        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        headers = {
            "User-Agent": USER_AGENT,
            # просим не сжимать ответ: со сжатием по сети пройдёт меньше байт, чем весит файл
            "Accept-Encoding": "identity",
            # просим промежуточные кэши не подсовывать сохранённую копию
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            # после ответа соединение закрываем, следующий запрос откроет новое
            "Connection": "close",
        }

        try:
            # ожидание: от отправки запроса до прихода заголовков ответа
            started = time.perf_counter()
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            timing.wait += time.perf_counter() - started

            location = response.getheader("Location")
            if response.status in REDIRECT_CODES and location:
                # сервер говорит «файл лежит по другому адресу», идём туда
                url = urljoin(url, location)
                timing.redirects += 1
                continue

            if response.status >= 400:
                raise FetchError(f"сервер ответил ошибкой {response.status} {response.reason}")

            length_header = response.getheader("Content-Length", "")
            expected = int(length_header) if length_header.isdigit() else None

            # скачивание: читаем тело ответа кусками и считаем байты
            started = time.perf_counter()
            received = 0
            while True:
                chunk = response.read(CHUNK_SIZE)
                if not chunk:
                    break
                received += len(chunk)
                if on_progress:
                    on_progress(received, expected)
            timing.download += time.perf_counter() - started

            # http.client молча останавливается, если связь оборвалась раньше
            # времени, поэтому сверяем полученное с обещанным размером сами
            if expected is not None and received < expected:
                raise FetchError(f"ответ оборвался: пришло {received} из {expected} байт")

        except (OSError, http.client.HTTPException) as error:
            raise FetchError(f"ошибка во время запроса: {error}") from error
        finally:
            conn.close()

        timing.status = response.status
        timing.bytes = received
        timing.final_url = url
        timing.total = time.perf_counter() - started_total
        return timing

    raise FetchError(f"слишком много переадресаций (больше {MAX_REDIRECTS})")


# ---------- серия запросов и итоги ----------

PHASES = ("dns", "tcp", "tls", "wait", "download")
PHASE_NAMES = {
    "dns": "DNS",
    "tcp": "TCP",
    "tls": "TLS",
    "wait": "ожидание",
    "download": "скачивание",
}


def summarize(timings):
    """Считает итоги по списку запросов."""
    count = len(timings)
    total_bytes = sum(t.bytes for t in timings)
    total_time = sum(t.total for t in timings)
    download_time = sum(t.download for t in timings)
    durations = [t.total for t in timings]

    return {
        "requests": count,
        "total_bytes": total_bytes,
        "avg_time_s": total_time / count,
        "median_time_s": statistics.median(durations),
        "min_time_s": min(durations),
        "max_time_s": max(durations),
        # стандартное отклонение: насколько в среднем время запроса гуляет вокруг среднего
        "stdev_time_s": statistics.stdev(durations) if count > 1 else 0.0,
        # главная скорость: весь объём / всё время запросов целиком
        "speed_mbit_s": to_mbit_per_s(total_bytes, total_time),
        "speed_mbyte_s": to_mbyte_per_s(total_bytes, total_time),
        # «чистая» скорость: только время, пока шло тело ответа
        "download_speed_mbit_s": to_mbit_per_s(total_bytes, download_time),
        "download_speed_mbyte_s": to_mbyte_per_s(total_bytes, download_time),
        # сколько в среднем на запрос ушло на каждый этап
        "avg_phase_s": {p: sum(getattr(t, p) for t in timings) / count for p in PHASES},
    }


# ---------- вывод в консоль ----------

TABLE_HEADER = (
    f"{'№':>3}  {'код':>3}  {'размер':>10}  {'DNS':>7}  {'TCP':>7}  {'TLS':>7}"
    f"  {'ожидание':>8}  {'скачивание':>10}  {'всего':>8}  {'скорость':>13}"
)


def format_row(number, t):
    """Одна строка таблицы для одного запроса."""
    speed = to_mbit_per_s(t.bytes, t.total)
    row = (
        f"{number:>3}  {t.status:>3}  {format_size(t.bytes):>10}  {format_time(t.dns):>7}"
        f"  {format_time(t.tcp):>7}  {format_time(t.tls):>7}  {format_time(t.wait):>8}"
        f"  {format_time(t.download):>10}  {format_time(t.total):>8}  {speed:>7.1f} Мбит/с"
    )
    if t.redirects:
        row += f"  (переадресаций: {t.redirects})"
    return row


def format_summary(s):
    """Блок итогов после таблицы."""
    phases = ", ".join(f"{PHASE_NAMES[p]} {format_time(s['avg_phase_s'][p])}" for p in PHASES)
    return "\n".join([
        "",
        f"Запросов:               {s['requests']}",
        f"Скачано всего:          {format_size(s['total_bytes'])} ({s['total_bytes']:,} байт)".replace(",", " "),
        f"Среднее время запроса:  {format_time(s['avg_time_s'])}",
        f"  медиана {format_time(s['median_time_s'])}, мин {format_time(s['min_time_s'])}, "
        f"макс {format_time(s['max_time_s'])}, отклонение {format_time(s['stdev_time_s'])}",
        f"Скорость скачивания:    {s['speed_mbit_s']:.2f} Мбит/с ({s['speed_mbyte_s']:.2f} МБ/с)",
        f"Чистая скорость:        {s['download_speed_mbit_s']:.2f} Мбит/с ({s['download_speed_mbyte_s']:.2f} МБ/с)"
        "  без учёта подключения и ожидания",
        f"В среднем на запрос:    {phases}",
    ])


class ProgressLine:
    """Строка прогресса, которая перерисовывается на месте через символ \\r."""

    WIDTH = 60

    def __init__(self, stream, number):
        self.stream = stream
        self.number = number
        self.last_draw = 0.0

    def __call__(self, received, expected):
        now = time.perf_counter()
        if now - self.last_draw < 0.1:      # не чаще 10 раз в секунду, чтобы не тормозить замер
            return
        self.last_draw = now
        if expected:
            text = f"  запрос {self.number}: {received * 100 / expected:5.1f}%  {format_size(received)}"
        else:
            text = f"  запрос {self.number}: {format_size(received)}"
        self.stream.write("\r" + text.ljust(self.WIDTH))
        self.stream.flush()

    def clear(self):
        self.stream.write("\r" + " " * self.WIDTH + "\r")
        self.stream.flush()


# ---------- запуск из командной строки ----------

def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="netspeed",
        description="Замеряет скорость скачивания: делает несколько запросов подряд "
                    "к адресу и считает среднее время, объём и скорость.",
    )
    parser.add_argument("url", help="адрес файла, например https://speed.cloudflare.com/__down?bytes=10000000")
    parser.add_argument("-n", "--count", type=int, default=10, help="сколько запросов сделать (по умолчанию 10)")
    parser.add_argument("-t", "--timeout", type=float, default=30.0,
                        help="сколько секунд ждать сеть, прежде чем сдаться (по умолчанию 30)")
    parser.add_argument("--no-cache-bust", action="store_true",
                        help="не добавлять к адресу случайный параметр (нужно для подписанных ссылок)")
    parser.add_argument("--json", action="store_true", help="вывести результат в формате JSON")
    args = parser.parse_args(argv)
    if args.count < 1:
        parser.error("число запросов должно быть не меньше 1")
    if args.timeout <= 0:
        parser.error("таймаут должен быть больше нуля")
    if "://" not in args.url:
        args.url = "https://" + args.url     # разрешаем писать адрес без https://
    return args


def main(argv=None):
    args = parse_args(argv)
    out = sys.stdout
    show_progress = not args.json and sys.stderr.isatty()

    if not args.json:
        print(f"Адрес: {args.url}", file=out)
        print(f"Запросов: {args.count}, каждый через новое соединение\n", file=out)
        print(TABLE_HEADER, file=out)

    timings = []
    try:
        for number in range(1, args.count + 1):
            url = args.url if args.no_cache_bust else add_cache_buster(args.url)
            progress = ProgressLine(sys.stderr, number) if show_progress else None
            try:
                timing = fetch_once(url, timeout=args.timeout, on_progress=progress)
            finally:
                if progress:
                    progress.clear()
            timings.append(timing)
            if not args.json:
                print(format_row(number, timing), file=out, flush=True)
    except FetchError as error:
        print(f"\nОшибка в запросе {len(timings) + 1}: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nОстановлено пользователем", file=sys.stderr)
        return 130

    summary = summarize(timings)
    if args.json:
        result = {
            "url": args.url,
            "units": {"time": "s", "size": "bytes", "speed": "Mbit/s и MB/s (1 Мбит = 10^6 бит, 1 МБ = 10^6 байт)"},
            "requests": [asdict(t) for t in timings],
            "summary": summary,
        }
        print(json.dumps(result, ensure_ascii=False, indent=2), file=out)
    else:
        print(format_summary(summary), file=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
