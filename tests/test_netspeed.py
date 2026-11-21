"""Тесты для netspeed. Запуск из корня репозитория: python -m unittest -v

Тесты не ходят в интернет: поднимают свой маленький HTTP-сервер на этом
компьютере, который отдаёт файл заранее известного размера.
"""

import contextlib
import io
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import netspeed  # noqa: E402

FILE_SIZE = 300_000   # 300 КБ, больше одного куска чтения (64 КБ)


class TestHandler(BaseHTTPRequestHandler):
    """Сервер для тестов. Что отдать, решает путь в адресе."""

    seen_paths = []      # сюда складываем запрошенные адреса, чтобы проверить их в тестах
    last_headers = {}    # заголовки последнего запроса

    def do_GET(self):
        TestHandler.seen_paths.append(self.path)
        TestHandler.last_headers = dict(self.headers)
        path = urlsplit(self.path).path
        if path == "/file":
            self.send_body(b"x" * FILE_SIZE)
        elif path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/file")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/short":
            # обещаем 1000 байт, отдаём 500 и закрываем соединение
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            self.wfile.write(b"x" * 500)
            self.close_connection = True
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def send_body(self, body):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass   # не засоряем вывод тестов логами сервера


class NetspeedTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # порт 0 значит «дай любой свободный»
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), TestHandler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        TestHandler.seen_paths.clear()

    # --- единицы ---

    def test_units(self):
        # 1 000 000 байт за 1 секунду = 8 Мбит/с = 1 МБ/с
        self.assertAlmostEqual(netspeed.to_mbit_per_s(1_000_000, 1.0), 8.0)
        self.assertAlmostEqual(netspeed.to_mbyte_per_s(1_000_000, 1.0), 1.0)
        self.assertAlmostEqual(netspeed.to_mbit_per_s(12_500_000, 2.0), 50.0)
        self.assertEqual(netspeed.to_mbit_per_s(100, 0), 0.0)

    def test_format(self):
        self.assertEqual(netspeed.format_size(999), "999 Б")
        self.assertEqual(netspeed.format_size(10_000_000), "10.00 МБ")
        self.assertEqual(netspeed.format_time(0.25), "250 мс")
        self.assertEqual(netspeed.format_time(1.5), "1.50 с")

    # --- один запрос ---

    def test_counts_all_bytes(self):
        timing = netspeed.fetch_once(self.base + "/file")
        self.assertEqual(timing.status, 200)
        self.assertEqual(timing.bytes, FILE_SIZE)
        self.assertEqual(timing.tls, 0.0)    # обычный http, шифрования нет
        phases = timing.dns + timing.tcp + timing.wait + timing.download
        self.assertLessEqual(phases, timing.total)

    def test_progress_reaches_full_size(self):
        calls = []
        netspeed.fetch_once(self.base + "/file", on_progress=lambda got, total: calls.append((got, total)))
        self.assertEqual(calls[-1], (FILE_SIZE, FILE_SIZE))

    def test_follows_redirect(self):
        timing = netspeed.fetch_once(self.base + "/redirect")
        self.assertEqual(timing.redirects, 1)
        self.assertEqual(timing.bytes, FILE_SIZE)
        self.assertTrue(timing.final_url.endswith("/file"))

    def test_redirect_loop_is_error(self):
        with self.assertRaisesRegex(netspeed.FetchError, "переадресаций"):
            netspeed.fetch_once(self.base + "/loop")

    def test_http_error(self):
        with self.assertRaisesRegex(netspeed.FetchError, "404"):
            netspeed.fetch_once(self.base + "/missing")

    def test_truncated_response(self):
        with self.assertRaisesRegex(netspeed.FetchError, "500 из 1000"):
            netspeed.fetch_once(self.base + "/short")

    def test_sends_no_cache_headers(self):
        netspeed.fetch_once(self.base + "/file")
        headers = TestHandler.last_headers
        self.assertEqual(headers["Accept-Encoding"], "identity")
        self.assertEqual(headers["Cache-Control"], "no-cache")
        self.assertEqual(headers["Connection"], "close")

    def test_cache_buster(self):
        url = netspeed.add_cache_buster("https://example.com/f.bin?a=1#part")
        parts = urlsplit(url)
        query = parse_qs(parts.query)
        self.assertEqual(query["a"], ["1"])
        self.assertIn("_nocache", query)
        self.assertEqual(parts.fragment, "")
        self.assertNotEqual(url, netspeed.add_cache_buster("https://example.com/f.bin?a=1"))

    # --- вся программа ---

    def run_main(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = netspeed.main(list(args))
        return code, out.getvalue()

    def test_main_json(self):
        code, output = self.run_main(self.base + "/file", "-n", "3", "--json")
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(len(data["requests"]), 3)
        self.assertEqual(data["summary"]["total_bytes"], 3 * FILE_SIZE)
        # каждый запрос шёл с новым случайным параметром
        self.assertEqual(len(set(TestHandler.seen_paths)), 3)

    def test_main_no_cache_bust(self):
        code, _ = self.run_main(self.base + "/file", "-n", "2", "--no-cache-bust", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(TestHandler.seen_paths, ["/file", "/file"])

    def test_main_text_report(self):
        code, output = self.run_main(self.base + "/file", "-n", "2")
        self.assertEqual(code, 0)
        self.assertIn("Скачано всего:          600.0 КБ", output)
        self.assertIn("Мбит/с", output)

    def test_main_error_exit_code(self):
        code, _ = self.run_main(self.base + "/missing", "-n", "1")
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
