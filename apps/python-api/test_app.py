"""HTTP-level tests for the health service."""

import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from app import HealthHandler


class HealthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), HealthHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, path):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=2
        )
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            body = response.read()
            self.assertEqual(response.getheader("Content-Length"), str(len(body)))
            self.assertEqual(
                response.getheader("Content-Type"), "application/json; charset=utf-8"
            )
            self.assertEqual(response.getheader("Cache-Control"), "no-store")
            return response.status, json.loads(body)
        finally:
            connection.close()

    def test_health(self):
        self.assertEqual(self.request("/health"), (200, {"status": "ok"}))

    def test_unknown_path(self):
        self.assertEqual(self.request("/missing"), (404, {"error": "not found"}))

    def test_query_is_not_health(self):
        self.assertEqual(self.request("/health?x=1"), (404, {"error": "not found"}))


if __name__ == "__main__":
    unittest.main()
