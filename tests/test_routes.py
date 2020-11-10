# Standard library
import unittest

# Local
from webapp.app import app


class TestRoutes(unittest.TestCase):
    def setUp(self):
        app.testing = True
        self.client = app.test_client()

        return super().setUp()

    def test_hello_world(self):
        self.assertEqual(self.client.get("/hello-world").status_code, 200)

    def test_spec(self):
        self.assertEqual(self.client.get("/spec").status_code, 200)

    def test_docs(self):
        self.assertEqual(self.client.get("/docs").status_code, 200)
