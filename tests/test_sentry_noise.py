"""raven's failure logs must not become Sentry events of their own."""

import logging
import unittest

import sentry_sdk

import webapp.app  # noqa: F401  registers the ignored loggers


class SentryNoise(unittest.TestCase):
    def setUp(self):
        self.events = []
        # before_send returning None drops the event, so nothing is sent.
        sentry_sdk.init(
            dsn="https://key@localhost/1",
            before_send=lambda event, hint: self.events.append(event),
        )
        self.addCleanup(sentry_sdk.init)

    def test_raven_failure_logs_are_not_reported(self):
        logging.getLogger("sentry.errors").error(
            "Sentry responded with an error: %s", "no wrap_socket"
        )
        logging.getLogger("sentry.errors.uncaught").error("['lost event']")
        logging.getLogger("webapp.views").error("a real error")

        self.assertEqual(
            [event["logentry"]["message"] for event in self.events],
            ["a real error"],
        )
