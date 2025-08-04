# Standard library
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable

# Packages
import flask
from flask.logging import default_handler
from launchpadlib.credentials import (
    AuthorizeRequestTokenWithURL,
    Credentials,
    MemoryCredentialStore,
)
from launchpadlib.launchpad import Launchpad
from lazr.restfulclient.errors import HTTPError
from macaroonbakery import bakery, checkers, httpbakery

logger = logging.getLogger()
logger.addHandler(default_handler)

AUTHORIZED_TEAMS = [
    "canonical-security-web",
    "canonical-security",
    "canonical-webmonkeys",
]

IDENTITY_CAVEATS = [
    checkers.need_declared_caveat(
        checkers.Caveat(
            location="https://api.jujucharms.com/identity",
            condition="is-authenticated-user",
        ),
        ["username"],
    ),
]


def is_authorized_user(
    launchpad: Launchpad,
    username: str | None = None,
) -> bool:
    """Check if the user is authorized to access the API.

    Args:
        launchpad: The Launchpad instance.
        username: The Launchpad user object.

    Returns:
        bool: True if the user is authorized, False otherwise.

    """
    launchpad_user = launchpad.people(username) if username else launchpad.me
    for team in AUTHORIZED_TEAMS:
        if launchpad_user in launchpad.people(team).members:
            return True
    return False


class Identity(bakery.Identity):
    """Identity information for a Candid third party caveat."""

    def __init__(self, identity):
        parts = identity.split("@", 1)
        self._username = parts[0]
        self._domain = parts[1] if len(parts) == 2 else ""

    def username(self):
        return self._username

    def domain(self):
        return self._domain


class IdentityClient(bakery.IdentityClient):
    """Basic identity client based on the username returned by Candid."""

    def identity_from_context(self, ctx):
        return None, IDENTITY_CAVEATS

    def declared_identity(self, ctx, declared):
        """Return the identity from the given declared attributes."""
        username = declared.get("username")
        if username is None:
            raise bakery.IdentityError("no username found")
        return Identity(username)


def authorization_required(func):
    """Decorator that checks if a user is logged in, and redirects
    to login page if not.
    """

    @wraps(func)
    def is_authorized(*args, **kwargs):
        macaroon_bakery = bakery.Bakery(
            location="ubuntu.com/security",
            locator=httpbakery.ThirdPartyLocator(),
            identity_client=IdentityClient(),
            key=bakery.generate_key(),
            root_key_store=bakery.MemoryKeyStore(
                flask.current_app.config["SECRET_KEY"],
            ),
        )
        macaroons = httpbakery.extract_macaroons(flask.request.headers)
        auth_checker = macaroon_bakery.checker.auth(macaroons)
        launchpad = Launchpad.login_anonymously(
            "ubuntu.com/security",
            "production",
            version="devel",
        )

        try:
            auth_info = auth_checker.allow(
                checkers.AuthContext(),
                [bakery.LOGIN_OP],
            )
        except bakery._error.DischargeRequiredError:
            macaroon = macaroon_bakery.oven.macaroon(
                version=bakery.VERSION_2,
                expiry=datetime.utcnow() + timedelta(weeks=4),
                caveats=IDENTITY_CAVEATS,
                ops=[bakery.LOGIN_OP],
            )

            content, headers = httpbakery.discharge_required_response(
                macaroon,
                "/",
                "cookie-suffix",
            )
            return content, 401, headers

        username = auth_info.identity.username()

        if not is_authorized_user(launchpad, username):
            return (
                f"{username} is not in any of the authorized teams: "
                f"{AUTHORIZED_TEAMS!s}",
                401,
            )

        # Validate authentication token
        return func(*args, **kwargs)

    return is_authorized


def async_process_request(
    credentials: Credentials,
    request: Callable,
    *args: tuple,
    **kwargs: dict,
) -> Any:
    """Process the request asynchronously.

    Args:
        credentials: The credentials object.
        request: The request function.
        args: The positional arguments.
        kwargs: The keyword arguments.

    Returns:
        The result of the request function.

    """
    for retry in range(3, 6):
        try:
            credentials.exchange_request_token_for_access_token(
                web_root="production",
            )
            launchpad = Launchpad(
                credentials=credentials,
                credential_store=MemoryCredentialStore(),
                authorization_engine=AuthorizeRequestTokenWithURL(
                    application_name="ubuntu.com/security",
                    service_root="production",
                ),
                service_root="production",
            )
            if is_authorized_user(launchpad):
                logger.info(
                    "[AUTHWORKER] User is authorized, proceeding with request",
                )
                return request(*args, **kwargs)
        except HTTPError:
            delay = 2**retry
            logger.info(
                "[AUTHWORKER] Waiting for access token."
                " Trying again in %d seconds...",
                delay,
            )
            time.sleep(delay)
    return "Authorization failed after multiple attempts", 401


def oauth_authorization_required(func: Callable) -> Callable:
    """Check if a user is logged in, and redirect.

    Args:
        func: The function to be decorated.

    Returns:
        The decorated function.

    """

    @wraps(func)
    def is_authorized(*args: tuple, **kwargs: dict) -> tuple[str, int]:
        """Validate authentication token or return 302."""
        credentials = Credentials("ubuntu.com/security")
        request_token_info: str = credentials.get_request_token(
            web_root="production",
        )
        # Wait for authorization in a separate thread
        thread = threading.Thread(
            target=async_process_request,
            args=(credentials, func, *args),
            kwargs=kwargs,
        )
        thread.start()
        return request_token_info, 302

    return is_authorized
