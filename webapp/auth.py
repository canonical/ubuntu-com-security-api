# Standard library
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from functools import wraps
import threading
import time
from typing import Any, Callable

# Packages
import flask
import requests
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from flask.logging import default_handler
from launchpadlib.launchpad import Launchpad
from macaroonbakery import bakery, checkers, httpbakery
from canonicalwebteam.flask_base.env import get_flask_env
from requests_oauthlib import OAuth1Session


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
        auth_type = flask.request.headers.get("Auth-Type")
        if auth_type and auth_type == "oauth":
            auth_fn = oauth_authorization_required(func)
            return auth_fn(*args, **kwargs)
        else:
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


TOKEN_DELIMITER = "␜"


def create_time_based_token(
    raw_token: str,
) -> str:
    """Create a time-based token for OAuth authorization.

    Returns:
        A string representing the time-based token.
    """
    current_time = str(int(datetime.now().timestamp()))
    salt = get_flask_env("OAUTH_TOKEN_SALT", error=True)
    fernet = Fernet(salt)

    # Add timestamp to the token and encrypt it
    token = fernet.encrypt(
        f"{raw_token}{TOKEN_DELIMITER}{current_time}".encode()
    ).decode()
    return token


def validate_time_based_token(token: str) -> bool:
    """Validate a time-based token for OAuth authorization.

    Args:
        token: The token to be validated.

    Returns:
        True if the token is valid, False otherwise.
    """
    try:
        salt = get_flask_env("OAUTH_TOKEN_SALT", error=True)
        fernet = Fernet(salt)
        decrypted = fernet.decrypt(token.encode()).decode()
        raw_token, timestamp = decrypted.rsplit(TOKEN_DELIMITER, 1)
        token_time = datetime.fromtimestamp(int(timestamp))
        if datetime.now() - token_time < timedelta(minutes=10):
            data = get_auth_params(raw_token)
            return verify_access_token(
                "ubuntu.com/security",
                data["oauth_token"],
                data["oauth_token_secret"],
            )
        else:
            logger.error("Token has expired.")
            return False
    except InvalidToken:
        pass
    logger.error(f"Invalid token provided for validation.{token}")
    return False


def get_auth_params(text: str) -> dict[str, str]:
    """Extract OAuth parameters from a given URI.

    Args:
        text: The URI containing OAuth parameters.
    """
    data = {}
    for i in text.split("&"):
        k, v = i.split("=")
        data[k] = v
    return data


def verify_access_token(
    consumer_key: str,
    oauth_token: str,
    oauth_token_secret: str,
) -> bool:
    """Verify if an access token is valid.

    Args:
        consumer_key: The Launchpad consumer key.
        oauth_token: The OAuth token to verify.
        oauth_token_secret: The OAuth token secret to verify.
    """
    lp = OAuth1Session(
        consumer_key,
        resource_owner_key=oauth_token,
        resource_owner_secret=oauth_token_secret,
        signature_method="PLAINTEXT",
    )
    res = lp.get("https://api.launchpad.net/beta/~sam-olwe")
    if res.status_code == 200:
        return True
    return False


def oauth_authorization_required(func: Callable) -> Callable:
    """Check if a user is logged in, and redirect.

    Args:
        func: The function to be decorated.

    Returns:
        The decorated function.

    """

    @wraps(func)
    def is_authorized(*args: tuple, **kwargs: dict) -> flask.Response:
        """Validate authentication token or return 302."""

        # Check if the Authorization header is present, and valid
        if auth_header := flask.request.headers.get("Authorization"):
            token = auth_header.replace("Bearer ", "")
            if validate_time_based_token(token):
                return func(*args, **kwargs)

        # If not authorized, initiate OAuth flow
        res = requests.post(
            "https://launchpad.net/+request-token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "oauth_consumer_key": "ubuntu.com/security",
                "oauth_signature_method": "PLAINTEXT",
                "oauth_signature": "&",
            },
        )
        data = get_auth_params(res.text)
        token = create_time_based_token(res.text)

        # Wait for authorization in a separate thread
        thread = threading.Thread(
            target=async_process_request,
            args=(
                data["oauth_token"],
                data["oauth_token_secret"],
                func,
                *args,
            ),
            kwargs=kwargs,
        )
        thread.start()

        auth_url = (
            "https://launchpad.net/+authorize-token?"
            f"oauth_token={data['oauth_token']}"
        )
        response = flask.make_response(auth_url, 302)
        response.headers["Auth-Token"] = token
        return response

    return is_authorized


def async_process_request(
    oauth_token: str,
    oauth_token_secret: str,
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
        if verify_access_token(
            "ubuntu.com/security",
            oauth_token,
            oauth_token_secret,
        ):
            logger.info(
                "[AUTHWORKER] User is authorized, proceeding with request",
            )
            return request(*args, **kwargs)
        else:
            delay = 2**retry
            logger.info(
                "[AUTHWORKER] Waiting for access token."
                " Trying again din %d seconds...",
                delay,
            )
            time.sleep(3)

    return "Authorization failed after multiple attempts", 401
