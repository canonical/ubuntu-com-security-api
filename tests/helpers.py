from functools import wraps
from webapp import auth


def transparent_decorator(function):
    """
    A function to act as a decorator that does nothing.

    This can be helpful for monkey-patching a decorator
    that you want to simply disable within a codebase.

    E.g.:

    webapp.auth.authorization_required = transparent_decorator
    """

    @wraps(function)
    def transparent_wrapper(*args, **kwargs):
        return function(*args, **kwargs)

    return transparent_wrapper


def monkey_patch_auth():
    """
    Monkey-patch webapp.auth.authorization_required to make it a plain
    passthrough decorator function. This will allow views decorated with
    authorization_required to run without authentication.

    This is hacky, I wish we had a better way of testing login.

    NB: This must be run before webapp.app or webapp.views is imported.
    """

    def permission_granted(function):
        @wraps(function)
        def granted(*args, **kwargs):
            return function(*args, **kwargs)

        return granted

    auth.authorization_required = permission_granted
