from functools import wraps


def mock_auth_decorator():
    def auth_decorator(f):
        @wraps(f)
        def auth_decorated_function(*args, **kwargs):
            return f(*args, **kwargs)

        return auth_decorated_function

    return auth_decorator
