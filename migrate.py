from flask_migrate import upgrade

from webapp.app import app
from webapp.context import database_lock


def migrate() -> None:
    # Use lock to prevent multiple concurrent migrations on startup
    # Automatically upgrade to head revision
    with app.app_context(), database_lock():
        upgrade()


if __name__ == "__main__":
    migrate()