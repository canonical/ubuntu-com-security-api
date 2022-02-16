import os

 # Patch psycopg2 for gevent before importing any sqlalchemy stuff
from psycogreen.gevent import patch_psycopg

patch_psycopg()

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.engine.reflection import Inspector  # noqa: E402
from sqlalchemy.orm import scoped_session, sessionmaker  # noqa: E402

from webapp.models import Release  # noqa: E402

db_engine = create_engine(os.environ["DATABASE_URL"])
db_session = scoped_session(
    sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=db_engine,
    )
)

inspector = Inspector.from_engine(db_engine)

release_codenames = []
if "release" in inspector.get_table_names():
    release_codenames = [
        rel.codename for rel in db_session.query(Release).all()
    ]

status_statuses = []
for enum in inspector.get_enums():
    if enum["name"] == "statuses":
        status_statuses = enum["labels"]
