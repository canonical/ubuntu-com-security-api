import json
from typing import Generator

from sqlalchemy.orm import Query

from webapp.schemas import NoticeAPIDetailedSchema


def stream_notices(
    notices_query: Query, offset: int, limit: int, total_count: int
) -> Generator[str, None, None]:
    """
    Stream notices as JSON object in chunks with one notice at a time.
    """
    notice_schema = NoticeAPIDetailedSchema()
    yield '{"notices":['
    first = True
    for notice in notices_query.offset(offset).limit(limit).yield_per(1):
        if not first:
            yield ","
        else:
            first = False
        yield json.dumps(notice_schema.dump(notice))
    yield f'],"offset":{offset},"limit":{limit},"total_results":{total_count}}}'
