
import json
import typing
import urllib.request

from constants import HTTP_TIMEOUT_SECONDS


def http_post_with_json(url: str, data: typing.Dict, headers: typing.Dict = {}):
    payload = json.dumps(data).encode('utf-8')
    return urllib.request.urlopen(
        urllib.request.Request(
            url,
            headers={
                'Content-Type': 'application/json',
                'Content-Length': len(payload),
                **headers,
            }
        ),
        data=payload,
        timeout=HTTP_TIMEOUT_SECONDS,
    )
