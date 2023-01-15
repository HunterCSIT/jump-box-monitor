
import json
import os
import typing

from utils.helpers import now_ts
from constants import DATA_DIR



class DataCacheMissError(Exception):
    pass

class DataCacheKeyExpired(Exception):
    pass

def read_saved_value(key: str):
    data_file_path = os.path.join(DATA_DIR, key)
    try:
        with open(data_file_path) as f:
            data = json.load(f)
    except IOError as e:
        raise DataCacheMissError from e
    if data.get("expired_at"):
        if data["expired_at"] < now_ts():
            os.remove(data_file_path)
            raise DataCacheKeyExpired()
    return data['payload']

def write_saved_value(
    key: str,
    value: typing.Any,
    ttl_seconds: typing.Union[None, int]
):
    data = {'payload': value}
    if ttl_seconds is not None:
        data['expired_at'] = now_ts() + ttl_seconds
    with open(os.path.join(DATA_DIR, key), "w") as f:
        json.dump(data, f)
