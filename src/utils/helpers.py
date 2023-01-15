
import hashlib
import time

def md5sum(value: str):
    return hashlib.md5(value.encode()).hexdigest()

def now_ts() -> int:
    return round(time.time())
