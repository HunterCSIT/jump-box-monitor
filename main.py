
from abc import ABC, abstractmethod
import argparse
import json
import logging
import hashlib
import os
import os.path
import pathlib
import re
import subprocess
import sys
import time
import typing


BASE_DIR = pathlib.Path(__file__).parent.absolute()
DATA_DIR = os.path.join(BASE_DIR, "data")

ALERT_SNOOZE_TIME_SECONDS = 60 * 60 * 6

# Resource usage max thresholds
ALERT_MAX_MEMORY_USAGE_PERCENT = 0.33
ALERT_MAX_CPU_USAGE_PERCENT = 0.33
ALERT_MAX_DISK_USAGE_PERCENT = 0.33


# # Data caching logic # # # # # #

def md5sum(value: str):
    return hashlib.md5(value.encode()).hexdigest()

def now_ts() -> int:
    return round(time.time())

class DataCacheMissError(Exception):
    pass

def read_saved_value(key: str):
    data_file_path = os.path.join(DATA_DIR, key)
    try:
        with open(data_file_path) as f:
            data = json.load(f)
    except IOError as e:
        raise DataCacheMissError from e
    if data.get("expired_at"):
        if data["expired_at"] > now_ts():
            os.remove(data_file_path)
            raise DataCacheMissError()
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


# Shell Command Runner
class ShellError(Exception):
    pass
def run_shell_command(*command_parts):
    try:
        result = subprocess.run(command_parts, capture_output=True, check=True)
    except subprocess.CalledProcessError as e:
        raise ShellError from e
    return result.stdout.decode().strip("\n")

# Alert type definitions # # # # # #

class AlertType:
    PROCESS = "PROCESS"
    RESOURCES = "RESOURCES"

class ResourceNames:
    MEMORY = "MEMORY"
    CPU = "CPU"
    DISK = "DISK"

class BaseAlert(ABC):
    @abstractmethod
    def to_key_name(self) -> str:
        pass

class SystemResourceUsageAlert(BaseAlert):

    def __init__(
        self,
        resource_name: str,
        resource_usage: str,
        resource_capacity: str
    ):
        self.resource_name = resource_name
        self.resource_usage = resource_usage
        self.resource_capacity = resource_capacity

    def to_key_name(self):
        return self.resource_name

    def __str__(self):
        return f"<ResourceAlert {self.resource_name}>"


class ProcessAlert(BaseAlert):
    def __init__(
        self,
        process_id: str,
        user_uid: int,
        command: str,
        age_seconds: int,
        memory_usage_mb: str,
        cpu_usage_percent: str,
    ):
        self.process_id = process_id
        self.user_uid = user_uid
        self.user_name = None
        self.command = command
        self.age_seconds = age_seconds
        self.memory_usage_mb = memory_usage_mb
        self.cpu_usage_percent = cpu_usage_percent

        self.enrich()

    def enrich(self):
        try:
            self.user_name = run_shell_command("id", "-nu", str(self.user_uid))
        except ShellError:
            self.user_name = "UNKNOWN"

    def to_key_name(self):
        return md5sum(f"{self.process_id}-{self.user_uid}")

    def __str__(self):
        return f"<ProcessAlert {self.process_id}>"


# # Check for resource alerts # # # # # #

def _get_memory_usage() -> typing.List[int]:
    total_usage_row = run_shell_command("free", "-t", "-m").split("\n")[-1]
    if not total_usage_row.startswith("Total: "):
        raise Exception("final row expected to start with 'Total: '")

    # Replace consecutuve spaces with single space,
    # Total_usage_row looks like this now 'Total: 17847 3370 9202'
    total_usage_row = re.sub(r"\s+", " ", total_usage_row)
    # Split total row into columns.
    [total, used, free] = [
        int(v) for v in total_usage_row.split(" ")
        if v and re.match(r"^\d+$", v)
    ]
    return [total, used, free]

def _check_cpu_usage() -> float:
    # return cpu usage as a percentage
    outText=run_shell_command("grep", "cpu", "/proc/stat")
    print(outText)

def get_system_resource_usage_alerts(logger) -> typing.List[SystemResourceUsageAlert]:
    # check memory usage
    [total_memory, used_memory, free_memory] = _get_memory_usage()
    logger.debug(f"memory usage {[total_memory, used_memory, free_memory]}")

    # CPU usage
    cpu_useage = _check_cpu_usage()
    logger.debug(f"cpu usage % {cpu_useage}")



# # Check for processes alerts # # # # # #

def get_processes_alerts(logger) -> typing.List[ProcessAlert]:
    pass



# # # Script Entry Point # # # # # # # # #

def main(debug: bool, logger: logging.Logger):
    resource_alerts = get_system_resource_usage_alerts(logger)
    process_alerts = get_processes_alerts(logger)


if __name__ == "__main__":
    debug = True

    # check if production. If prod = True, no console logging and send alerts
    #                      If prod = False, log to console, show alerts in console.
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--production', action='store_true')
    args = parser.parse_args()

    logger = logging.getLogger("jump-box-monitor")
    logger.setLevel(logging.DEBUG)
    if args.production:
        logger.addHandler(logging.NullHandler())
    else:
        logger.addHandler(logging.StreamHandler(sys.stdout))

    main(debug, logger)
