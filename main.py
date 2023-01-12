
#!/usr/bin/python3


from abc import ABC, abstractmethod
import argparse
import json
import logging
import hashlib
import itertools
import os
import os.path
import pathlib
import re
import subprocess
import sys
import time
import traceback
import typing

import psutil



BASE_DIR = pathlib.Path(__file__).parent.absolute()
DATA_DIR = os.path.join(BASE_DIR, "data")
PROD_LOG_PATH = os.path.join(BASE_DIR, "warnings.log")

ALERT_SNOOZE_TIME_SECONDS = 60 * 60 * 6

# Resource usage max thresholds
ALERT_MAX_MEMORY_USAGE_PERCENT = 0.33
ALERT_MAX_CPU_USAGE_PERCENT = 0.45
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
        if data["expired_at"] < now_ts():
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
    PROCESSES = "PROCESSES"
    RESOURCES = "RESOURCES"

class ResourceNames:
    MEMORY = "MEMORY"
    CPU = "CPU"
    DISK = "DISK"

class BaseAlert(ABC):

    alert_type = NotImplemented

    @abstractmethod
    def to_key_name(self) -> str:
        pass

class SystemResourceUsageAlert(BaseAlert):

    alert_type = AlertType.RESOURCES

    def __init__(
        self,
        resource_name: str,
        resource_usage_percent: float,
    ):
        self.resource_name = resource_name
        self.resource_usage_percent = resource_usage_percent

    def to_key_name(self):
        return self.resource_name

    def __str__(self):
        return f"<ResourceAlert {self.resource_name} @ {round(self.resource_usage_percent, 4)}>"


class ProcessAlert(BaseAlert):

    alert_type = AlertType.PROCESSES

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
        return f"<ProcessAlert pid{self.process_id} uid{self.user_uid}>"


# # Check for resource alerts # # # # # #

def get_system_resource_usage_alerts(logger) -> typing.List[SystemResourceUsageAlert]:
    # Memory
    memory_used_percent = psutil.virtual_memory().percent / 100
    logger.info(f"memory_used_percent {memory_used_percent}")
    # CPU
    cpu_useage_percent = psutil.cpu_percent(interval=0.5) / 100
    logger.info(f"cpu_useage_percent {cpu_useage_percent}")
    # Disk
    disk_useage_percent = psutil.disk_usage("/").percent / 100
    logger.info(f"disk_useage_percent {disk_useage_percent}")


    alerts = []
    if memory_used_percent > ALERT_MAX_MEMORY_USAGE_PERCENT:
        alerts.append(SystemResourceUsageAlert(
            ResourceNames.MEMORY,
            memory_used_percent
        ))
        logger.warning(f"creating alert for MEMORY usage")
    if cpu_useage_percent > ALERT_MAX_CPU_USAGE_PERCENT:
        alerts.append(SystemResourceUsageAlert(
            ResourceNames.CPU,
            cpu_useage_percent
        ))
        logger.warning(f"creating alert for CPU usage")
    if disk_useage_percent > ALERT_MAX_DISK_USAGE_PERCENT:
        alerts.append(SystemResourceUsageAlert(
            ResourceNames.DISK,
            disk_useage_percent
        ))
        logger.warning(f"creating alert for DISK usage")

    return alerts


# # Check for processes alerts # # # # # #

def get_processes_alerts(logger) -> typing.List[ProcessAlert]:
    alerts = []
    for proc in psutil.process_iter():
        pid = proc.pid
        username = proc.username()

    return alerts



# # # Script Entry Point # # # # # # # # #

def main(logger: logging.Logger) -> None:
    logger.debug("main method running")

    logger.debug("checking for alerts")
    resource_alerts = get_system_resource_usage_alerts(logger)
    process_alerts = get_processes_alerts(logger)
    if len(resource_alerts) == 0 and len(process_alerts) == 0:
        logger.debug("no alerts found")
        return

    if len(resource_alerts):
        logger.warning(f"found {len(resource_alerts)} resource alert(s)")
    if len(process_alerts):
        logger.warning(f"found {len(process_alerts)} process alert(s)")
    for alert in itertools.chain(resource_alerts, process_alerts):

        alert_cache_key = alert.to_key_name()
        try:
            # Check cache to see if we've sent an alert for this event recently.
            # We don't want to spam alerts.
            read_saved_value(alert_cache_key)
        except DataCacheMissError:
            send_alert = True
            logger.debug(f"cache miss, writing key to cache: {alert_cache_key}")
            write_saved_value(alert_cache_key, None, ALERT_SNOOZE_TIME_SECONDS)
        else:
            logger.debug("cache hit")
            logger.warning(f"not sending alert {alert}, cache key found")
            send_alert = False

        if send_alert:
            logger.warning(f" **** SENDING ALERT **** {alert}")



if __name__ == "__main__":

    # check if production. If prod = True, no console logging and send alerts
    #                      If prod = False, log to console, show alerts in console.
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--production', action='store_true')
    args = parser.parse_args()

    # Assemble logger instance
    logger = logging.getLogger("jump-box-monitor")
    logger.setLevel(logging.DEBUG)
    if args.production:
        handler = logging.FileHandler(PROD_LOG_PATH, mode="a")
        handler.setLevel(logging.WARN)
        formatting = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
    else:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
    logger.addHandler(handler)
    logger.debug("logger created")

    # Call main method and log any errors.
    try:
        main(logger)
    except Exception as e:
        logger.error(f"An Error Occured :(: {e}")
        logger.error(traceback.format_exc())
        raise
    finally:
        logger.debug("goodbye")
