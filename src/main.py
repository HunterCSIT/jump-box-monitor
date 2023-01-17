
from abc import ABC, abstractmethod
import argparse
import datetime
import json
import logging
import itertools
import os
import os.path
import time
import traceback
import typing
import uuid

import psutil

from constants import (
    REPORTS_DIR,
    CONFIG_FILE_PATH,
    ALERT_SNOOZE_TIME_SECONDS,
)
from utils.data_cache import (
    read_saved_value,
    write_saved_value,
    DataCacheMissError,
    DataCacheKeyExpired,
)
from utils.discord import create_discord_message
from utils.logger import spawn_logger
from utils.pid import (
    create_pid_file,
    remove_pid_file,
    PIDFileExistsException,
)
from utils.helpers import md5sum


# Config validation
class InvalidConfigError(Exception):
    pass

def validate_config(config: typing.Dict):
    if 'max_memory_percent' not in config:
        raise InvalidConfigError("expected config value 'max_memory_percent'")
    if 'max_cpu_percent' not in config:
        raise InvalidConfigError("expected config value 'max_cpu_percent'")
    if 'max_disk_percent' not in config:
        raise InvalidConfigError("expected config value 'max_disk_percent'")

    def _validate_percent_value(v: float, name: str):
        if not isinstance(v, float) or v < 0 or v > 1:
            raise InvalidConfigError(f'field {v} has invalid value')

    _validate_percent_value(config['max_memory_percent'], 'max_memory_percent')
    _validate_percent_value(config['max_cpu_percent'], 'max_cpu_percent')
    _validate_percent_value(config['max_disk_percent'], 'max_disk_percent')

    if "user_names_to_ignore" not in config or not isinstance(config['user_names_to_ignore'], list):
        raise InvalidConfigError(f'expected field user_names_to_ignore to be a list')

    if "process_names_to_ignore" not in config or not isinstance(config['process_names_to_ignore'], list):
        raise InvalidConfigError(f'expected field process_names_to_ignore to be a list')

    if "discord_bot" in config:
        if "channel_id" not in config["discord_bot"]:
            raise InvalidConfigError(
                "discord_bot object expected key channel_id"
            )
        if not config["discord_bot"]['channel_id'] or len(config["discord_bot"]['channel_id']) < 5:
            raise InvalidConfigError(
                "discord_bot object contains invalid key channel_id"
            )
        if "bot_token" not in config["discord_bot"]:
            raise InvalidConfigError(
                "discord_bot object expected key bot_token"
            )
        if not config["discord_bot"]['bot_token'] or len(config["discord_bot"]['bot_token']) < 5:
            raise InvalidConfigError(
                "discord_bot object contains invalid key bot_token"
            )



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
    notice_fields = NotImplemented

    @abstractmethod
    def to_key_name(self) -> str:
        pass

    def to_email_string(self) -> str:
        parts = []
        for field in self.notice_fields:
            parts.append(f"{field}: {getattr(self, field)}")
        return "\n".join(parts)

class SystemResourceUsageAlert(BaseAlert):

    alert_type = AlertType.RESOURCES
    notice_fields = [
        'resource_name',
        'resource_usage_percent',
    ]

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
    notice_fields = [
        'process_id',
        'user_uid',
        'user_name',
        'command',
        'priority',
        'created_at',
    ]

    def __init__(
        self,
        process_id: str,
        user_uid: int,
        user_name: str,
        command: str,
        priority: str,
        created_at: str,
    ):
        self.process_id = process_id
        self.user_uid = user_uid
        self.user_name = user_name
        self.command = command
        self.priority = priority
        self.created_at = created_at


    def to_key_name(self):
        return md5sum(f"{self.process_id}-{self.user_uid}-{self.command}")

    def __str__(self):
        return f"<ProcessAlert pid{self.process_id} uid{self.user_uid}>"


# # Check for resource alerts # # # # # #

def get_system_resource_usage_alerts(logger, config) -> typing.List[SystemResourceUsageAlert]:
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
    if memory_used_percent > config['max_memory_percent']:
        alerts.append(SystemResourceUsageAlert(
            ResourceNames.MEMORY,
            memory_used_percent
        ))
        logger.warning(f"creating alert for MEMORY usage")
    if cpu_useage_percent > config['max_cpu_percent']:
        alerts.append(SystemResourceUsageAlert(
            ResourceNames.CPU,
            cpu_useage_percent
        ))
        logger.warning(f"creating alert for CPU usage")
    if disk_useage_percent > config['max_disk_percent']:
        alerts.append(SystemResourceUsageAlert(
            ResourceNames.DISK,
            disk_useage_percent
        ))
        logger.warning(f"creating alert for DISK usage")

    return alerts


# # Check for processes alerts # # # # # #

def get_processes_alerts(logger, config) -> typing.List[ProcessAlert]:
    alerts = []
    for proc in psutil.process_iter():
        with proc.oneshot():
            pid = proc.pid
            user_uid = proc.uids().real
            user_name = proc.username()
            command = f"{proc.name()} ({proc.exe()})"
            created_at =  datetime.datetime.fromtimestamp(proc.create_time()).strftime("%Y-%m-%d %H:%M:%S")
            priority = proc.nice()

        if user_name in config['user_names_to_ignore']:
            continue
        if proc.name() in config['process_names_to_ignore']:
            if priority >= 0:
                # We expect this to be 0 or higher.
                # if < 0 then process has elevated priority
                continue

        logger.warning(f"creating alert for process")
        alerts.append(ProcessAlert(
            pid, user_uid, user_name, command, priority, created_at
        ))

    return alerts



# # # Script Entry Point # # # # # # # # #

def main(logger: logging.Logger, config: typing.Dict) -> None:
    logger.debug("main method running")

    logger.debug("checking for alerts")
    resource_alerts = get_system_resource_usage_alerts(logger, config)
    process_alerts = get_processes_alerts(logger, config)
    if len(resource_alerts) == 0 and len(process_alerts) == 0:
        logger.debug("no alerts found")
        return

    if len(resource_alerts):
        logger.warning(f"found {len(resource_alerts)} resource alert(s)")
    if len(process_alerts):
        logger.warning(f"found {len(process_alerts)} process alert(s)")

    message_text = []
    for alert in itertools.chain(resource_alerts, process_alerts):

        alert_cache_key = alert.to_key_name()
        try:
            # Check cache to see if we've sent an alert for this event recently.
            # We don't want to spam alerts.
            read_saved_value(alert_cache_key)
        except (DataCacheMissError, DataCacheKeyExpired):
            send_alert = True
            logger.debug(f"cache miss, writing key to cache: {alert_cache_key}")
            write_saved_value(alert_cache_key, None, ALERT_SNOOZE_TIME_SECONDS)
        else:
            logger.debug("cache hit")
            logger.warning(f"not sending alert {alert}, cache key found")
            send_alert = False

        if send_alert:
            logger.warning(f" **** SENDING ALERT **** {alert}")
            message_text.append(alert.to_email_string())

    if len(message_text):
        file_report_path = os.path.join(REPORTS_DIR, str(uuid.uuid4()) + ".report")
        # Send messages
        if "discord_bot" in config and not config['discord_bot'].get("skip"):
            logger.debug("sending discord message")
            max_discord_messages = 5
            chunk_size = 12
            for ix, i in enumerate(range(0, len(message_text), chunk_size)):
                if i > 0:
                    time.sleep(1.5)
                create_discord_message(
                    "\n\n".join(message_text[i: i+chunk_size]),
                    config['discord_bot']['bot_token'],
                    config['discord_bot']['channel_id'],
                    logger,
                )
                if ix >= max_discord_messages:
                    # write the rest to disk
                    logger.debug("creating incident report file")
                    with open(file_report_path, "w") as f:
                        f.write("\n\n".join(message_text[i+chunk_size:]))
                    create_discord_message(
                        "Additional indicent details written to " + file_report_path,
                        config['discord_bot']['bot_token'],
                        config['discord_bot']['channel_id'],
                        logger,
                    )
                    break

        else:
            logger.debug("creating incident report file")
            with open(file_report_path, "w") as f:
                f.write("\n\n".join(message_text))

    else:
        logger.warning("no messages to send")


if __name__ == "__main__":

    # check if production. If prod = True, no console logging and send alerts
    #                      If prod = False, log to console, show alerts in console.
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--production', action='store_true')
    args = parser.parse_args()

    logger = spawn_logger(args.production)


    # Load config
    try:
        with open(CONFIG_FILE_PATH) as f:
            config = json.load(f)
        validate_config(config)
    except IOError:
        logger.error("could not find config file")
        logger.error(traceback.format_exc())
        raise
    except InvalidConfigError:
        logger.error("invalid config file")
        logger.error(traceback.format_exc())
        raise

    # Create pid file right before calling main
    try:
        create_pid_file()
    except PIDFileExistsException:
        logger.error("found PID file, exiting")
        raise

    # Call main method and log any errors.
    try:
        main(logger, config)
    except Exception as e:
        logger.error(f"An Error Occured :(: {e}")
        logger.error(traceback.format_exc())
        raise
    finally:
        remove_pid_file()
        logger.debug("goodbye")
