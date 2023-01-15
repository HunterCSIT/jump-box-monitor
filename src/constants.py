
import os.path
import pathlib


# Script constants & Settings
BASE_DIR = pathlib.Path(__file__).parent.parent.absolute()
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
PROD_LOG_PATH = os.path.join(BASE_DIR, "warnings.log")
CONFIG_FILE_PATH = os.path.join(BASE_DIR, "monitor-config.json")
ALERT_SNOOZE_TIME_SECONDS = 60 * 60 * 6


