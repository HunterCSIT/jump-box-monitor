
import logging
import sys

from constants import PROD_LOG_PATH

def spawn_logger(is_prodcution: bool):
    # Assemble logger instance
    logger = logging.getLogger("jump-box-monitor")
    logger.setLevel(logging.DEBUG)
    if is_prodcution:
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
    return logger
