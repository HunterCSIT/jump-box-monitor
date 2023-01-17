
import os.path

from constants import BASE_DIR


class PIDFileExistsException(Exception):
    pass

def _get_full_pid_file_path() -> str:
    return os.path.join(BASE_DIR, "jump_box_monitor.pid")


def _validate_no_pid_exists() -> None:
    if os.path.exists(_get_full_pid_file_path()):
        raise PIDFileExistsException("pid file exists")

def create_pid_file() -> None:
    """ Raises PIDFileExistsException if a pid file is found.
        Creates pid file if none exists
    """
    _validate_no_pid_exists()
    with open(_get_full_pid_file_path(), 'w') as f:
        f.write(str(os.getpid()))

def remove_pid_file() -> None:
    os.remove(_get_full_pid_file_path())
