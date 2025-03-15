import sys
from loguru import logger as log
from enum import Enum

# Configure Loguru Logging
log.remove()
log.add(
    sys.stdout,
    format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level:<5} | {extra[module]:<20} | {message}",
    level="INFO",
)


def get_logger(name):
    """Returns a logger with the module name"""
    return log.bind(module=name)


class ConnectionType(Enum):
    SUB = "SUB"
    STREAM = "STREAM"
