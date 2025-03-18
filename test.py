import time

from lib import get_logger
from lib.serial import SerialHandler
from lib.telnet import TelnetHandler

# Configure Loguru Logging
logger = get_logger(__name__)


def main_serial():
    s = SerialHandler("/dev/ttyACM0", 9600)
    s.start()

    while True:
        time.sleep(1)


def main_telnet():
    client = TelnetHandler("192.168.1.211", 7001)
    client.start()

    while True:
        time.sleep(1)


if __name__ == '__main__':
    main_serial()
