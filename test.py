import time

from lib import get_logger
from lib.nasa_parser import NasaPacketParser, crc16
from lib.serial import SerialHandler
from lib.telnet import TelnetHandler
from tools import hex2bin

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
    # main_serial()
    payload = hex2bin('32003e100000b000ffc0149f0c820400688206ffff8208ffff8201248217000082180051821affff822302268225ffff822907d0822c00008233ffffb43634')
    parser = NasaPacketParser()
    parser.parse_nasa(payload)

