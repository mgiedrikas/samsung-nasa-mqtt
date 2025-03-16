import queue
import struct
import threading
import time
import binascii
import serial
from lib import get_logger
from lib.serial import SerialHandler
from lib.telnet import TelnetHandler
from nasa_messages import nasa_message_name
from packetgateway import NasaPacketTypes, NasaPayloadTypes


class NasaPacketParser:
    def __init__(self):
        pass

    def bin2hex(self, data):
        """Convert binary data to a hex string for readability"""
        return binascii.hexlify(data).decode()

    def parse_nasa(self, data: bytes):
        if len(data) < 16 or len(data) > 1500:
            return f"Error: Invalid NASA packet size: {len(data)}"

        size = (int(data[1]) << 8) | int(data[2])
        output = ""

        return "\n".join(output)
