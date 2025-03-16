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

    def parse_nasa(self, p):
        if len(p) < 10:  # Minimum required packet length
            return "Error: Too short NASA packet"

        src = p[0:3]
        dst = p[3:6]
        isInfo = (p[6] & 0x80) >> 7
        protVersion = (p[6] & 0x60) >> 5
        retryCnt = (p[6] & 0x18) >> 3
        packetType = p[7] >> 4
        payloadType = p[7] & 0xF
        packetNumber = p[8]
        dsCnt = p[9]

        # Convert packet type and payload type to human-readable format
        packetTypStr = NasaPacketTypes[packetType] if packetType < len(NasaPacketTypes) else "unknown"
        payloadTypeStr = NasaPayloadTypes[payloadType] if payloadType < len(NasaPayloadTypes) else "unknown"

        output = []
        output.append(f"Source: {self.bin2hex(src)}")
        output.append(f"Destination: {self.bin2hex(dst)}")
        output.append(f"Packet Type: {packetTypStr}")
        output.append(f"Payload Type: {payloadTypeStr}")
        output.append(f"Packet Number: {hex(packetNumber)}")

        ds = []
        off = 10
        seenMsgCnt = 0

        for i in range(dsCnt):
            seenMsgCnt += 1
            kind = (p[off] & 0x6) >> 1
            size_map = {0: 1, 1: 2, 2: 4}
            s = size_map.get(kind, None)

            if s is None:
                return f"Error: Invalid data size at offset {off}"

            messageNumber = struct.unpack(">H", p[off: off + 2])[0]
            value = p[off + 2:off + 2 + s]
            valuehex = self.bin2hex(value)

            valuedec = []
            if s == 1:
                intval = struct.unpack(">b", value)[0]
                valuedec.append(intval)
                valuedec.append("ON" if value[0] != 0 else "OFF")
            elif s == 2:
                intval = struct.unpack(">h", value)[0]
                valuedec.append(intval)
                valuedec.append(intval / 10.0)
            elif s == 4:
                intval = struct.unpack(">i", value)[0]
                valuedec.append(intval)
                valuedec.append(intval / 10.0)

            desc = nasa_message_name(messageNumber) if "nasa_message_name" in globals() else "UNSPECIFIED"

            output.append(f"  {hex(messageNumber)} ({desc}): {valuehex} | {valuedec}")
            ds.append([messageNumber, desc, valuehex, value, valuedec])
            off += 2 + s

        if seenMsgCnt != dsCnt:
            return "Error: Not every message processed"

        return "\n".join(output)
