import binascii
import struct
from enum import Enum
from typing import List, Union

from lib.nasa_lib import DecodeResult, Address, Command, MessageSet
from nasa_messages import nasa_message_name
from packetgateway import NasaPacketTypes, NasaPayloadTypes


def crc16(data: bytes, start_index: int, length: int) -> int:
    crc = 0
    for index in range(start_index, start_index + length):
        crc ^= (data[index] << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
    return crc & 0xFFFF  # Ensure 16-bit output


class NasaPacketParser:
    def __init__(self):
        pass

    def bin2hex(self, data):
        """Convert binary data to a hex string for readability"""
        return binascii.hexlify(data).decode()

    def parse_nasa(self, data: bytes):
        if data[0] != 0x32:
            return DecodeResult.InvalidStartByte
        if data[-1] != 0x34:
            return DecodeResult.InvalidEndByte
        if len(data) < 16 or len(data) > 1500:
            return DecodeResult.UnexpectedSize

        size = (data[1] << 8) | data[2]
        if size + 2 != len(data):
            print(f' - size expected {size + 2} != paylod {len(data)}')
            return DecodeResult.SizeDidNotMatch

        crc_actual = crc16(data, 3, size - 4)
        crc_expected = (data[-3] << 8) | data[-2]

        print(f' - sizeok: {size + 2 == len(data)}')
        print(f' - crc ok: {crc_actual == crc_expected}')

        if crc_expected != crc_actual:
            print(f"NASA: invalid crc - got {crc_actual} but should be {crc_expected}")
            print(data.hex(' '))
            return DecodeResult.CrcError

        cursor = 3
        sa = Address()
        sa.decode(data, cursor)
        cursor += sa.size

        da = Address()
        da.decode(data, cursor)
        cursor += da.size

        command = Command()
        command.decode(data, cursor)
        cursor += command.size

        capacity = data[cursor]
        cursor += 1
        print(f' - Src.{sa}')
        print(f' - Dst.{da}')
        print(command)
        print(f'capacity {capacity} bytes, cursor: {cursor}')
        print()

        messages = []
        for _ in range(1, capacity + 1):
            message_set = MessageSet.decode(data, cursor, capacity)
            messages.append(message_set)
            cursor += message_set.size
            print(message_set)

        # dsCnt = data[9]
        # print(f'dsCnt {dsCnt} bytes')
        #
        # output = []
        # ds = []
        # off = 10
        # seenMsgCnt = 0
        #
        # try:
        #
        #     for i in range(dsCnt):
        #         seenMsgCnt += 1
        #         kind = (data[off] & 0x6) >> 1
        #         size_map = {0: 1, 1: 2, 2: 4}
        #         s = size_map.get(kind, None)
        #
        #         if s is None:
        #             return f"Error: Invalid data size at offset {off}"
        #
        #         messageNumber = struct.unpack(">H", data[off: off + 2])[0]
        #         value = data[off + 2:off + 2 + s]
        #         valuehex = self.bin2hex(value)
        #
        #         valuedec = []
        #         if s == 1:
        #             intval = struct.unpack(">b", value)[0]
        #             valuedec.append(intval)
        #             valuedec.append("ON" if value[0] != 0 else "OFF")
        #         elif s == 2:
        #             intval = struct.unpack(">h", value)[0]
        #             valuedec.append(intval)
        #             valuedec.append(intval / 10.0)
        #         elif s == 4:
        #             intval = struct.unpack(">i", value)[0]
        #             valuedec.append(intval)
        #             valuedec.append(intval / 10.0)
        #
        #         desc = nasa_message_name(messageNumber) if "nasa_message_name" in globals() else "UNSPECIFIED"
        #
        #         output.append(f"  {hex(messageNumber)} ({desc}): {valuehex} | {valuedec}")
        #         ds.append([messageNumber, desc, valuehex, value, valuedec])
        #         off += 2 + s
        #
        #     if seenMsgCnt != dsCnt:
        #         print("Error: Not every message processed")
        #         return DecodeResult.Failure
        #
        #     print("\n".join(output))
        #
        # except Exception as e:
        #     print(e)
        #     return DecodeResult.Failure

        return DecodeResult.Success  # Assuming a success case exists

        # size = (int(data[1]) << 8) | int(data[2])
        # packet_information = ((int(data[index]) & 128) >> 7) == 1
        # protocol_version = (data[index] & 96) >> 5
        # retry_count = (data[index] & 24) >> 3
        # packet_type = PacketType((data[index + 1] & 240) >> 4)
        # data_type = DataType(data[index + 1] & 15)
        # packet_number = data[index + 2]
