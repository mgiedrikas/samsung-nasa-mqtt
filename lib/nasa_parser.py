import binascii
from enum import Enum
from typing import List


class DecodeResult(Enum):
    InvalidStartByte = 1
    UnexpectedSize = 2
    SizeDidNotMatch = 3
    InvalidEndByte = 4
    CrcError = 5
    Success = 6


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
            print(f'size expected {size + 2} != paylod {len(data)}')
            return DecodeResult.SizeDidNotMatch

        crc_actual = crc16(data, 3, size - 4)
        crc_expected = (data[-3] << 8) | data[-2]

        print(f' - sizeok: {size + 2 == len(data)}')
        print(f' - crc ok: {crc_actual == crc_expected}')

        if crc_expected != crc_actual:
            print(f"NASA: invalid crc - got {crc_actual} but should be {crc_expected}")
            print(data.hex(' '))
            return DecodeResult.CrcError

        return DecodeResult.Success  # Assuming a success case exists

        # size = (int(data[1]) << 8) | int(data[2])
        # packet_information = ((int(data[index]) & 128) >> 7) == 1
        # protocol_version = (data[index] & 96) >> 5
        # retry_count = (data[index] & 24) >> 3
        # packet_type = PacketType((data[index + 1] & 240) >> 4)
        # data_type = DataType(data[index + 1] & 15)
        # packet_number = data[index + 2]
