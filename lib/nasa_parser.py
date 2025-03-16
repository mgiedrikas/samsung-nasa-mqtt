import binascii
from enum import Enum
from typing import List


class PacketType(Enum):
    StandBy = 0
    Normal = 1
    Gathering = 2
    Install = 3
    Download = 4


class DataType(Enum):
    Undefined = 0
    Read = 1
    Write = 2
    Request = 3
    Notification = 4
    Response = 5
    Ack = 6
    Nack = 7


class MessageSetType(Enum):
    Enum = 0
    Variable = 1
    LongVariable = 2
    Structure = 3


class Address:
    size = 3

    def __init__(self):
        self.klass = None  # AddressClass equivalent
        self.channel = 0
        self.address = 0

    def decode(self, data: bytes, index: int):
        self.klass = data[index]  # Assuming klass is a single byte
        self.channel = data[index + 1]
        self.address = data[index + 2]

    def encode(self, data: List[int]):
        data.extend([self.klass, self.channel, self.address])

    def __str__(self):
        return f"Address({self.klass}.{self.channel}.{self.address})"


class Command:
    size = 3

    def __init__(self):
        self.packet_information = True
        self.protocol_version = 2
        self.retry_count = 0
        self.packet_type = PacketType.StandBy
        self.data_type = DataType.Undefined
        self.packet_number = 0

    def decode(self, data: bytes, index: int):
        byte = data[index]
        self.packet_information = ((byte & 128) >> 7) == 1
        self.protocol_version = (byte & 96) >> 5
        self.retry_count = (byte & 24) >> 3
        self.packet_type = PacketType((data[index + 1] & 240) >> 4)
        self.data_type = DataType(data[index + 1] & 15)
        self.packet_number = data[index + 2]

    def encode(self, data: List[int]):
        byte1 = (int(self.packet_information) << 7) | (self.protocol_version << 5) | (self.retry_count << 3)
        byte2 = (self.packet_type.value << 4) | self.data_type.value
        data.extend([byte1, byte2, self.packet_number])

    def __str__(self):
        return (f"Command(packet_information={self.packet_information}, "
                f"protocol_version={self.protocol_version}, retry_count={self.retry_count}, "
                f"packet_type={self.packet_type}, data_type={self.data_type}, "
                f"packet_number={self.packet_number})")

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
        print(sa)

        da = Address()
        da.decode(data, cursor)
        cursor += da.size
        print(da)

        command = Command()
        command.decode(data, cursor)
        cursor += command.size
        print(command)

        capacity = data[cursor]
        cursor += 1
        print(f'capacity {capacity} bytes, cursor: {cursor}')

        return DecodeResult.Success  # Assuming a success case exists

        # size = (int(data[1]) << 8) | int(data[2])
        # packet_information = ((int(data[index]) & 128) >> 7) == 1
        # protocol_version = (data[index] & 96) >> 5
        # retry_count = (data[index] & 24) >> 3
        # packet_type = PacketType((data[index + 1] & 240) >> 4)
        # data_type = DataType(data[index + 1] & 15)
        # packet_number = data[index + 2]
