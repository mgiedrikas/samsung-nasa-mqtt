import queue
import struct
import threading
import time
import binascii
import serial
from lib import get_logger
from nasa_messages import nasa_message_name
from packetgateway import NasaPacketTypes, NasaPayloadTypes

# Configure Loguru Logging
logger = get_logger(__name__)


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


class SerialHandler:
    """Handles Serial Connection."""

    def __init__(self, port, baud):
        self.port: serial.Serial = port
        self.baud = baud
        self.conn: serial.Serial = None
        self.lock = threading.Lock()
        self.client_lock = threading.Lock()
        self.restart_lock = threading.Lock()
        self.response_queue: queue.Queue = queue.Queue()
        self.shutdown_event = threading.Event()
        self.restart_shutdown_event = threading.Event()
        self.restart_event = threading.Event()
        self.reader_thread: threading.Thread = None
        self.conn: serial.Serial = None

    def connect(self):
        """Opens Serial connection."""
        while True:
            try:
                if self.conn and self.conn.is_open:
                    return  # Connection already open

                self.conn = serial.Serial(self.port, self.baud, timeout=1)
                logger.info(f"Connected to Serial {self.port} at {self.baud} baud")
                return
            except serial.SerialException as e:
                logger.error(f"Connection error: {e}. Retrying in 5 seconds...")
                time.sleep(5)

    def clear_queue(self):
        try:
            while not self.response_queue.qsize() != 0:
                self.response_queue.get_nowait()
        except queue.Empty:
            pass

    @logger.catch
    def stop(self):
        """Closes connection and stops threads."""
        self.shutdown_event.set()
        self.restart_shutdown_event.set()
        while self.reader_thread and self.reader_thread.is_alive():
            time.sleep(0.02)
        # while self.restart_thread and self.restart_thread.is_alive():
        #     time.sleep(0.02)
        if self.conn:
            self.conn.close()
            logger.info("Connection closed.")

    @logger.catch
    def start(self):
        with self.restart_lock:
            self.shutdown_event.clear()
            self.restart_shutdown_event.clear()
            logger.info('starting serial connection')
            self.connect()
            self.reader_thread = threading.Thread(target=self.connection_reader, daemon=True)
            self.reader_thread.start()
            # self.restart_thread = threading.Thread(target=self.restart, daemon=True)
            # self.restart_thread.start()

    def connection_reader(self):
        """Reads data continuously on a separate thread and stores it in the queue."""
        logger.info("Starting new reader thread")
        parser = NasaPacketParser()
        while not self.shutdown_event.is_set():
            # logger.info(f"reader thread loop, serial: {isinstance(self.conn, serial.Serial)}, telnet: {isinstance(self.conn, socket.socket)}")
            try:
                if self.conn:
                    # .decode("utf-8", errors="ignore").strip()
                    response = self.conn.readline()
                    # self.response_queue.put(response)

                    if len(response) > 0:
                        print(response)
                        print(" ".join(f"{b:02X}" for b in response))
                        print()
                        # res = parser.parse_nasa(response)
                        # print(res)

                else:
                    logger.warning("Connection lost, restarting reader...")
                    self.restart_event.set()
                    break

            except Exception as e:
                logger.error(f"Reader Error: {e}")
                self.restart_event.set()
                break


def main():
    s = SerialHandler("/dev/ttyUSB0", 9600)
    s.start()

    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()
