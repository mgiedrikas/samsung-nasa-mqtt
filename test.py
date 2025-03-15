import queue
import struct
import threading
import time

import serial
import tools
from lib import get_logger

# Configure Loguru Logging
logger = get_logger(__name__)


def parse_nasa_frame(data):
    if len(data) < 5:
        return None  # Frame too short

    header = data[0]  # Usually fixed value (e.g., 0x32)
    device_id = data[1]
    function_code = data[2]
    payload = data[3:-1]  # Data without checksum
    checksum = data[-1]  # Last byte is checksum

    print(f"Header: {hex(header)}, Device ID: {hex(device_id)}, Function: {hex(function_code)}")
    print(f"Payload: {payload.hex()}, Checksum: {hex(checksum)}")

    return header, device_id, function_code, payload, checksum


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

                self.conn = serial.Serial(self.port, self.baud, timeout=0.1)
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
        while not self.shutdown_event.is_set():
            # logger.info(f"reader thread loop, serial: {isinstance(self.conn, serial.Serial)}, telnet: {isinstance(self.conn, socket.socket)}")
            try:
                if self.conn:
                    # .decode("utf-8", errors="ignore").strip()
                    response = self.conn.readline()

                    # logger.info(f"connection_reader {type(response)}: '{response.hex()}'")
                    if len(response) == 1 and response[0] == b'\n':
                        continue

                    if response and len(response) > 1:
                        # self.response_queue.put(response)
                        print(response)
                        parse_nasa_frame(response)

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
