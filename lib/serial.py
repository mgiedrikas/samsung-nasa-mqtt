import queue
import threading
import time
from datetime import datetime

import serial

from lib import get_logger
from lib.nasa_parser import NasaPacketParser

logger = get_logger(__name__)


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
            self.process_queue()

    def connection_reader(self):
        """Reads data continuously on a separate thread and stores it in the queue."""
        logger.info("Starting new reader thread")

        while not self.shutdown_event.is_set():
            # logger.info(f"reader thread loop, serial: {isinstance(self.conn, serial.Serial)}, telnet: {isinstance(self.conn, socket.socket)}")
            try:
                if self.conn:
                    # .decode("utf-8", errors="ignore").strip()
                    response = self.conn.read(1)
                    if len(response) > 0:
                        if response not in (b'\r', b'\n'):
                            self.response_queue.put(response)

                else:
                    logger.warning("Connection lost, restarting reader...")
                    self.restart_event.set()
                    break

            except Exception as e:
                logger.error(f"Reader Error: {e}")
                self.restart_event.set()
                break

    def process_queue(self):
        parser = NasaPacketParser()
        payload = bytearray()
        discarded = bytearray()
        msg_start_found = False
        msg_end_found = False
        logger.info(f'process_queue starting...')
        while not self.shutdown_event.is_set():
            try:
                b = self.response_queue.get()
                if b == b'\x34':
                    msg_end_found = True
                    msg_start_found = False
                    if len(payload) > 0:
                        payload.extend(b)
                        print('-'*100)
                        print(datetime.now())
                        print(payload.hex())
                        print(f'{len(payload)}:', payload.hex(' '))
                        parser.parse_nasa(payload)
                        print('\ndiscarded')
                        print(f'{len(discarded)}:', discarded.hex(' '))
                        print(discarded.hex())
                        print('-'*100)
                        print()
                        payload = bytearray()
                        discarded = bytearray()
                        continue

                if b == b'\x32' and msg_end_found:
                    msg_start_found = True
                    msg_end_found = False

                if msg_start_found:

                    payload.extend(b)
                else:
                    discarded.extend(b)


            except queue.Empty:
                time.sleep(0.002)
                continue
            except Exception as e:
                logger.error(f"Queue Error: {e}")


