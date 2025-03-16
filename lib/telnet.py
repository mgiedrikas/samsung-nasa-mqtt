import queue
import socket
import threading
import time

from lib import get_logger

logger = get_logger(__name__)


class TelnetHandler:
    """Handles Telnet Connection."""
    def __init__(self, telnet_host, telnet_port, read_timeout=0.5):
        self.lock = threading.Lock()
        self.client_lock = threading.Lock()
        self.restart_lock = threading.Lock()
        self.response_queue: queue.Queue = queue.Queue()
        self.shutdown_event = threading.Event()
        self.restart_shutdown_event = threading.Event()
        self.send_to_queue = threading.Event()
        self.restart_event = threading.Event()
        self.reader_thread: threading.Thread = None
        self.restart_thread: threading.Thread = None
        self.conn: socket.socket = None
        self.telnet_host = telnet_host
        self.telnet_port = telnet_port
        self.read_timeout = read_timeout

    def open_connection(self):
        """Opens Telnet connection."""
        while True:
            try:
                if self.conn:
                    logger.error("open_connection - self.conn is not null")
                    return  # Connection already open

                self.conn = socket.create_connection((self.telnet_host, self.telnet_port))
                self.conn.settimeout(self.read_timeout)
                logger.info(f"Connected to Telnet {self.telnet_host}:{self.telnet_port}")
                break
            except socket.error as e:
                logger.error(f"Connection error: {e}. Retrying in 5 seconds...")
                time.sleep(5)

    def clear_queue(self):
        try:
            while not self.response_queue.qsize() != 0:
                self.response_queue.get_nowait()
        except queue.Empty:
            pass

    @logger.catch
    def restart(self):
        while not self.restart_shutdown_event.is_set():
            if self.restart_event.is_set():
                with self.restart_lock:
                    logger.info('restarting handler connection')
                    self.shutdown_event.set()
                    while self.reader_thread and self.reader_thread.is_alive():
                        time.sleep(0.002)

                    self.shutdown_event.clear()  # Reset shutdown flag for new thread
                    if self.conn:
                        self.conn.close()
                    self.conn = None
                    self.open_connection()

                    self.reader_thread = threading.Thread(target=self.connection_reader, daemon=True)
                    self.reader_thread.start()
                    self.restart_event.clear()
            time.sleep(0.3)

    @logger.catch
    def start(self):
        with self.restart_lock:
            self.shutdown_event.clear()
            self.restart_shutdown_event.clear()
            logger.info('starting handler connection')
            self.open_connection()
            self.reader_thread = threading.Thread(target=self.connection_reader, daemon=True)
            self.reader_thread.start()
            self.restart_thread = threading.Thread(target=self.restart, daemon=True)
            self.restart_thread.start()

    @logger.catch
    def stop(self):
        """Closes connection and stops threads."""
        self.shutdown_event.set()
        self.restart_shutdown_event.set()
        while self.reader_thread and self.reader_thread.is_alive():
            time.sleep(0.02)
        while self.restart_thread and self.restart_thread.is_alive():
            time.sleep(0.02)
        if self.conn:
            self.conn.close()
            logger.info("Connection closed.")

    def unset_queue_write(self):
        self.send_to_queue.clear()
        self.clear_queue()

    def send_command(self, command: str):
        """Thread-safe function to write to Serial/Telnet and get response.
            command - command to write to serial port
            who - Client classs - identifier who writes to serial port
            resp - return or not the response after writing to serial port
        """
        with self.lock:
            try:
                if not self.reader_thread:
                    self.restart_event.set()
                logger.info(f"sent: '{command}'")
                self.conn.sendall((command.strip() + "\n").encode())
                response = self.response_queue.get(timeout=1)
                logger.info(f"received: '{response}'")
            except queue.Empty:
                logger.error(f"send_command queue.Empty")
            except Exception as e:
                logger.error(f"send_command exception")
                logger.error(f"{type(e)}, {e}")
                logger.exception(e)
                return
            finally:
                pass

    def connection_reader(self):
        """Reads data continuously on a separate thread and stores it in the queue."""
        logger.info("Starting new reader thread")
        while not self.shutdown_event.is_set():
            # logger.info(f"reader thread loop, serial: {isinstance(self.conn, serial.Serial)}, telnet: {isinstance(self.conn, socket.socket)}")
            try:
                if self.conn:
                    # .decode("utf-8", errors="ignore").strip()
                    response = self.conn.recv(1024)
                    if response and len(response) > 0:
                        logger.info(f"connection_reader: '{response.hex()}'")
                        self.response_queue.put(response)
                else:
                    logger.warning("Connection lost, restarting reader...")
                    self.restart_event.set()
                    break

            except socket.timeout:
                continue

            except Exception as e:
                logger.error(f"Reader Error: {e}")
                self.restart_event.set()
                break
