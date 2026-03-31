"""
Abstract base class for all honeypots.
Each honeypot runs a socket server in its own daemon thread.
"""

import socket
import threading
import logging
from abc import ABC, abstractmethod
from datetime import datetime


class BaseHoneypot(ABC):
    """
    Abstract base for low- and medium-interaction honeypots.

    Subclasses must implement:
        handle_connection(client_socket, client_address)
    """

    def __init__(self, name: str, host: str, port: int, logger=None):
        self.name = name
        self.host = host
        self.port = port
        self.hp_logger = logger          # HoneypotLogger instance
        self._server_socket = None
        self._running = False
        self._thread = None
        self._log = logging.getLogger(f"honeypot.{name}")

    # ── Lifecycle ─────────────────────────────────────────────────────

    def start(self):
        """Bind the socket and start accepting connections in a thread."""
        if self._running:
            self._log.warning(f"{self.name} is already running.")
            return

        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.settimeout(1.0)  # allow periodic check for shutdown
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(100)
        self._running = True

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        self._log.info(f"[+] {self.name} started on {self.host}:{self.port}")

    def stop(self):
        """Gracefully shut down the honeypot."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=5)
        self._log.info(f"[-] {self.name} stopped.")

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Internal ──────────────────────────────────────────────────────

    def _accept_loop(self):
        """Accept connections in a loop; spawn a handler thread for each."""
        while self._running:
            try:
                client_sock, client_addr = self._server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            self._log.info(f"Connection from {client_addr[0]}:{client_addr[1]}")
            handler = threading.Thread(
                target=self._safe_handle,
                args=(client_sock, client_addr),
                daemon=True,
            )
            handler.start()

    def _safe_handle(self, client_socket: socket.socket, client_address: tuple):
        """Wrap handle_connection with error handling & logging."""
        try:
            # Log the raw connection event
            if self.hp_logger:
                self.hp_logger.log_connection(
                    honeypot_name=self.name,
                    src_ip=client_address[0],
                    src_port=client_address[1],
                    dst_port=self.port,
                    protocol=self.name.split("_")[0],  # e.g. "ssh", "ftp"
                )
            self.handle_connection(client_socket, client_address)
        except Exception as exc:
            self._log.error(f"Error handling {client_address}: {exc}")
        finally:
            try:
                client_socket.close()
            except OSError:
                pass

    # ── Subclass Interface ────────────────────────────────────────────

    @abstractmethod
    def handle_connection(self, client_socket: socket.socket, client_address: tuple):
        """
        Process a single client session.
        Must be implemented by each honeypot type.
        """
        ...
