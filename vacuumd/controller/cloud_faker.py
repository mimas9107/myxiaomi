import socket
import threading
import logging

logger = logging.getLogger(__name__)


class CloudFaker:
    """
    Emulates a minimal Xiaomi Cloud server to keep devices from going offline.
    Inspired by micloudfaker (https://codeberg.org/valpackett/micloudfaker).
    """

    def __init__(self, port=8053):
        self.port = port
        self.running = False

    def start(self):
        self.running = True
        self.udp_thread = threading.Thread(target=self._run_udp, daemon=True)
        self.tcp_thread = threading.Thread(target=self._run_tcp, daemon=True)
        self.udp_thread.start()
        self.tcp_thread.start()
        logger.info(f"CloudFaker started on port {self.port} (UDP/TCP)")

    def _run_udp(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("0.0.0.0", self.port))
            while self.running:
                try:
                    data, addr = s.recvfrom(1024)
                    # logger.debug(f"CloudFaker UDP received {len(data)} bytes from {addr}")

                    # If it's a miio hello (32 bytes), echo it back
                    if len(data) == 32 and data.startswith(b"\x21\x31"):
                        s.sendto(data, addr)
                except Exception as e:
                    if self.running:
                        logger.error(f"CloudFaker UDP error: {e}")

    def _run_tcp(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", self.port))
            s.listen(5)
            while self.running:
                try:
                    conn, addr = s.accept()
                    with conn:
                        # logger.debug(f"CloudFaker TCP connection from {addr}")
                        data = conn.recv(1024)
                        if b"GET " in data or b"POST " in data:
                            response = (
                                b"HTTP/1.1 200 OK\r\n"
                                b"Content-Type: text/plain\r\n"
                                b"Content-Length: 2\r\n"
                                b"Connection: close\r\n"
                                b"\r\n"
                                b"ok"
                            )
                            conn.sendall(response)
                        else:
                            # Just close for other protocols or empty data
                            pass
                except Exception as e:
                    if self.running:
                        logger.error(f"CloudFaker TCP error: {e}")


# Global instance
cloud_faker = CloudFaker()
