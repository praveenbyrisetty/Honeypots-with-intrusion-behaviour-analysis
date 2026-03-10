"""
Low-interaction HTTP honeypot.
Serves a fake login page and captures all HTTP requests (method, path, headers, body).
"""

import socket

from honeypots.base import BaseHoneypot
import config

_LOGIN_PAGE = """\
<!DOCTYPE html>
<html>
<head><title>Admin Panel - Login</title></head>
<body style="font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;background:#1a1a2e;">
<div style="background:#16213e;padding:40px;border-radius:12px;box-shadow:0 0 20px rgba(0,0,0,0.5);">
<h2 style="color:#e94560;text-align:center;">Admin Login</h2>
<form method="POST" action="/login">
  <input name="username" placeholder="Username" style="width:100%;padding:10px;margin:8px 0;border:none;border-radius:6px;"><br>
  <input name="password" type="password" placeholder="Password" style="width:100%;padding:10px;margin:8px 0;border:none;border-radius:6px;"><br>
  <button type="submit" style="width:100%;padding:10px;background:#e94560;color:#fff;border:none;border-radius:6px;cursor:pointer;">Login</button>
</form>
</div>
</body>
</html>
"""

_RESPONSE_TEMPLATE = (
    "HTTP/1.1 {status}\r\n"
    "Server: {server}\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: {length}\r\n"
    "Connection: close\r\n"
    "\r\n"
    "{body}"
)


class LowHTTPHoneypot(BaseHoneypot):
    """Low-interaction HTTP honeypot — fake login page, logs all requests."""

    def __init__(self, host: str = None, port: int = None, logger=None):
        super().__init__(
            name="low_http",
            host=host or config.BIND_HOST,
            port=port or config.LOW_HTTP_PORT,
            logger=logger,
        )

    def handle_connection(self, client_socket: socket.socket, client_address: tuple):
        client_socket.settimeout(30)

        try:
            raw = client_socket.recv(4096)
            if not raw:
                return

            request = raw.decode("utf-8", errors="replace")
            lines = request.split("\r\n")
            request_line = lines[0] if lines else ""

            # Parse method / path
            parts = request_line.split(" ")
            method = parts[0] if len(parts) >= 1 else "?"
            path = parts[1] if len(parts) >= 2 else "/"

            # Parse headers
            headers = {}
            body = ""
            header_section = True
            for line in lines[1:]:
                if header_section:
                    if line == "":
                        header_section = False
                        continue
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip()] = v.strip()
                else:
                    body += line

            # Log everything
            if self.hp_logger:
                self.hp_logger.log_payload(
                    honeypot_name="low_http",
                    src_ip=client_address[0],
                    data=request[:2048],
                )

            # Extract credentials from POST body
            if method == "POST" and body:
                params = dict(p.split("=", 1) for p in body.split("&") if "=" in p)
                username = params.get("username", "")
                password = params.get("password", "")
                if username or password:
                    if self.hp_logger:
                        self.hp_logger.log_credential(
                            honeypot_name="low_http",
                            src_ip=client_address[0],
                            username=username,
                            password=password,
                        )

            # Send response
            response = _RESPONSE_TEMPLATE.format(
                status="200 OK",
                server=config.HTTP_SERVER_HEADER,
                length=len(_LOGIN_PAGE),
                body=_LOGIN_PAGE,
            )
            client_socket.sendall(response.encode())

        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            self._log.debug(f"HTTP error: {e}")
