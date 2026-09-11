"""Lightweight local intentionally vulnerable test application for testing WebVuln Scanner."""

import html
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

HTML_PAGE = """<!DOCTYPE html>
<html>
<head>
    <title>WebVuln Test Lab App</title>
</head>
<body>
    <h1>Authorized Test Target Lab</h1>
    <p>Welcome to the educational lab environment.</p>
    
    <form action="/search" method="GET">
        <label>Search Query: <input type="text" name="q" value="security" /></label>
        <button type="submit">Search</button>
    </form>

    <form action="/login" method="POST">
        <label>Username: <input type="text" name="username" /></label>
        <label>Password: <input type="password" name="password" /></label>
        <button type="submit">Login</button>
    </form>

    <p><a href="/api/users">API Users List</a> | <a href="/redirect?next=/dashboard">Redirect Test</a></p>
    <p><a href="/view?file=notes.txt">View File</a></p>
</body>
</html>
"""


class VulnerableLabHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for the test lab application."""

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        # 1. OpenAPI Route
        if parsed.path == "/openapi.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"openapi": "3.0.0", "info": {"title": "Lab Test API"}}')
            return

        # 2. Reflected parameter without encoding
        if parsed.path == "/search":
            q_val = params.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            body = f"<html><body><h2>Results for: {q_val}</h2><a href='/'>Back</a></body></html>"
            self.wfile.write(body.encode("utf-8"))
            return

        # 3. Database error simulation for SQLi check
        if parsed.path == "/view":
            file_param = params.get("file", [""])[0]
            if "'" in file_param:
                self.send_response(500)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"Database Error: You have an error in your SQL syntax near '' at line 1")
                return
            elif "../" in file_param:
                self.send_response(500)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"Warning: failed to open stream: No such file or directory")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>File contents displayed here.</body></html>")
            return

        # 4. Open redirect simulation
        if parsed.path == "/redirect":
            dest = params.get("next", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", dest)
            self.end_headers()
            return

        # 5. JSON API disclosure
        if parsed.path == "/api/users":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b'{"users": [{"id": 1, "name": "alice"}], "debug_info": "stage=lab"}')
            return

        # Default root page
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "nginx/1.24.0")
        self.send_header("X-Powered-By", "PHP/8.2.0")
        self.send_header("Set-Cookie", "session=lab_test_cookie_value; Path=/")
        self.end_headers()
        self.wfile.write(HTML_PAGE.encode("utf-8"))

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>POST Received</body></html>")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS, DELETE")
        self.end_headers()

    def log_message(self, format, *args):
        # Suppress noisy standard HTTP logs
        pass


def run_lab(port: int = 8888):
    server = HTTPServer(("127.0.0.1", port), VulnerableLabHandler)
    print(f"[*] Vulnerable Lab Application running on http://127.0.0.1:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping Lab Application.")
        server.server_close()


if __name__ == "__main__":
    run_lab()
