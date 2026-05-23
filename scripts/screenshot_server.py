#!/usr/bin/env python3
"""实时截图查看服务器 — 访问 http://localhost:8766"""
import http.server, time, os, sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8766
SCREENSHOT_PATH = "/tmp/paypal_live.png"

HTML = b"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>PayPal Live</title>
<style>
  body { margin: 0; background: #111; display: flex; flex-direction: column; align-items: center; }
  h3 { color: #aaa; font-family: monospace; margin: 8px; }
  img { max-width: 100%; border: 1px solid #333; }
</style>
</head>
<body>
<h3 id="ts">loading...</h3>
<img id="img" src="/shot?t=0">
<script>
function refresh() {
  var t = Date.now();
  document.getElementById('img').src = '/shot?t=' + t;
  document.getElementById('ts').textContent = new Date().toLocaleTimeString();
}
setInterval(refresh, 2000);
refresh();
</script>
</body>
</html>"""

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/shot'):
            if os.path.exists(SCREENSHOT_PATH):
                data = open(SCREENSHOT_PATH, 'rb').read()
                self.send_response(200)
                self.send_header('Content-Type', 'image/png')
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(HTML)))
            self.end_headers()
            self.wfile.write(HTML)

    def log_message(self, fmt, *args):
        pass  # 静默

print(f"截图服务器启动: http://0.0.0.0:{PORT}  (截图路径: {SCREENSHOT_PATH})")
http.server.HTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
