import configparser
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs, urlencode, unquote
from queue import Queue
import requests
import argparse
from ascii_colors import ASCIIColors
from pathlib import Path
import csv
import datetime

def get_config(filename):
    config = configparser.ConfigParser()
    config.read(filename)
    return [(name, {'url': config[name]['url'], 'queue': Queue()}) for name in config.sections()]

def get_authorized_users(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
    authorized_users = {}
    for line in lines:
        if not line.strip():
            continue
        try:
            user, key = line.strip().split(':')
            authorized_users[user] = key
        except Exception:
            ASCIIColors.red(f"User entry broken: {line.strip()}")
    return authorized_users

class RequestHandler(BaseHTTPRequestHandler):
    def _validate_user_and_key(self):
        try:
            auth_header = self.headers.get('Authorization')
            token = None
            path_override = None
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
            else:
                url = urlparse(self.path)
                get_params = parse_qs(url.query)
                if 'auth' in get_params:
                    full_auth = get_params['auth'][0]
                    full_auth = unquote(full_auth)
                    if '/' in full_auth:
                        token, path_override = full_auth.split('/', 1)
                        path_override = '/' + path_override
                    else:
                        token = full_auth
            if not token or ':' not in token:
                return False
            user, key = token.split(':', 1)
            if authorized_users.get(user) == key:
                self.user = user
                if path_override:
                    url = urlparse(self.path)
                    query_params = parse_qs(url.query)
                    query_params.pop('auth', None)
                    new_query = urlencode(query_params, doseq=True)
                    self.path = path_override + ('?' + new_query if new_query else '')
                return True
            else:
                self.user = "unknown"
                return False
        except Exception:
            return False

    def proxy(self):
        self.user = "unknown"
        if not deactivate_security and not self._validate_user_and_key():
            ASCIIColors.red(f'User is not authorized')
            self.send_response(403)
            self.end_headers()
            return
        url = urlparse(self.path)
        path = url.path
        get_params = parse_qs(url.query) or {}
        get_params.pop('auth', None)  
        if self.command == "POST":
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length) if content_length > 0 else b''
            post_params = post_data
        else:
            post_params = {}
        # Redirect to localhost:11434
        target_url = "http://localhost:11434" + path
        response = requests.request(self.command, target_url, params=get_params, data=post_params)
        self._send_response(response)

    def _send_response(self, response):
        self.send_response(response.status_code)
        for key, value in response.headers.items():
            if key.lower() not in ['content-length', 'transfer-encoding', 'content-encoding']:
                self.send_header(key, value)
        self.end_headers()
        try:
            content = response.content
            self.wfile.write(content)
            self.wfile.flush()
        except BrokenPipeError:
            pass

    def do_GET(self):
        self.log_request()
        self.proxy()

    def do_POST(self):
        self.log_request()
        self.proxy()

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default="config.ini", help='Path to the config file')
    parser.add_argument('--log_path', default="access_log.txt", help='Path to the access log file')
    parser.add_argument('--users_list', default="authorized_users.txt", help='Path to the authorized users list')
    parser.add_argument('--port', type=int, default=4000, help='Port number for the server')
    parser.add_argument('-d', '--deactivate_security', action='store_true', help='Deactivates security')
    args = parser.parse_args()
    global servers, authorized_users, deactivate_security
    servers = get_config(args.config)
    authorized_users = get_authorized_users(args.users_list)
    deactivate_security = args.deactivate_security
    ASCIIColors.red("Ollama Proxy server")
    ASCIIColors.red("Author: ParisNeo")
    print('Starting server')
    server = ThreadedHTTPServer(('', args.port), RequestHandler)
    print(f'Running server on port {args.port}')
    server.serve_forever()

if __name__ == "__main__":
    main()
