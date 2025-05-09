import configparser
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs, urlencode
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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default="config.ini", help='Path to the config file')
    parser.add_argument('--log_path', default="access_log.txt", help='Path to the access log file')
    parser.add_argument('--users_list', default="authorized_users.txt", help='Path to the authorized users list')
    parser.add_argument('--port', type=int, default=4000, help='Port number for the server')
    parser.add_argument('-d', '--deactivate_security', action='store_true', help='Deactivates security')
    args = parser.parse_args()

    servers = get_config(args.config)
    authorized_users = get_authorized_users(args.users_list)
    deactivate_security = args.deactivate_security

    ASCIIColors.red("Ollama Proxy server")
    ASCIIColors.red("Author: ParisNeo")

    class RequestHandler(BaseHTTPRequestHandler):
        def add_access_log_entry(self, event, user, ip_address, access, server, nb_queued_requests_on_server, error=""):
            log_file_path = Path(args.log_path)
            if not log_file_path.exists():
                with open(log_file_path, mode='w', newline='') as csvfile:
                    fieldnames = ['time_stamp', 'event', 'user_name', 'ip_address', 'access', 'server', 'nb_queued_requests_on_server', 'error']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
            with open(log_file_path, mode='a', newline='') as csvfile:
                fieldnames = ['time_stamp', 'event', 'user_name', 'ip_address', 'access', 'server', 'nb_queued_requests_on_server', 'error']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                row = {
                    'time_stamp': str(datetime.datetime.now()),
                    'event': event,
                    'user_name': user,
                    'ip_address': ip_address,
                    'access': access,
                    'server': server,
                    'nb_queued_requests_on_server': nb_queued_requests_on_server,
                    'error': error
                }
                writer.writerow(row)

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

        def do_HEAD(self):
            self.log_request()
            self.proxy()

        def do_GET(self):
            self.log_request()
            self.proxy()

        def do_POST(self):
            self.log_request()
            self.proxy()

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
                        # Custom format: ?auth=user:key/v1/chat/completions
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
                    # If path_override is present, rewrite self.path
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
                client_ip, _ = self.client_address
                # Try to get token for logging
                auth_header = self.headers.get('Authorization')
                token = None
                if auth_header and auth_header.startswith('Bearer '):
                    token = auth_header.split(' ')[1]
                else:
                    url = urlparse(self.path)
                    get_params = parse_qs(url.query)
                    if 'auth' in get_params:
                        token = get_params['auth'][0]
                self.add_access_log_entry(
                    event='rejected',
                    user=token if token else "unknown",
                    ip_address=client_ip,
                    access="Denied",
                    server="None",
                    nb_queued_requests_on_server=-1,
                    error="Authentication failed"
                )
                self.send_response(403)
                self.end_headers()
                return

            url = urlparse(self.path)
            path = url.path
            get_params = parse_qs(url.query) or {}

            # Remove auth param before forwarding
            get_params.pop('auth', None)

            if self.command == "POST":
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length) if content_length > 0 else b''
                post_params = post_data
            else:
                post_params = {}

            # Find the server with the lowest number of queued requests
            min_queued_server = servers[0]
            for server in servers:
                cs = server[1]
                if cs['queue'].qsize() < min_queued_server[1]['queue'].qsize():
                    min_queued_server = server

            # Apply queuing for specific endpoints
            if path in ['/api/generate', '/api/chat', '/v1/chat/completions']:
                que = min_queued_server[1]['queue']
                client_ip, _ = self.client_address
                self.add_access_log_entry(
                    event="gen_request",
                    user=self.user,
                    ip_address=client_ip,
                    access="Authorized",
                    server=min_queued_server[0],
                    nb_queued_requests_on_server=que.qsize()
                )
                que.put_nowait(1)
                try:
                    post_data_dict = {}
                    if isinstance(post_params, bytes) and post_params:
                        post_data_str = post_params.decode('utf-8')
                        try:
                            post_data_dict = json.loads(post_data_str)
                        except Exception:
                            post_data_dict = {}
                    response = requests.request(
                        self.command,
                        min_queued_server[1]['url'] + path,
                        params=get_params,
                        data=post_params,
                        stream=post_data_dict.get("stream", False)
                    )
                    self._send_response(response)
                except Exception as ex:
                    self.add_access_log_entry(event="gen_error",user=self.user, ip_address=client_ip, access="Authorized", server=min_queued_server[0], nb_queued_requests_on_server=que.qsize(),error=ex)                    
                finally:
                    que.get_nowait()
                    self.add_access_log_entry(event="gen_done",user=self.user, ip_address=client_ip, access="Authorized", server=min_queued_server[0], nb_queued_requests_on_server=que.qsize())                    
            else:
                # For other endpoints, just mirror the request.
                response = requests.request(self.command, min_queued_server[1]['url'] + path, params=get_params, data=post_params)
                self._send_response(response)

    class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
        pass


    print('Starting server')
    server = ThreadedHTTPServer(('', args.port), RequestHandler)  # Set the entry port here.
    print(f'Running server on port {args.port}')
    server.serve_forever()

if __name__ == "__main__":
    main()
