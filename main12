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
import logging

# Configure logging at the start
logging.basicConfig(
    filename='server.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(module)s - %(funcName)s - %(lineno)d - %(message)s',
    encoding='utf-8'
)

logger = logging.getLogger(__name__)

def get_config(filename):
    try:
        logger.debug(f"Attempting to read config file: {filename}")
        print(f"Loading configuration from {filename}")
        config = configparser.ConfigParser()
        config.read(filename)
        result = [(name, {'url': config[name]['url'], 'queue': Queue()}) for name in config.sections()]
        logger.info(f"Successfully loaded config with sections: {config.sections()}")
        print(f"Config loaded with sections: {config.sections()}")
        return result
    except Exception as e:
        logger.exception(f"Error reading config file {filename}")
        print(f"Error loading config: {e}")
        raise

def get_authorized_users(filename):
    try:
        logger.debug(f"Attempting to read authorized users from: {filename}")
        print(f"Loading authorized users from {filename}")
        with open(filename, 'r') as f:
            lines = f.readlines()
        authorized_users = {}
        for line in lines:
            if not line.strip():
                continue
            try:
                user, key = line.strip().split(':')
                authorized_users[user] = key
            except Exception as e:
                logger.error(f"User entry broken in {filename}: {line.strip()} - Error: {e}")
                ASCIIColors.red(f"User entry broken: {line.strip()}")
        logger.info(f"Loaded {len(authorized_users)} authorized users")
        print(f"Loaded {len(authorized_users)} authorized users")
        return authorized_users
    except Exception as e:
        logger.exception(f"Error reading authorized users file {filename}")
        print(f"Error loading authorized users: {e}")
        raise

class RequestHandler(BaseHTTPRequestHandler):
    def _validate_user_and_key(self):
        try:
            logger.debug("Starting user validation")
            print("Validating user...")
            auth_header = self.headers.get('Authorization')
            token = None
            path_override = None
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                logger.debug(f"Found Bearer token in Authorization header")
                print("Found Bearer token in Authorization header")
            else:
                url = urlparse(self.path)
                get_params = parse_qs(url.query)
                if 'auth' in get_params:
                    full_auth = get_params['auth'][0]
                    full_auth = unquote(full_auth)
                    if '/' in full_auth:
                        token, path_override = full_auth.split('/', 1)
                        path_override = '/' + path_override
                        logger.debug(f"Found auth token with path override: {path_override}")
                        print(f"Auth token with path override: {path_override}")
                    else:
                        token = full_auth
                        logger.debug(f"Found auth token without path override")
                        print("Auth token found in URL")
            if not token or ':' not in token:
                logger.warning("No valid token found or token format incorrect")
                print("No valid token or incorrect format")
                return False
            user, key = token.split(':', 1)
            if authorized_users.get(user) == key:
                self.user = user
                logger.info(f"User {user} authenticated successfully")
                print(f"User {user} authenticated")
                if path_override:
                    url = urlparse(self.path)
                    query_params = parse_qs(url.query)
                    query_params.pop('auth', None)
                    new_query = urlencode(query_params, doseq=True)
                    self.path = path_override + ('?' + new_query if new_query else '')
                    logger.debug(f"Path overridden to: {self.path}")
                    print(f"Path overridden to: {self.path}")
                return True
            else:
                self.user = "unknown"
                logger.warning(f"Authentication failed for user {user}")
                print(f"Authentication failed for user {user}")
                return False
        except Exception as e:
            logger.exception("Error during user validation")
            print(f"Error during validation: {e}")
            return False

    def proxy(self):
        self.user = "unknown"
        logger.debug("Starting proxy process")
        print("Starting proxy process")
        if not deactivate_security and not self._validate_user_and_key():
            logger.error(f"User is not authorized for path: {self.path}")
            ASCIIColors.red(f'User is not authorized')
            print("User not authorized - sending 403")
            self.send_response(403)
            self.end_headers()
            return
        try:
            url = urlparse(self.path)
            path = url.path
            get_params = parse_qs(url.query) or {}
            get_params.pop('auth', None)
            logger.debug(f"Processed URL path: {path}, params after auth removal: {get_params}")
            print(f"URL path: {path}, params after auth removal")
            if self.command == "POST":
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length) if content_length > 0 else b''
                post_params = post_data
                logger.debug(f"POST request with content length: {content_length}")
                print(f"POST request data length: {content_length}")
            else:
                post_params = {}
                logger.debug("GET request detected")
                print("GET request")
            # Redirect to localhost:11434
            target_url = "http://localhost:11434" + path
            logger.info(f"Proxying request to: {target_url}")
            print(f"Proxying to: {target_url}")
            response = requests.request(self.command, target_url, params=get_params, data=post_params)
            logger.info(f"Received response from target with status: {response.status_code}")
            print(f"Target response status: {response.status_code}")
            self._send_response(response)
        except Exception as e:
            logger.exception(f"Error during proxying request to {target_url if 'target_url' in locals() else 'unknown target'}")
            print(f"Proxy error: {e}")
            self.send_response(500)
            self.end_headers()

    def _send_response(self, response):
        try:
            logger.debug("Sending response to client")
            print("Sending response to client")
            self.send_response(response.status_code)
            for key, value in response.headers.items():
                if key.lower() not in ['content-length', 'transfer-encoding', 'content-encoding']:
                    self.send_header(key, value)
            self.end_headers()
            content = response.content
            self.wfile.write(content)
            self.wfile.flush()
            logger.info("Response sent successfully")
            print("Response sent")
        except BrokenPipeError:
            logger.warning("Broken pipe error while sending response")
            print("Broken pipe error while sending response")
        except Exception as e:
            logger.exception("Error sending response to client")
            print(f"Error sending response: {e}")

    def do_GET(self):
        logger.debug("Handling GET request")
        print("Handling GET request")
        self.log_request()
        self.proxy()

    def do_POST(self):
        logger.debug("Handling POST request")
        print("Handling POST request")
        self.log_request()
        self.proxy()

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass

def main():
    try:
        logger.debug("Starting main server setup")
        print("Setting up server...")
        parser = argparse.ArgumentParser()
        parser.add_argument('--config', default="config.ini", help='Path to the config file')
        parser.add_argument('--log_path', default="access_log.txt", help='Path to the access log file')
        parser.add_argument('--users_list', default="authorized_users.txt", help='Path to the authorized users list')
        parser.add_argument('--port', type=int, default=4000, help='Port number for the server')
        parser.add_argument('-d', '--deactivate_security', action='store_true', help='Deactivates security')
        args = parser.parse_args()
        logger.info(f"Parsed arguments: config={args.config}, port={args.port}, security={'off' if args.deactivate_security else 'on'}")
        print(f"Server args - Config: {args.config}, Port: {args.port}, Security: {'off' if args.deactivate_security else 'on'}")
        
        global servers, authorized_users, deactivate_security
        servers = get_config(args.config)
        authorized_users = get_authorized_users(args.users_list)
        deactivate_security = args.deactivate_security
        
        ASCIIColors.red("Ollama Proxy server")
        ASCIIColors.red("Author: ParisNeo")
        print('Starting server')
        logger.info("Initializing HTTP server")
        server = ThreadedHTTPServer(('', args.port), RequestHandler)
        logger.info(f"Server started on port {args.port}")
        print(f'Running server on port {args.port}')
        server.serve_forever()
    except Exception as e:
        logger.exception("Fatal error in server startup")
        print(f"Server startup failed: {e}")
        raise

if __name__ == "__main__":
    logger.debug("Application start")
    print("Starting application...")
    main()
