import socketserver
import ssl
import time
from threading import Thread, Lock
from OpenSSL import crypto, SSL
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
import bcrypt

CREDENTIALS = {
    "thomas": bcrypt.hashpw(b"soleil", bcrypt.gensalt()),
}

CLIENT_STUB=f"""
import socket
import ssl
import threading
import readline
import pathlib
import requests

HOST, PORT = "{socket.gethostname()}", 9999

def receive_messages(ssock):
    while True:
        try:
            data = ssock.recv(4096)
            if not data:
                print("\\nServer closed the connection.")
                break
            message = data.decode('utf-8')
            print(f"\\r{{message}}\\n> {{readline.get_line_buffer()}}", end='', flush=True)
        except Exception as e:
            print(f"\\nError receiving data: {{e}}")
            break

def main(context):
    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as ssock:
            print(f"Connected to {{HOST}}:{{PORT}}")
            receive_thread = threading.Thread(target=receive_messages, args=(ssock,))
            receive_thread.daemon = True
            receive_thread.start()    
            try:
                while True:
                    message = input("> ")
                    if message.lower() == 'exit':
                        break
                    ssock.sendall(message.encode('utf-8'))
            except KeyboardInterrupt:
                ssock.close()
                print("[!] Exiting")

if __name__ == '__main__':
    if not pathlib.Path('./cert.pem').exists():
        r = requests.get(f"http://{{HOST}}:8080/cert")
        if r.status_code == 200:
            with open('./cert.pem', 'w') as f:
                f.write(r.text)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations('cert.pem')
    main(context)

print("[OK] Client exited.")
"""

def gen_certificate(
    emailAddress="toto@legoat.42.fr",
    commonName=None,
    countryName="FR",
    localityName="42",
    stateOrProvinceName="IDF",
    organizationName="goatesque",
    organizationUnitName="RnD",
    serialNumber=0,
    validityStartInSeconds=0,
    validityEndInSeconds=10 * 365 * 24 * 60 * 60,
    KEY_FILE="key.pem",
    CERT_FILE="cert.pem",
):
    if commonName is None:
        commonName = socket.gethostname()
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateOrProvinceName
    cert.get_subject().L = localityName
    cert.get_subject().O = organizationName
    cert.get_subject().OU = organizationUnitName
    cert.get_subject().CN = commonName
    cert.get_subject().emailAddress = emailAddress
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(validityStartInSeconds)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, "sha512")
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/client':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(CLIENT_STUB.encode())
        elif self.path == '/cert':
            with open("cert.pem", "r") as cert_file:
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(cert_file.read().encode())
        else:
            self.send_response_only(404)


class Client:
    def __init__(self, ip, name, connection):
        self.ip = ip
        self.name = name
        self.connection = connection
        self.authenticated = False


class MyTCPHandler(socketserver.BaseRequestHandler):
    clients = []
    clients_lock = Lock()

    def handle(self):
        client_ip = self.client_address[0]
        sess_client = None
        with self.clients_lock:
            for client in self.clients:
                if client.ip == client_ip:
                    sess_client = client
            if sess_client is None:
                sess_client = Client(
                    client_ip, str(id(client_ip) ^ int(time.time())), self.request
                )
                self.clients.append(sess_client)
        print(f"Connection from: {client_ip}")
        try:
            while True:
                self.data = self.request.recv(4096)
                if self.data.decode().startswith("LOGIN="):
                    parts = self.data.decode()[len("LOGIN="):].split(':')
                    if len(parts) == 2:
                        username, password = parts
                        if username in CREDENTIALS and bcrypt.checkpw(password.encode("utf-8"), CREDENTIALS[username]):
                            sess_client.name = username
                            sess_client.authenticated = True
                            self.request.sendall(b"LOGIN_SUCCESS\n")
                        else:
                            self.request.sendall(b"LOGIN_FAILED\n")
                    else:
                        self.request.sendall(b"LOGIN_FAILED\n")
                    continue
                if not len(self.data):
                    print(f"Connection closed by: {client_ip}")
                    break
                if self.data.decode().startswith("USERNAME="):
                    sess_client.name = self.data.decode().split("=")[1]
                    self.request.send(b"OK")
                    continue
                self.broadcast_message(
                    sess_client, sess_client.name.encode() + b" > " + self.data
                )
        finally:
            with self.clients_lock:
                self.clients.remove(sess_client)

    def broadcast_message(self, sender, message):
        with self.clients_lock:
            for client in self.clients:
                if client != sender:
                    try:
                        client.connection.sendall(message)
                    except Exception as e:
                        print(f"Error sending message to {client.ip}: {e}")


class ReusableTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

    def get_request(self):
        newsocket, fromaddr = super().get_request()
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
        connstream = context.wrap_socket(newsocket, server_side=True)
        return connstream, fromaddr

def run_http(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting httpd server on port {port}')
    httpd.serve_forever()

def run_socket(host, port):
    with ReusableTCPServer((host, port), MyTCPHandler) as server:
        print("Server started at {}:{}".format(host, port))
        server.serve_forever()

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 9999
    gen_certificate()

    http_port = 8080

    http_thread = Thread(target=run_http, args=(HTTPServer, SimpleHTTPRequestHandler, http_port))
    socket_thread = Thread(target=run_socket, args=(HOST, PORT))

    http_thread.start()
    socket_thread.start()

    http_thread.join()
    socket_thread.join()
    print("[OK] Exited.")
