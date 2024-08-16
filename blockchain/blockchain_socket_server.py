import socket
import threading
import json
from .Chain import Chain


class BlockchainSocketServer:
    def __init__(self, host='localhost', port=65432):
        self.host = host
        self.port = port
        self.blockchain = Chain(difficulty=15)  # Adjust difficulty as needed
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")

    def client_handler(self, client_socket, address):
        print(f"Connection established with {address}")
        while True:
            try:
                data = client_socket.recv(65536).decode('utf-8')
                if not data:
                    break

                request = json.loads(data)
                if request['action'] == 'add_to_pool':
                    self.handle_add_to_pool(request, client_socket)
                elif request['action'] == 'mine':
                    self.handle_mine(client_socket)

            except Exception as e:
                print(f"Error: {e}")
                break

        print(f"Connection with {address} closed")
        client_socket.close()

    def handle_add_to_pool(self, request, client_socket):
        document_hash = request['document_hash']
        signature = request['signature']
        public_key = request['public_key']
        signer_identity = request['signer_identity']

        self.blockchain.add_to_pool(document_hash, signature, public_key, signer_identity)
        response = {'status': 'added_to_pool'}
        client_socket.send(json.dumps(response).encode('utf-8'))

    def handle_mine(self, client_socket):
        self.blockchain.mine()
        response = {'status': 'mined'}
        client_socket.send(json.dumps(response).encode('utf-8'))

    def start(self):
        print("Waiting for connections...")
        while True:
            client_socket, address = self.server_socket.accept()
            client_thread = threading.Thread(target=self.client_handler, args=(client_socket, address))
            client_thread.start()