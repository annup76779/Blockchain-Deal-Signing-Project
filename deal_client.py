import socket
import json
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


class DealClient:
    def __init__(self, host='localhost', port=65432):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.host, self.port))

    def send_request(self, request):
        self.client_socket.send(json.dumps(request).encode('utf-8'))
        response = self.client_socket.recv(65536).decode('utf-8')
        return json.loads(response)

    def generate_and_save_keys(self, name):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        public_key = private_key.public_key()

        with open(f"{name}_private_key.pem", "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        with open(f"{name}_public_key.pem", "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

        return private_key, public_key

    def sign_file(self, file_path, file_name, private_key, party_name):
        with open(file_path, "rb") as f:
            file_data = f.read()

        signature = private_key.sign(
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        with open(f"Signatures/{party_name}_signed_{file_name}.sig", "wb") as sig_file:
            sig_file.write(signature)

        return signature

    def verify_signature(self, file_path, signature_path, public_key):
        with open(file_path, "rb") as f:
            file_data = f.read()

        with open(signature_path, "rb") as sig_file:
            signature = sig_file.read()

        try:
            public_key.verify(
                signature,
                file_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception as e:
            return False

    def handle_deals(self):
        # Generate keys for Seller and Buyer
        seller_private_key, seller_public_key = self.generate_and_save_keys("Seller")
        buyer_private_key, buyer_public_key = self.generate_and_save_keys("Buyer")
        os.makedirs("Signatures", exist_ok=True)

        for deal_file, deal_file_name in ((os.path.join(os.path.dirname(__file__), 'deals', file), file) for file in
                                          os.listdir("./deals")):
            # Seller signs the deal
            seller_signature = self.sign_file(deal_file, deal_file_name, seller_private_key, "Seller")

            # Buyer verifies the Seller's signature
            if self.verify_signature(deal_file, f"Signatures/Seller_signed_{deal_file_name}.sig", seller_public_key):
                print(f"Buyer's verification: Seller's signature for {deal_file_name} is valid.")

                # Add the Seller's signature data to the blockchain via the socket
                document_hash = hashlib.sha256(open(deal_file, 'rb').read()).hexdigest()
                signer_identity = "CN=Seller, O=Company, C=US"
                request = {
                    'action': 'add_to_pool',
                    'document_hash': document_hash,
                    'signature': seller_signature.hex(),
                    'public_key': seller_public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8'),
                    'signer_identity': signer_identity
                }
                self.send_request(request)

                # Buyer signs the deal after verification
                buyer_signature = self.sign_file(deal_file, deal_file_name, buyer_private_key, "Buyer")

                # Seller verifies the Buyer's signature
                if self.verify_signature(deal_file, f"Signatures/Buyer_signed_{deal_file_name}.sig", buyer_public_key):
                    print(f"Seller's verification: Buyer's signature for {deal_file_name} is valid.")

                    # Add the Buyer's signature data to the blockchain via the socket
                    request = {
                        'action': 'add_to_pool',
                        'document_hash': document_hash,
                        'signature': buyer_signature.hex(),
                        'public_key': buyer_public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8'),
                        'signer_identity': "CN=Buyer, O=Company, C=US"
                    }
                    self.send_request(request)

                    # Mine the block with the deal information via the socket
                    request = {'action': 'mine'}
                    self.send_request(request)
                else:
                    print(f"Seller's verification: Buyer's signature for {deal_file_name} is invalid.")
            else:
                print(f"Buyer's verification: Seller's signature for {deal_file_name} is invalid.")


if __name__ == "__main__":
    client = DealClient()
    client.handle_deals()
