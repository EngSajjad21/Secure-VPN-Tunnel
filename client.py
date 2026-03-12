import socket
import json
import crypto_utils
from colorama import Fore, Style, init

# Initialize colorama
init()

# Configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999

def print_info(msg):
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")

def print_success(msg):
    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {msg}")

def print_warning(msg):
    print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {msg}")

def print_error(msg):
    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        print_info(f"Connected to VPN Server at {SERVER_HOST}:{SERVER_PORT}")
        
        # 1. Key Exchange
        print_info("Starting secure key agreement...")
        client_priv, client_pub = crypto_utils.generate_key_pair()
        
        # Receive server's public key
        server_pub_bytes = client_socket.recv(4096)
        
        # Send client's public key
        client_socket.sendall(client_pub.export_key(format='PEM').encode('utf-8'))
        
        # Derive shared secret and session keys
        shared_secret = crypto_utils.derive_shared_secret(client_priv, server_pub_bytes)
        aes_key, hmac_key = crypto_utils.derive_keys(shared_secret)
        print_success("Secure key exchange completed.")
        
        # 2. Secure Communication
        print_info("You can now send encrypted messages. Type 'exit' to quit.")
        while True:
            msg = input(f"{Fore.WHITE}Message: {Style.RESET_ALL}")
            if msg.lower() == 'exit':
                break
                
            # Encrypt and send
            encrypted_payload = crypto_utils.encrypt_message(msg, aes_key, hmac_key)
            client_socket.sendall(json.dumps(encrypted_payload).encode('utf-8'))
            
            # Receive and decrypt response
            data = client_socket.recv(4096)
            if not data:
                break
                
            try:
                payload = json.loads(data.decode('utf-8'))
                response, error = crypto_utils.decrypt_message(payload, aes_key, hmac_key)
                
                if error:
                    print_warning(f"Message integrity verification failed! {error}")
                else:
                    print_info(f"Secure response: {Fore.MAGENTA}{response}{Style.RESET_ALL}")
            except json.JSONDecodeError:
                print_error("Received malformed JSON response.")
                
    except Exception as e:
        print_error(f"Connection error: {e}")
    finally:
        client_socket.close()
        print_info("Disconnected from server.")

if __name__ == "__main__":
    start_client()
