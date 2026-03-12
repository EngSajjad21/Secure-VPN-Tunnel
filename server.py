import socket
import json
import crypto_utils
from colorama import Fore, Style, init

# Initialize colorama
init()

# Configuration
HOST = '0.0.0.0'
PORT = 9999

def print_info(msg):
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")

def print_success(msg):
    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {msg}")

def print_warning(msg):
    print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {msg}")

def print_error(msg):
    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        print_info(f"VPN Server listening on {HOST}:{PORT}")
    except Exception as e:
        print_error(f"Failed to start server: {e}")
        return
    
    while True:
        conn, addr = server_socket.accept()
        print_info(f"Client connected from {addr}")
        
        try:
            # 1. Key Exchange
            print_info("Starting secure key agreement...")
            server_priv, server_pub = crypto_utils.generate_key_pair()
            
            # Send server's public key
            conn.sendall(server_pub.export_key(format='PEM').encode('utf-8'))
            
            # Receive client's public key
            client_pub_bytes = conn.recv(4096)
            if not client_pub_bytes:
                break
                
            # Derive shared secret and session keys
            shared_secret = crypto_utils.derive_shared_secret(server_priv, client_pub_bytes)
            aes_key, hmac_key = crypto_utils.derive_keys(shared_secret)
            print_success("Secure key exchange completed.")
            
            # 2. Secure Communication
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                
                try:
                    payload = json.loads(data.decode('utf-8'))
                    message, error = crypto_utils.decrypt_message(payload, aes_key, hmac_key)
                    
                    if error:
                        print_warning(f"Message integrity verification failed! {error}")
                        continue
                    
                    print_info(f"Encrypted message received: {Fore.MAGENTA}{message}{Style.RESET_ALL}")
                    
                    # Send encrypted response
                    response_text = f"Server processed: {message}"
                    encrypted_response = crypto_utils.encrypt_message(response_text, aes_key, hmac_key)
                    conn.sendall(json.dumps(encrypted_response).encode('utf-8'))
                except json.JSONDecodeError:
                    print_error("Received malformed JSON packet.")
                
        except Exception as e:
            print_error(f"Connection error: {e}")
        finally:
            conn.close()
            print_info("Client disconnected.")

if __name__ == "__main__":
    start_server()
