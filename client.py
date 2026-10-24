import crypto_utils
import socket
from colorama import Fore, Style, init

init()

SERVER_HOST = "127.0.0.1"
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

        print_info("Starting secure key agreement...")
        client_priv, client_pub = crypto_utils.generate_key_pair()
        server_pub_bytes = crypto_utils.recv_frame(client_socket)
        if server_pub_bytes is None:
            raise ConnectionError("Server closed the connection during key exchange")
        crypto_utils.send_frame(client_socket, client_pub.export_key(format="PEM").encode("utf-8"))

        shared_secret = crypto_utils.derive_shared_secret(client_priv, server_pub_bytes)
        aes_key, hmac_key = crypto_utils.derive_keys(shared_secret)
        print_success("Secure key exchange completed.")

        print_info("You can now send encrypted messages. Type 'exit' to quit.")
        send_counter = 0
        receive_counter = 0
        while True:
            msg = input(f"{Fore.WHITE}Message: {Style.RESET_ALL}")
            if msg.lower() == "exit":
                break

            crypto_utils.send_json(
                client_socket,
                crypto_utils.encrypt_message(msg, aes_key, hmac_key, send_counter),
            )
            send_counter += 1

            payload = crypto_utils.recv_json(client_socket)
            if payload is None:
                break
            response, error = crypto_utils.decrypt_message(
                payload, aes_key, hmac_key, expected_counter=receive_counter
            )
            if error:
                print_warning(f"Message integrity verification failed! {error}")
                break
            receive_counter += 1
            print_info(f"Secure response: {Fore.MAGENTA}{response}{Style.RESET_ALL}")

    except Exception as exc:
        print_error(f"Connection error: {exc}")
    finally:
        client_socket.close()
        print_info("Disconnected from server.")


if __name__ == "__main__":
    start_client()
