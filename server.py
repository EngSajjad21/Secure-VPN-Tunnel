import json
import os
import socket

import crypto_utils
from colorama import Fore, Style, init

init()

HOST = os.getenv("VPN_HOST", "127.0.0.1")
PORT = int(os.getenv("VPN_PORT", "9999"))


def print_info(msg):
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")


def print_success(msg):
    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {msg}")


def print_warning(msg):
    print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {msg}")


def print_error(msg):
    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_socket.bind((HOST, PORT))
            server_socket.listen(1)
            print_info(f"VPN Server listening on {HOST}:{PORT}")
        except OSError as exc:
            print_error(f"Failed to start server: {exc}")
            return

        while True:
            conn, addr = server_socket.accept()
            with conn:
                print_info(f"Client connected from {addr}")
                try:
                    print_info("Starting secure key agreement...")
                    server_priv, server_pub = crypto_utils.generate_key_pair()
                    crypto_utils.send_frame(
                        conn, server_pub.export_key(format="PEM").encode("utf-8")
                    )
                    client_pub_bytes = crypto_utils.recv_frame(conn)
                    if client_pub_bytes is None:
                        raise ConnectionError("Client closed the connection during key exchange")

                    shared_secret = crypto_utils.derive_shared_secret(
                        server_priv, client_pub_bytes
                    )
                    aes_key, hmac_key = crypto_utils.derive_keys(shared_secret)
                    print_success("Secure key exchange completed.")

                    receive_counter = 0
                    send_counter = 0
                    while True:
                        payload = crypto_utils.recv_json(conn)
                        if payload is None:
                            break
                        message, error = crypto_utils.decrypt_message(
                            payload,
                            aes_key,
                            hmac_key,
                            expected_counter=receive_counter,
                        )
                        if error:
                            print_warning(f"Message rejected: {error}")
                            break
                        receive_counter += 1
                        print_info(
                            f"Encrypted message received: {Fore.MAGENTA}{message}{Style.RESET_ALL}"
                        )
                        response = crypto_utils.encrypt_message(
                            f"Server processed: {message}",
                            aes_key,
                            hmac_key,
                            send_counter,
                        )
                        crypto_utils.send_json(conn, response)
                        send_counter += 1

                except (ConnectionError, json.JSONDecodeError, ValueError) as exc:
                    print_error(f"Connection error: {exc}")
                except Exception as exc:
                    print_error(f"Unexpected connection error: {exc}")
                finally:
                    print_info("Client disconnected.")


if __name__ == "__main__":
    start_server()
