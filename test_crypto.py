import sys

import colorama
from colorama import Fore, Style

import crypto_utils

colorama.init()


def print_info(msg):
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")


def print_success(msg):
    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {msg}")


def print_warning(msg):
    print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {msg}")


def print_error(msg):
    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")


def test_crypto():
    print_info("Testing Key Pair Generation...")
    _, _ = crypto_utils.generate_key_pair()
    print_success("Key pair generated.")

    print_info("Testing Key Exchange...")
    priv1, pub1 = crypto_utils.generate_key_pair()
    priv2, pub2 = crypto_utils.generate_key_pair()
    secret1 = crypto_utils.derive_shared_secret(priv1, pub2.export_key(format="PEM"))
    secret2 = crypto_utils.derive_shared_secret(priv2, pub1.export_key(format="PEM"))
    assert secret1 == secret2
    print_success("Shared secrets match.")

    print_info("Testing Encryption/Decryption...")
    aes_key, hmac_key = crypto_utils.derive_keys(secret1)
    message = "Secret tunnel message!"
    encrypted = crypto_utils.encrypt_message(message, aes_key, hmac_key, counter=0)
    decrypted, error = crypto_utils.decrypt_message(
        encrypted, aes_key, hmac_key, expected_counter=0
    )
    assert decrypted == message
    assert error is None
    print_success(f"Message '{message}' decrypted correctly.")

    print_info("Testing Replay Protection...")
    replayed, replay_error = crypto_utils.decrypt_message(
        encrypted, aes_key, hmac_key, expected_counter=1
    )
    assert replayed is None
    assert replay_error and "counter" in replay_error.lower()
    print_success("Replay protection rejected the old counter.")

    print_info("Testing HMAC Integrity Verification...")
    tampered = encrypted.copy()
    tampered["ciphertext"] = "A" + tampered["ciphertext"][1:]
    decrypted, error = crypto_utils.decrypt_message(
        tampered, aes_key, hmac_key, expected_counter=0
    )
    assert decrypted is None
    assert error is not None
    print_warning(f"Integrity violation rejected: {error}")


if __name__ == "__main__":
    try:
        test_crypto()
        print(f"\n{Fore.GREEN}{Style.BRIGHT}[ALL TESTS PASSED]{Style.RESET_ALL}")
    except Exception as exc:
        print_error(f"Test failed: {exc}")
        sys.exit(1)
