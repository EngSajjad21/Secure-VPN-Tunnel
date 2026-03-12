import crypto_utils
import colorama
from colorama import Fore, Style

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
    # 1. Test Key Pair Generation
    print_info("Testing Key Pair Generation...")
    priv, pub = crypto_utils.generate_key_pair()
    print_success("Key pair generated.")

    # 2. Test Key Exchange
    print_info("Testing Key Exchange...")
    priv1, pub1 = crypto_utils.generate_key_pair()
    priv2, pub2 = crypto_utils.generate_key_pair()
    
    secret1 = crypto_utils.derive_shared_secret(priv1, pub2.export_key(format='PEM'))
    secret2 = crypto_utils.derive_shared_secret(priv2, pub1.export_key(format='PEM'))
    
    assert secret1 == secret2
    print_success("Shared secrets match.")

    # 3. Test Encryption/Decryption
    print_info("Testing Encryption/Decryption...")
    aes_key, hmac_key = crypto_utils.derive_keys(secret1)
    message = "Secret tunnel message!"
    
    encrypted = crypto_utils.encrypt_message(message, aes_key, hmac_key)
    decrypted, error = crypto_utils.decrypt_message(encrypted, aes_key, hmac_key)
    
    assert decrypted == message
    assert error is None
    print_success(f"Message '{message}' decrypted correctly.")

    # 4. Test Integrity Violation
    print_info("Testing HMAC Integrity Verification...")
    # Tamper with ciphertext
    tampered_encrypted = encrypted.copy()
    raw_ciphertext = list(tampered_encrypted['ciphertext'])
    raw_ciphertext[0] = 'A' if raw_ciphertext[0] != 'A' else 'B'
    tampered_encrypted['ciphertext'] = "".join(raw_ciphertext)
    
    decrypted, error = crypto_utils.decrypt_message(tampered_encrypted, aes_key, hmac_key)
    assert decrypted is None
    print_warning(f"Message integrity verification failed! Error: {error}")

if __name__ == "__main__":
    try:
        test_crypto()
        print(f"\n{Fore.GREEN}{Style.BRIGHT}[ALL TESTS PASSED]{Style.RESET_ALL}")
    except Exception as e:
        print_error(f"Test failed: {e}")
