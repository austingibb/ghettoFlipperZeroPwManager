import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pyperclip

# Constants
BLOCK_SIZE = 16  # AES block size for CBC mode

def pad(data):
    padding = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + (chr(padding) * padding).encode()

def unpad(data):
    return data[:-ord(data[-1:])]

def encrypt(password, key):
    key = hashlib.sha256(key.encode()).digest()
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(password.encode()))
    return base64.b64encode(iv + encrypted).decode()

def decrypt(encrypted_base64, key):
    key = hashlib.sha256(key.encode()).digest()
    encrypted = base64.b64decode(encrypted_base64)
    iv = encrypted[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted[BLOCK_SIZE:])
    return unpad(decrypted).decode()

def copy_to_clipboard(text):
    pyperclip.copy(text)
    print("Copied to clipboard.")

def main():
    print("Interactive AES Encryption/Decryption")
    print("Commands:")
    print("  encrypt <plaintext password>")
    print("  decrypt <base64 encrypted string>")
    print("  exit")
    
    while True:
        command = input(">>> ").strip().split(" ", 1)
        if len(command) < 2 and command[0] not in ["exit"]:
            print("Invalid command. Use 'encrypt <text>' or 'decrypt <text>'.")
            continue
        
        action = command[0].lower()
        argument = command[1] if len(command) > 1 else ""

        if action == "encrypt":
            key = input("Enter your pre-shared key (PSK): ")
            encrypted = encrypt(argument, key)
            print("Encrypted Base64:")
            print(encrypted)
            if input("Would you like to copy to clipboard? [Y/N]: ").strip().lower() == 'y':
                copy_to_clipboard(encrypted)
        elif action == "decrypt":
            print("Decrypting...")
            key = input("Enter your pre-shared key (PSK): ")
            try:
                decrypted = decrypt(argument, key)
                print("Decrypted Plaintext:")
                print(decrypted)
                if input("Would you like to copy to clipboard? [Y/N]: ").strip().lower() == 'y':
                    copy_to_clipboard(decrypted)
            except Exception as e:
                print(f"Error during decryption: {e}")
        elif action == "exit":
            print("Exiting.")
            break
        else:
            print("Unknown command. Use 'encrypt <text>', 'decrypt <text>', or 'exit'.")

if __name__ == "__main__":
    try:
        import pyperclip
    except ImportError:
        print("The pyperclip library is required. Install it with 'pip install pyperclip'.")
        exit(1)
    main()
