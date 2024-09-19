from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64decode, urlsafe_b64encode
import os

def gen_key(password:str, salt:bytes):
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        iterations=1000,
        length=32,
        salt = salt,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypy_message(plain_txt: str, key:bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_txt.encode()) + padder.finalize()
    cipher_txt = encryptor.update(padded_data) + encryptor.finalize()
    return iv + cipher_txt

def decrypt(key :bytes, cipher_txt:bytes ):
    iv = cipher_txt[:16]
    real_txt = cipher_txt[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(real_txt) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode()





if __name__ == "__main__":
    password = "secret_password"
    salt = os.urandom(16)
    key = gen_key(password, salt)

    message = "anna is a sexy fucker"
    encryption = encrypy_message(message, key)
    print(f"message encrypted {encryption}")

    decryption = decrypt(key, encryption)
    print(f"decrypted message ======= {decryption}")