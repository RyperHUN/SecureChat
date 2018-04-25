from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding

def encryptString(plaintext, key):
    # Encryption#
    plaintext = Padding.pad(plaintext, AES.block_size);

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(plaintext);
    return iv + ciphertext;


def decryptString(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = cipher.decrypt(ciphertext)
    plaintext = Padding.unpad(plaintext, AES.block_size)

    return plaintext.decode('utf-8');

key = b'0123456789abcdef0123456789abcdef'
cipherText = encryptString(b"alma a fa alatt", key);
print(cipherText.hex());
print(decryptString(cipherText,key));

