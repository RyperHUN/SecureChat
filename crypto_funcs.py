from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA3_256

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

def test_AES():
    key = b'0123456789abcdef0123456789abcdef'
    cipherText = encryptString(b"alma a fa alatt", key);
    print(cipherText.hex());
    print(decryptString(cipherText,key));





# ------RSA-------

def encrypt_RSA(ciphertext, key):
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(ciphertext)
    return ciphertext


def decrypt_RSA(ciphertext, key):
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8');

def get_rsa_key():
    RSA_key = RSA.generate(1024)
    return RSA_key;

def test_rsa():
    RSA_key = get_rsa_key()

    cipherText_RSA = encrypt_RSA(b"RSA a fa alatt", RSA_key.publickey());
    print(cipherText_RSA.hex())

    plainText_RSA = decrypt_RSA(cipherText_RSA, RSA_key);
    print(plainText_RSA)


# ------Signing-------

def signMessage(message, priv_rsa_key):
    #rsa_private key
    hash_mess = SHA3_256.new(message)
    signature = pss.new(priv_rsa_key).sign(hash_mess)
    return signature

def validateSigniture(message, pub_rsa_key, signature):
    verifier = pss.new(pub_rsa_key)
    hash_mess = SHA3_256.new(message)
    try:
        verifier.verify(hash_mess, signature)
        return True
    except (ValueError, TypeError):
        return False



