from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes, random
from Crypto.Util import Padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA3_256
from Crypto.Hash import HMAC, SHA
import binascii

DHPrime=int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",16)
DHGen = 2

def encryptString(plaintext, key):
    # Encryption#
    plaintext = Padding.pad(plaintext, AES.block_size);

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(plaintext);
    return (iv + ciphertext).hex();

def decryptString(ciphertextHex, key):
    ciphertext = binascii.unhexlify(ciphertextHex)
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = cipher.decrypt(ciphertext)
    plaintext = Padding.unpad(plaintext, AES.block_size)

    return plaintext.decode('utf-8');

def test_AES():
    key = b'0123456789abcdef0123456789abcdef'
    cipherText = encryptString(b"alma a fa alatt", key);
    print(cipherText);
    print(decryptString(cipherText,key));

# ------RSA-------

def encrypt_RSA(plaintext, key):
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext)
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

def save_rsa_key(key, name):
    ofile = open(name + '_rsa_key.pem', 'w');
    ofile.write(key.exportKey(format='PEM').decode('ASCII'));
    ofile.close();
    ofile = open(name + '_pub_key.pem', 'w');
    ofile.write(key.publickey().exportKey(format='PEM').decode('ASCII'));
    ofile.close();

def import_key(name):
    kfile = open(name, 'r')
    pubkeystr = kfile.read()
    kfile.close()

    pubkey = RSA.import_key(pubkeystr)
    return pubkey;


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

# ------HMAC-------

def generate_HMAC(message, key):
    hmac = HMAC.new(key, digestmod=SHA)
    hmac.update(message)
    return hmac

def check_HMAC(message, key, expected_hmac):
    hmac = HMAC.new(key, digestmod=SHA)
    hmac.update(message)
    try:
        hmac.verify(expected_hmac)
        print("The message '%s' is authentic" % message)
    except ValueError:
        print("The message or the key is wrong")

def test_mac():
    mackey = b'yoursecretMACkey'
    msg = b'Hello World! HMAC is a keyed hash function. '

    mac = generate_HMAC(msg, mackey);
    print("Message HMAC");
    print(mac.hexdigest());
    print(mac.digest());

    check_HMAC(msg, mackey, b'C\xach\xf8R\x13U\xfaA>\x19\xf6at\x81\x10h\xba\xff\x19');

def randInt():
    return random.getrandbits(256)