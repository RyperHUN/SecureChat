from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes, random
from Crypto.Util import Padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import HMAC, SHA, SHA3_256
from Crypto.Signature import pkcs1_15
from Crypto.Protocol import KDF
import binascii
import hashlib
import json;
import os;
import smtplib
from random import randint

#TODO Find better prime
DHPrime=1522605027922533360535618378132637429718068114961380688657908494580122963258952897654000350692006139
DHGen = 2


####
#Helpers
def string_to_byte(str):
    return str.encode('utf-8');

def byte_to_string(bytes):
    return bytes.decode('utf-8');

def hex_to_bytes(hex):
    return binascii.unhexlify(hex);

def bytes_to_hex(bytes):
    return bytes.hex();

def dict_to_bytes(dict):
    return string_to_byte(json.dumps(dict))

def bytes_to_dict(the_binary):
    return json.loads(byte_to_string(the_binary))

def RSA_to_str(rsa_key):
    return rsa_key.exportKey(format='PEM').decode('ASCII');

def str_to_RSA(str):
    return RSA.import_key(str);
##


def encryptString(plaintext, key):
    # Encryption#
    plaintext = Padding.pad(plaintext, AES.block_size);

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(plaintext);
    return (iv + ciphertext).hex();

def decryptString(ciphertextHex, key):
    ciphertext = hex_to_bytes(ciphertextHex)
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = cipher.decrypt(ciphertext)
    plaintext = Padding.unpad(plaintext, AES.block_size)

    return plaintext.decode('utf-8');

# ------RSA-------

def encrypt_RSA(plaintext, key):
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex();

def decrypt_RSA_toBytes(ciphertext, key):
    cipher = PKCS1_OAEP.new(key)
    bytes = binascii.unhexlify(ciphertext);
    plaintext = cipher.decrypt(bytes)
    return plaintext;

def decrypt_RSA_toStr(ciphertext, key):
    return decrypt_RSA_toBytes(ciphertext,key).decode('utf-8');



def get_rsa_key():
    RSA_key = RSA.generate(2048)
    return RSA_key;

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

def create_rsa_key(name):
    priv_name = name + "_rsa_key.pem";
    pub_name = name + "_rsa_key.pem";
    if not os.path.isfile(pub_name):
        key = get_rsa_key();
        save_rsa_key(key, name);
        return key.publickey(),key;
    else :
        key_priv = import_key(priv_name);
        key_pub  = import_key(pub_name);
        return key_pub, key_priv;

# ------Signing-------

def digital_sign_message(message, priv_rsa_key):
    #rsa_private key
    hash_mess = SHA3_256.new(message)
    signature = pss.new(priv_rsa_key).sign(hash_mess)
    return signature

def digital_sign_verify(message, pub_rsa_key, signature):
    verifier = pss.new(pub_rsa_key)
    hash_mess = SHA3_256.new(message)
    try:
        verifier.verify(hash_mess, signature)
        return True
    except (ValueError, TypeError) as e:
        #print(e)
        return False

# ------HMAC-------

def generate_HMAC(message, key):
    hmac = HMAC.new(key, digestmod=SHA3_256)
    hmac.update(message)
    return hmac.hexdigest()

def check_HMAC(message, key, expected_hmac):
    hmac = HMAC.new(key, digestmod=SHA3_256)
    hmac.update(message)
    try:
        hmac.verify(expected_hmac)
        return True
    except ValueError:
        return False

#####################

def randInt():
    return random.getrandbits(256)

def hash(password):
    return SHA3_256.new(password).hexdigest()

def generateAES(masterkey_bin):
    key_bin = masterkey_bin
    if type(key_bin) is int:
        key_bin = str(key_bin)
    if type(key_bin) is str:
        key_bin = string_to_byte(key_bin)

    result_bin = hex_to_bytes(SHA3_256.new(key_bin).hexdigest());

    return result_bin;

#----email verification function----

emailVerificationCode = randint(100000, 999999)

def send_Verificationemail(to, verificationCode):
    toEmail = to
    subject = 'E-mail verification message'
    message = 'E-mail verification code: ' + str(verificationCode)
    senderEmail = 'chat.email.verifi@gmail.com'
    senderPasswd = 'biztproto'
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.ehlo()
    server.starttls()
    server.login(senderEmail, senderPasswd)
    body = '\r\n'.join(['To: %s' % toEmail, 'From: %s' % senderEmail, 'Subject: %s' % subject, '', message])
    server.sendmail(senderEmail, [toEmail], body)
    server.quit()


def diffie_hellman_send():
    #TODO Need to be logged in to used because of sessionId
    #sender
    p = DHPrime
    g = DHGen
    saveRand = randInt()

    sentPow = pow(g, saveRand, p)
    return sentPow, saveRand;

def diffie_hellman_send_finish(savedRand, receivedPow):
    #sender, after receiving back
    p = DHPrime

    KEY = pow(receivedPow, savedRand, p)
    return KEY;

def diffie_hellman_receive(receivedPow):
    #receiver
    A = receivedPow
    p = DHPrime
    g = DHGen
    myRand = randInt()

    finishPow = pow(g, myRand, p)
    KEY = pow(A, myRand, p)
    return finishPow, KEY;